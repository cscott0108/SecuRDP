// Package client opens the SSH tunnel and launches Remote Desktop through it.
package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/config"
)

// UnknownHostError is returned on first connect so the user can verify the
// server fingerprint before it is pinned.
type UnknownHostError struct{ Fingerprint string }

func (e *UnknownHostError) Error() string {
	return "first connection to this server - verify fingerprint " + e.Fingerprint
}

// HostChangedError means the server key no longer matches the pinned one:
// either the server was reinstalled or someone is intercepting the connection.
type HostChangedError struct{ Want, Got string }

func (e *HostChangedError) Error() string {
	return fmt.Sprintf("SERVER IDENTITY CHANGED! expected %s but got %s. "+
		"If you did not reinstall SecuRDP on the server, do NOT connect.", e.Want, e.Got)
}

type Tunnel struct {
	LocalAddr string
	Computer  string // hub computer being forwarded to ("" = the login's)
	profile   config.Profile
	mu        sync.Mutex
	cur       *link      // the login new connections use; nil while a dropped login waits (Lost)
	home      bool       // the login is a home (key) login
	homeKey   ssh.Signer // for quietly retrying a dropped home login
	holds     map[*hold]bool
	listeners []net.Listener
	uses      atomic.Int32
	active    atomic.Int32
	used      atomic.Bool
	closeOnce sync.Once
	done      chan struct{}
}

// A link is one SSH login. After SwitchRemote the old link stays open until
// the connections it carries (e.g. a Remote Desktop session) end.
type link struct {
	c        *ssh.Client
	streams  atomic.Int32
	retiring atomic.Bool
	dropped  atomic.Bool // keepalive gave up on it (the network went away)
}

func (l *link) release() {
	if l.streams.Add(-1) <= 0 && l.retiring.Load() {
		l.c.Close()
	}
}

// LostGrace is how long a tunnel whose login dropped with the network (Wi-Fi
// to mobile data, leaving home) keeps its ports before it closes. A home
// login retries by itself every HomeRetry; otherwise SwitchRemote (password
// + code) reconnects it. Remote Desktop reconnects by itself either way.
var (
	LostGrace = 5 * time.Minute
	HomeRetry = 10 * time.Second

	keepaliveEvery   = 30 * time.Second
	keepaliveTimeout = 15 * time.Second
)

// SetKeepalive changes how often logins are checked (for tests).
func SetKeepalive(every, timeout time.Duration) { keepaliveEvery, keepaliveTimeout = every, timeout }

func keyboardAuth(password, code string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instr string, qs []string, echos []bool) ([]string, error) {
		ans := make([]string, len(qs))
		for i, q := range qs {
			lq := strings.ToLower(q)
			switch {
			case strings.Contains(lq, "password"):
				ans[i] = password
			case strings.Contains(lq, "code"), strings.Contains(lq, "verification"):
				ans[i] = code
			}
		}
		return ans, nil
	})
}

func loginError(err error) error {
	if err != nil && strings.Contains(err.Error(), "unable to authenticate") {
		return errors.New("login failed - check username, password and authenticator code (too many failures will block your IP for a while)")
	}
	return err
}

// Connect authenticates to the gate. Call Listen (after Computers, for a
// picker) to start forwarding.
func Connect(p config.Profile, password, code string) (*Tunnel, error) {
	c, err := dial(p, p.Host, keyboardAuth(password, code))
	if err != nil {
		return nil, loginError(err)
	}
	return newTunnel(p, c, false), nil
}

// ConnectHome logs in with this PC's trusted home key: no password or code.
// The hub only accepts it from the home network, so it connects to the hub's
// home address (p.HomeHost) when one is saved.
func ConnectHome(p config.Profile, key ssh.Signer) (*Tunnel, error) {
	host := p.Host
	if p.HomeHost != "" {
		host = p.HomeHost
	}
	c, err := dial(p, host, ssh.PublicKeys(key))
	if err != nil && strings.Contains(err.Error(), "unable to authenticate") {
		return nil, errors.New("the hub didn't accept this PC's home login - it only works on your home network (use Connect with password + code away from home), or it was removed on the hub")
	}
	if err != nil {
		return nil, err
	}
	t := newTunnel(p, c, true)
	t.homeKey = key
	return t, nil
}

func newTunnel(p config.Profile, c *ssh.Client, home bool) *Tunnel {
	t := &Tunnel{profile: p, cur: &link{c: c}, home: home, holds: map[*hold]bool{}, done: make(chan struct{})}
	go t.watch(t.cur)
	go t.keepalive()
	return t
}

func (t *Tunnel) homeHost() string {
	if t.profile.HomeHost != "" {
		return t.profile.HomeHost
	}
	return t.profile.Host
}

// SwitchRemote moves the tunnel to a normal password + code login through
// the profile's public address, without closing anything: the local ports
// stay, new connections use the new login, and connections already open
// finish on the old one. Use it to leave a home (Local) login, or to
// reconnect a login that dropped with the network.
func (t *Tunnel) SwitchRemote(password, code string) error {
	c, err := dial(t.profile, t.profile.Host, keyboardAuth(password, code))
	if err != nil {
		return loginError(err)
	}
	return t.attach(c, false)
}

// attach makes c the tunnel's login, moving holds over and retiring the old
// login once its connections end.
func (t *Tunnel) attach(c *ssh.Client, home bool) error {
	l := &link{c: c}
	t.mu.Lock()
	select {
	case <-t.done:
		t.mu.Unlock()
		c.Close()
		return errors.New("the connection already closed - connect again")
	default:
	}
	old := t.cur
	t.cur, t.home = l, home
	holds := make([]*hold, 0, len(t.holds))
	for h := range t.holds {
		holds = append(holds, h)
	}
	t.mu.Unlock()
	go t.watch(l)
	for _, h := range holds {
		h.move(l)
	}
	if old != nil {
		old.retiring.Store(true)
		if old.streams.Load() <= 0 {
			old.c.Close()
		}
	}
	return nil
}

// Home reports whether the tunnel uses a home (Local) login; Lost whether
// its login dropped with the network and it is waiting to reconnect.
func (t *Tunnel) Home() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.home
}

func (t *Tunnel) Lost() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cur == nil
}

// watch notices when a login ends. A login that dropped with the network
// keeps the tunnel's ports for LostGrace (a home login retries by itself);
// one the hub closed ends the tunnel.
func (t *Tunnel) watch(l *link) {
	err := l.c.Wait()
	t.mu.Lock()
	if t.cur != l {
		t.mu.Unlock() // an old login after a switch, or closing
		return
	}
	if !l.dropped.Load() && (err == nil || errors.Is(err, io.EOF)) {
		t.mu.Unlock() // the hub ended it
		t.Close()
		return
	}
	t.cur = nil
	home := t.home && t.homeKey != nil
	t.mu.Unlock()
	deadline := time.Now().Add(LostGrace)
	go func() {
		for time.Now().Before(deadline) {
			select {
			case <-t.done:
				return
			case <-time.After(min(HomeRetry, time.Until(deadline))):
			}
			if !t.Lost() {
				return // reconnected with password + code
			}
			if home {
				if c, err := dial(t.profile, t.homeHost(), ssh.PublicKeys(t.homeKey)); err == nil {
					if t.attach(c, true) == nil {
						return
					}
				}
			}
		}
		if t.Lost() {
			t.Close()
		}
	}()
}

// conn returns the current login, or an error while a home login is lost.
func (t *Tunnel) conn() (*link, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur == nil {
		return nil, errors.New("the connection dropped - reconnect to continue")
	}
	return t.cur, nil
}

// open dials dest through the current login. The connection is counted on
// that login, so a retired login closes once its last connection ends.
func (t *Tunnel) open(dest string) (net.Conn, error) {
	l, err := t.conn()
	if err != nil {
		return nil, err
	}
	l.streams.Add(1)
	ch, err := l.c.Dial("tcp", dest)
	if err != nil {
		l.release()
		return nil, err
	}
	return &countedConn{Conn: ch, l: l}, nil
}

type countedConn struct {
	net.Conn
	l    *link
	once sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.l.release)
	return err
}

// A hold keeps the hub-side session open (hold.securdp); it moves to the new
// login on SwitchRemote.
type hold struct {
	mu sync.Mutex
	ch net.Conn
}

func (h *hold) move(l *link) {
	ch, err := l.c.Dial("tcp", "hold.securdp:0")
	h.mu.Lock()
	old := h.ch
	h.ch = nil
	if err == nil {
		h.ch = ch
	}
	h.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

func (h *hold) close() {
	h.mu.Lock()
	if h.ch != nil {
		h.ch.Close()
		h.ch = nil
	}
	h.mu.Unlock()
}

func dial(p config.Profile, host string, auth ssh.AuthMethod) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM},
		},
		User: p.Username,
		Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if p.HostFingerprint == "" {
				return &UnknownHostError{Fingerprint: fp}
			}
			if fp != p.HostFingerprint {
				return &HostChangedError{Want: p.HostFingerprint, Got: fp}
			}
			return nil
		},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           15 * time.Second,
	}
	addr := net.JoinHostPort(host, fmt.Sprint(p.Port))
	if _, _, err := net.SplitHostPort(host); err == nil {
		addr = host // a home address given as host:port
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		var uh *UnknownHostError
		var hc *HostChangedError
		if errors.As(err, &uh) {
			return nil, uh
		}
		if errors.As(err, &hc) {
			return nil, hc
		}
		return nil, err
	}

	return c, nil
}

// Dial logs in and starts forwarding to the login's computer (the
// "user+computer" suffix, or the hub default), as before the picker existed.
func Dial(p config.Profile, password, code string) (*Tunnel, error) {
	t, err := Connect(p, password, code)
	if err != nil {
		return nil, err
	}
	if err := t.Listen("", p.LocalIP); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// HubComputer is one entry of a hub's computer list.
type HubComputer struct {
	Name    string `json:"name"`
	Online  bool   `json:"online"`
	Default bool   `json:"default"`
}

// Computers asks the gate which computers this login may reach. Older gates
// don't support this; they yield (nil, nil) after a short wait.
func (t *Tunnel) Computers() ([]HubComputer, error) {
	type result struct {
		list []HubComputer
		err  error
	}
	res := make(chan result, 1)
	go func() {
		ch, err := t.open("list.securdp:0")
		if err != nil {
			res <- result{nil, err}
			return
		}
		defer ch.Close()
		b, err := io.ReadAll(io.LimitReader(ch, 64<<10))
		if err != nil {
			res <- result{nil, err}
			return
		}
		var list []HubComputer
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Fields(line)
			if len(f) == 3 {
				list = append(list, HubComputer{f[0], f[1] == "1", f[2] == "1"})
			}
		}
		res <- result{list, nil}
	}()
	select {
	case r := <-res:
		return r.list, r.err
	case <-time.After(4 * time.Second):
		return nil, nil // an older gate forwards this to RDP, which never answers first
	}
}

// Listen starts the local listener for computer ("" = the login's computer)
// on a stable loopback address, so Remote Desktop's saved login sticks.
func (t *Tunnel) Listen(computer, localIP string) error {
	// A computer name asks the hub for that PC; 127.0.0.1 means "the
	// computer I logged in to" (and is what older gates expect).
	dest := "127.0.0.1:3389"
	if computer != "" {
		dest = computer + ":3389"
	}
	ln, err := t.listenLocal(localIP, 13389, dest, true)
	if err != nil {
		return err
	}
	t.Computer, t.LocalAddr = computer, ln.Addr().String()
	return nil
}

// ListenService forwards a local port to the hub's web service name and
// returns the local host:port to open in a browser.
func (t *Tunnel) ListenService(name, localIP string) (string, error) {
	ln, err := t.listenLocal(localIP, 18080, "svc."+name+":0", false)
	if err != nil {
		return "", err
	}
	return ln.Addr().String(), nil
}

// listenLocal binds the first free port from firstPort on localIP and
// forwards each connection to dest through the tunnel. rdp connections are
// counted for the auto-close-after-Remote-Desktop logic.
func (t *Tunnel) listenLocal(localIP string, firstPort int, dest string, rdp bool) (net.Listener, error) {
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	var ln net.Listener
	var err error
	for port := firstPort; port < firstPort+20 && ln == nil; port++ {
		ln, _ = net.Listen("tcp", fmt.Sprintf("%s:%d", localIP, port))
	}
	if ln == nil {
		if ln, err = net.Listen("tcp", localIP+":0"); err != nil {
			return nil, err
		}
	}
	t.mu.Lock()
	t.listeners = append(t.listeners, ln)
	t.mu.Unlock()
	go t.serve(ln, dest, rdp)
	return ln, nil
}

func (t *Tunnel) serve(ln net.Listener, dest string, rdp bool) {
	for {
		lc, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer lc.Close()
			rc, err := t.open(dest)
			if err != nil {
				return
			}
			defer rc.Close()
			if rdp {
				t.used.Store(true)
				t.active.Add(1)
				defer t.active.Add(-1)
			}
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { io.Copy(rc, lc); rc.Close(); wg.Done() }()
			go func() { io.Copy(lc, rc); lc.Close(); wg.Done() }()
			wg.Wait()
		}()
	}
}

// keepalive checks the current login every 30 s. A login that doesn't answer
// within 15 s (e.g. the network went away) is closed, so watch notices.
func (t *Tunnel) keepalive() {
	tk := time.NewTicker(keepaliveEvery)
	defer tk.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tk.C:
			l, err := t.conn()
			if err != nil {
				continue
			}
			res := make(chan error, 1)
			go func() { _, _, err := l.c.SendRequest("keepalive@openssh.com", true, nil); res <- err }()
			select {
			case err := <-res:
				if err != nil {
					l.dropped.Store(true)
					l.c.Close()
				}
			case <-time.After(keepaliveTimeout):
				l.dropped.Store(true)
				l.c.Close()
			case <-t.done:
				return
			}
		}
	}
}

func (t *Tunnel) Active() int           { return int(t.active.Load()) }
func (t *Tunnel) Done() <-chan struct{} { return t.done }

func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		for _, ln := range t.listeners {
			ln.Close()
		}
		l := t.cur
		t.cur = nil
		holds := t.holds
		t.holds = map[*hold]bool{}
		t.mu.Unlock()
		for h := range holds {
			h.close()
		}
		if l != nil {
			l.c.Close()
		}
		close(t.done)
	})
}

// Acquire / Release count what is using the tunnel (a Remote Desktop
// window, a file browser, a web page window). The last Release closes it.
func (t *Tunnel) Acquire() { t.uses.Add(1) }

func (t *Tunnel) Release() {
	if t.uses.Add(-1) <= 0 {
		t.Close()
	}
}

// LaunchRDP starts mstsc against the tunnel and closes the tunnel once
// Remote Desktop has exited and no RDP connection is left open.
func (t *Tunnel) LaunchRDP() error {
	rdp, err := t.writeRDPFile()
	if err != nil {
		return err
	}
	cmd := exec.Command("mstsc.exe", rdp)
	if err := cmd.Start(); err != nil {
		return err
	}
	t.Acquire()
	go func() {
		cmd.Wait()
		// Give mstsc a moment in case it handed off to another process.
		time.Sleep(5 * time.Second)
		for {
			select {
			case <-t.done:
				return
			case <-time.After(2 * time.Second):
				if t.Active() == 0 {
					t.Release() // closes the tunnel unless files/web are in use
					return
				}
			}
		}
	}()
	return nil
}
