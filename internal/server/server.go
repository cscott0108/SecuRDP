// Package server is the SSH gatekeeper: it authenticates with password +
// TOTP and then only allows TCP forwarding to the local RDP port.
// No shells, no exec, no SFTP, no remote forwarding, no other destinations.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/auth"
	"securdp/internal/config"
	"securdp/internal/ddns"
	"securdp/internal/logx"
	"securdp/internal/winutil"
)

type Server struct {
	log     *logx.Logger
	limiter *auth.Limiter

	mu       sync.Mutex
	cfg      *config.Server
	cfgMod   time.Time
	static   bool // tests: never reload from disk
	lastStep map[string]int64 // TOTP replay protection per user
	sessions atomic.Int32
}

// LoadOrCreateHostKey returns the server's ed25519 host key, creating it once.
func LoadOrCreateHostKey() (ssh.Signer, error) {
	path := config.HostKeyPath()
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	if err := config.EnsureServerDir(); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "SecuRDP host key")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// HostFingerprint returns the SHA256 fingerprint shown to users for pinning.
func HostFingerprint() (string, error) {
	s, err := LoadOrCreateHostKey()
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(s.PublicKey()), nil
}

// config returns the current config, reloading it if the file changed so
// user edits made in the UI take effect without restarting.
func (s *Server) config() *config.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.static {
		return s.cfg
	}
	if st, err := os.Stat(config.ServerConfigPath()); err == nil && st.ModTime() != s.cfgMod {
		if c, err := config.LoadServer(); err == nil {
			s.cfg, s.cfgMod = c, st.ModTime()
			s.log.Printf("configuration reloaded (%d users)", len(c.Users))
		}
	}
	return s.cfg
}

// rdpTarget is the address to dial for a computer. "this-pc" is the local
// RDP port (or RDPTarget when set); hub computers use their configured address.
func (s *Server) rdpTarget(computer string) (string, *config.Computer) {
	cfg := s.config()
	c := cfg.FindComputer(computer)
	if c == nil {
		return "", nil
	}
	if c.Name != config.ThisPC {
		return c.DialAddress(), c
	}
	if cfg.RDPTarget != "" {
		return cfg.RDPTarget, c
	}
	return fmt.Sprintf("127.0.0.1:%d", winutil.GetRDPInfo().Port), c
}

func ipOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func (s *Server) sourceAllowed(ip string) bool {
	srcs := s.config().AllowedSources
	if len(srcs) == 0 {
		return true
	}
	addr := net.ParseIP(ip)
	for _, c := range srcs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && n.Contains(addr) {
			return true
		}
		if net.ParseIP(strings.TrimSpace(c)).Equal(addr) {
			return true
		}
	}
	return false
}

// authenticate asks for password and authenticator code in one prompt.
func (s *Server) authenticate(conn ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	ip := ipOf(conn.RemoteAddr())
	if banned, _ := s.limiter.Banned(ip); banned {
		return nil, errors.New("denied")
	}
	answers, err := ask("", "SecuRDP login", []string{"Password: ", "Authenticator code: "}, []bool{false, false})
	if err != nil || len(answers) != 2 {
		return nil, errors.New("denied")
	}
	cfg := s.config()
	// "name+computer" picks a hub computer; the part before '+' is the account.
	login, wanted := config.SplitLogin(conn.User())
	user := cfg.FindUser(login)

	// Always do the expensive work so timing doesn't reveal valid usernames.
	pwOK := false
	if user != nil && user.Enabled {
		pwOK = auth.VerifyPassword(answers[0], user.PasswordHash)
	} else {
		auth.BurnTime(answers[0])
	}
	codeOK := false
	var step int64
	if user != nil && user.Enabled {
		if secret, err := config.UnprotectSecret(user.TOTPSecret); err == nil {
			var ok bool
			step, ok = auth.VerifyTOTP(secret, answers[1], time.Now())
			s.mu.Lock()
			codeOK = ok && step > s.lastStep[strings.ToLower(user.Username)]
			s.mu.Unlock()
		}
	}

	if pwOK && codeOK {
		target, err := cfg.ResolveTarget(user, wanted)
		if err != nil {
			// Right credentials, wrong computer: refuse, but it isn't an
			// attack, so it doesn't count towards a ban or burn the code.
			s.log.Printf("REJECT %s user=%s: %v", ip, user.Username, err)
			return nil, errors.New("denied")
		}
		s.mu.Lock()
		s.lastStep[strings.ToLower(user.Username)] = step // each code works once
		s.mu.Unlock()
		s.limiter.Succeed(ip)
		if target.MAC != "" {
			go s.wakeIfAsleep(target)
		}
		return &ssh.Permissions{Extensions: map[string]string{"user": user.Username, "computer": target.Name}}, nil
	}
	if s.limiter.Fail(ip) {
		s.log.Printf("BAN %s after repeated failures (last username tried: %q)", ip, conn.User())
	} else {
		s.log.Printf("FAIL login from %s user=%q", ip, conn.User())
	}
	time.Sleep(time.Second) // slow down online guessing
	return nil, errors.New("denied")
}

func (s *Server) sshConfig(signer ssh.Signer) *ssh.ServerConfig {
	c := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519, "curve25519-sha256@libssh.org"},
			Ciphers:      []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM},
			MACs:         []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM},
		},
		KeyboardInteractiveCallback: s.authenticate,
		MaxAuthTries:                3,
		ServerVersion:               "SSH-2.0-Gate",
	}
	c.AddHostKey(signer)
	return c
}

// Run listens until ctx is cancelled.
func Run(ctx context.Context, log *logx.Logger) error {
	cfg, err := config.LoadServer()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config not ready (run setup in the SecuRDP app): %w", err)
	}
	signer, err := LoadOrCreateHostKey()
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	s := &Server{
		log:      log,
		cfg:      cfg,
		lastStep: map[string]int64{},
		limiter: auth.NewLimiter(cfg.MaxFailures, time.Duration(cfg.FailureWindowS)*time.Second,
			time.Duration(cfg.BanMinutes)*time.Minute, 3),
	}
	if st, err := os.Stat(config.ServerConfigPath()); err == nil {
		s.cfgMod = st.ModTime()
	}
	sc := s.sshConfig(signer)

	addr := net.JoinHostPort(cfg.ListenAddress, fmt.Sprint(cfg.ListenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	var names []string
	for _, c := range cfg.ActiveComputers() {
		t, _ := s.rdpTarget(c.Name)
		names = append(names, c.Name+"="+t)
	}
	mode := "server"
	if cfg.IsHub() {
		mode = "hub"
	}
	log.Printf("listening on %s (%s mode), computers: %s, host key %s", addr, mode, strings.Join(names, ", "),
		ssh.FingerprintSHA256(signer.PublicKey()))
	go func() { <-ctx.Done(); ln.Close() }()
	go ddns.Run(ctx, log) // no-op unless DuckDNS is configured

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(ctx, c, sc)
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn, sc *ssh.ServerConfig) {
	ip := ipOf(c.RemoteAddr())
	if !s.sourceAllowed(ip) {
		c.Close()
		return
	}
	if banned, _ := s.limiter.Banned(ip); banned {
		c.Close()
		return
	}
	if !s.limiter.Acquire(ip) {
		c.Close()
		return
	}
	// The whole handshake + login must finish within 45 seconds.
	c.SetDeadline(time.Now().Add(45 * time.Second))
	conn, chans, reqs, err := ssh.NewServerConn(c, sc)
	s.limiter.Release(ip)
	if err != nil {
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	defer conn.Close()

	if n := s.sessions.Add(1); int(n) > s.config().MaxSessions {
		s.sessions.Add(-1)
		s.log.Printf("REJECT %s user=%s: max sessions reached", ip, conn.Permissions.Extensions["user"])
		return
	}
	defer s.sessions.Add(-1)

	user := conn.Permissions.Extensions["user"]
	computer := conn.Permissions.Extensions["computer"]
	start := time.Now()
	s.log.Printf("LOGIN %s user=%s computer=%s", ip, user, computer)
	defer func() {
		s.log.Printf("LOGOUT %s user=%s computer=%s after %s", ip, user, computer, time.Since(start).Round(time.Second))
	}()

	// Refuse every global request (e.g. remote port forwarding).
	go ssh.DiscardRequests(reqs)

	// Drop dead clients: keepalive every 30s, close after 3 misses.
	done := make(chan struct{})
	defer close(done)
	go func() {
		misses := 0
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				conn.Close()
				return
			case <-t.C:
				res := make(chan error, 1)
				go func() { _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); res <- err }()
				select {
				case err := <-res:
					if err != nil {
						conn.Close()
						return
					}
					misses = 0
				case <-time.After(15 * time.Second):
					if misses++; misses >= 3 {
						conn.Close()
						return
					}
				}
			}
		}
	}()

	// The tunnel stays up as long as any RDP connection is open. Once the last
	// one closes (or if none is ever opened) a grace timer starts; when it
	// runs out with no new RDP connection, the whole tunnel is closed.
	grace := time.Duration(s.config().IdleTimeoutMin) * time.Minute
	tr := newTracker(grace, func() {
		s.log.Printf("CLOSE %s user=%s: no Remote Desktop connection for %s", ip, user, grace)
		conn.Close()
	})
	defer tr.stop()

	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.Prohibited, "only RDP forwarding is permitted")
			continue
		}
		// The requested host may name a hub computer (picker clients) or the
		// special list address; anything else means the login's computer.
		var d struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		ssh.Unmarshal(nc.ExtraData(), &d)
		host := strings.ToLower(d.Host)
		if host == listHost {
			go s.sendComputerList(nc, user, computer)
			continue
		}
		target := computer
		if host != computer && s.config().FindComputer(host) != nil {
			u := s.config().FindUser(user)
			if u == nil || !u.CanReach(host) {
				nc.Reject(ssh.Prohibited, "you may not reach that computer")
				s.log.Printf("REJECT %s user=%s: may not reach %q", ip, user, host)
				continue
			}
			target = host
			s.log.Printf("OPEN %s user=%s computer=%s", ip, user, target)
		}
		go s.forward(nc, tr, target)
	}
}

// listHost is the pseudo destination a client opens to get its computer list.
const listHost = "list.securdp"

// sendComputerList writes the computers this user may reach, one per line:
// "name online(0/1) default(0/1)". Online means Remote Desktop answered just now.
func (s *Server) sendComputerList(nc ssh.NewChannel, user, loginComputer string) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()
	cfg := s.config()
	u := cfg.FindUser(user)
	if u == nil {
		return
	}
	var comps []config.Computer
	for _, c := range cfg.ActiveComputers() {
		if u.CanReach(c.Name) {
			comps = append(comps, c)
		}
	}
	online := make([]bool, len(comps))
	var wg sync.WaitGroup
	for i, c := range comps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if addr, _ := s.rdpTarget(c.Name); addr != "" {
				if conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond); err == nil {
					conn.Close()
					online[i] = true
				}
			}
		}()
	}
	wg.Wait()
	var b strings.Builder
	for i, c := range comps {
		fmt.Fprintf(&b, "%s %d %d\n", c.Name, b2i(online[i]), b2i(c.Name == loginComputer))
	}
	io.WriteString(ch, b.String())
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// tracker counts open RDP connections in one tunnel and fires onIdle after
// grace has passed with none open. grace == 0 disables the timer.
type tracker struct {
	mu     sync.Mutex
	open   int
	grace  time.Duration
	timer  *time.Timer
	onIdle func()
}

func newTracker(grace time.Duration, onIdle func()) *tracker {
	t := &tracker{grace: grace, onIdle: onIdle}
	t.mu.Lock()
	t.arm()
	t.mu.Unlock()
	return t
}

func (t *tracker) arm() {
	if t.grace > 0 && t.timer == nil {
		t.timer = time.AfterFunc(t.grace, t.onIdle)
	}
}

func (t *tracker) disarm() {
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
}

func (t *tracker) opened() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.open++
	t.disarm()
}

func (t *tracker) closed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.open--; t.open == 0 {
		t.arm()
	}
}

func (t *tracker) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.grace = 0
	t.disarm()
}

// forward connects a direct-tcpip channel to the RDP port of the computer
// chosen at login. The destination the client asked for is ignored on
// purpose: only the configured address of that computer is ever dialled.
func (s *Server) forward(nc ssh.NewChannel, tr *tracker, computer string) {
	target, c := s.rdpTarget(computer)
	if c == nil {
		nc.Reject(ssh.Prohibited, "that computer is no longer configured on the hub")
		return
	}
	dst, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		msg := "Remote Desktop is not reachable on " + c.Name
		if c.MAC != "" {
			wakeOnLAN(c.MAC)
			msg += " - sent a wake-up signal, try again in a minute"
		}
		nc.Reject(ssh.ConnectionFailed, msg)
		s.log.Printf("RDP dial %s (%s) failed: %v", target, c.Name, err)
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		dst.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	tr.opened()
	defer tr.closed()

	// No inactivity limit while RDP is connected: an open session is never cut.
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(w io.Writer, r io.Reader) {
		defer wg.Done()
		io.Copy(w, r)
		ch.CloseWrite()
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}
	go pipe(dst, ch)
	go pipe(ch, dst)
	wg.Wait()
	ch.Close()
	dst.Close()
}
