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
	ssh       *ssh.Client
	ln        net.Listener
	active    atomic.Int32
	used      atomic.Bool
	closeOnce sync.Once
	done      chan struct{}
}

// Connect authenticates to the gate. Call Listen (after Computers, for a
// picker) to start forwarding.
func Connect(p config.Profile, password, code string) (*Tunnel, error) {
	cfg := &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM},
		},
		User: p.Username,
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(name, instr string, qs []string, echos []bool) ([]string, error) {
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
		})},
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
	c, err := ssh.Dial("tcp", net.JoinHostPort(p.Host, fmt.Sprint(p.Port)), cfg)
	if err != nil {
		var uh *UnknownHostError
		var hc *HostChangedError
		if errors.As(err, &uh) {
			return nil, uh
		}
		if errors.As(err, &hc) {
			return nil, hc
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, errors.New("login failed - check username, password and authenticator code (too many failures will block your IP for a while)")
		}
		return nil, err
	}

	t := &Tunnel{profile: p, ssh: c, done: make(chan struct{})}
	go t.keepalive()
	go func() { c.Wait(); t.Close() }()
	return t, nil
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
		ch, err := t.ssh.Dial("tcp", "list.securdp:0")
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
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	var ln net.Listener
	var err error
	for port := 13389; port < 13400 && ln == nil; port++ {
		ln, _ = net.Listen("tcp", fmt.Sprintf("%s:%d", localIP, port))
	}
	if ln == nil {
		if ln, err = net.Listen("tcp", localIP+":0"); err != nil {
			return err
		}
	}
	t.ln, t.Computer, t.LocalAddr = ln, computer, ln.Addr().String()
	go t.accept()
	return nil
}

func (t *Tunnel) accept() {
	// A computer name asks the hub for that PC; 127.0.0.1 means "the
	// computer I logged in to" (and is what older gates expect).
	dest := "127.0.0.1:3389"
	if t.Computer != "" {
		dest = t.Computer + ":3389"
	}
	for {
		lc, err := t.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer lc.Close()
			rc, err := t.ssh.Dial("tcp", dest)
			if err != nil {
				return
			}
			defer rc.Close()
			t.used.Store(true)
			t.active.Add(1)
			defer t.active.Add(-1)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { io.Copy(rc, lc); rc.Close(); wg.Done() }()
			go func() { io.Copy(lc, rc); lc.Close(); wg.Done() }()
			wg.Wait()
		}()
	}
}

func (t *Tunnel) keepalive() {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tk.C:
			if _, _, err := t.ssh.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				t.Close()
				return
			}
		}
	}
}

func (t *Tunnel) Active() int        { return int(t.active.Load()) }
func (t *Tunnel) Done() <-chan struct{} { return t.done }

func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		if t.ln != nil {
			t.ln.Close()
		}
		t.ssh.Close()
		close(t.done)
	})
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
					t.Close()
					return
				}
			}
		}
	}()
	return nil
}
