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

func (s *Server) rdpTarget() string {
	if t := s.config().RDPTarget; t != "" {
		return t
	}
	return fmt.Sprintf("127.0.0.1:%d", winutil.GetRDPInfo().Port)
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
	user := cfg.FindUser(conn.User())

	// Always do the expensive work so timing doesn't reveal valid usernames.
	pwOK := false
	if user != nil && user.Enabled {
		pwOK = auth.VerifyPassword(answers[0], user.PasswordHash)
	} else {
		auth.BurnTime(answers[0])
	}
	codeOK := false
	if user != nil && user.Enabled {
		if secret, err := config.UnprotectSecret(user.TOTPSecret); err == nil {
			step, ok := auth.VerifyTOTP(secret, answers[1], time.Now())
			s.mu.Lock()
			key := strings.ToLower(user.Username)
			if ok && step > s.lastStep[key] {
				codeOK = true
				if pwOK {
					s.lastStep[key] = step // only burn the code on a full success
				}
			}
			s.mu.Unlock()
		}
	}

	if pwOK && codeOK {
		s.limiter.Succeed(ip)
		return &ssh.Permissions{Extensions: map[string]string{"user": user.Username}}, nil
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
	log.Printf("listening on %s, forwarding to %s, host key %s", addr, s.rdpTarget(), ssh.FingerprintSHA256(signer.PublicKey()))
	go func() { <-ctx.Done(); ln.Close() }()

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
	start := time.Now()
	s.log.Printf("LOGIN %s user=%s", ip, user)
	defer func() { s.log.Printf("LOGOUT %s user=%s after %s", ip, user, time.Since(start).Round(time.Second)) }()

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
		go s.forward(nc, tr)
	}
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

// forward connects a direct-tcpip channel to the RDP target. The destination
// the client asked for is ignored on purpose: it is always the local RDP port.
func (s *Server) forward(nc ssh.NewChannel, tr *tracker) {
	target := s.rdpTarget()
	dst, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, "RDP is not reachable on this computer")
		s.log.Printf("RDP dial %s failed: %v", target, err)
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
