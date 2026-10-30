package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/auth"
	"securdp/internal/client"
	"securdp/internal/config"
	"securdp/internal/logx"
)

// startTestServer runs the gatekeeper against an echo server standing in for RDP.
func startTestServer(t *testing.T) (port int, secret, fingerprint string, rdpHits chan struct{}) {
	t.Helper()
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	rdpHits = make(chan struct{}, 10)
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			rdpHits <- struct{}{}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { echo.Close() })

	secret, _ = auth.NewTOTPSecret()
	enc, err := config.ProtectSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("Test-passphrase-123")
	cfg := config.DefaultServer()
	cfg.RDPTarget = echo.Addr().String()
	cfg.Users = []config.User{{Username: "blue.falcon", PasswordHash: hash, TOTPSecret: enc, Enabled: true}}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	log, _ := logx.Open(os.DevNull, nil)
	s := &Server{log: log, cfg: cfg, static: true, lastStep: map[string]int64{},
		limiter: auth.NewLimiter(3, time.Minute, time.Minute, 3)}
	sc := s.sshConfig(signer)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(ctx, c, sc)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, secret, ssh.FingerprintSHA256(signer.PublicKey()), rdpHits
}

func TestEndToEndTunnel(t *testing.T) {
	port, secret, fp, hits := startTestServer(t)
	p := config.Profile{Name: "test", Host: "127.0.0.1", Port: port, Username: "blue.falcon", LocalIP: "127.0.0.77"}

	// First connect: unknown host must be reported, not silently trusted.
	_, err := client.Dial(p, "Test-passphrase-123", auth.CurrentTOTP(secret, time.Now()))
	uh, ok := err.(*client.UnknownHostError)
	if !ok || uh.Fingerprint != fp {
		t.Fatalf("expected unknown host with %s, got %v", fp, err)
	}
	p.HostFingerprint = fp

	tun, err := client.Dial(p, "Test-passphrase-123", auth.CurrentTOTP(secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if !strings.HasPrefix(tun.LocalAddr, "127.0.0.77:") {
		t.Fatalf("local addr %s", tun.LocalAddr)
	}
	c, err := net.Dial("tcp", tun.LocalAddr)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello rdp"))
	buf := make([]byte, 9)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello rdp" {
		t.Fatalf("echo through tunnel failed: %q %v", buf, err)
	}
	c.Close()
	select {
	case <-hits:
	case <-time.After(time.Second):
		t.Fatal("RDP target never reached")
	}

	// Replay: the same code must not work a second time.
	_, err = client.Dial(p, "Test-passphrase-123", auth.CurrentTOTP(secret, time.Now()))
	if err == nil {
		t.Fatal("replayed TOTP code accepted")
	}
}

func TestRejectsWrongCredsAndOtherChannels(t *testing.T) {
	port, secret, fp, _ := startTestServer(t)
	p := config.Profile{Host: "127.0.0.1", Port: port, Username: "blue.falcon", HostFingerprint: fp, LocalIP: "127.0.0.78"}
	if _, err := client.Dial(p, "wrong-password-xx", auth.CurrentTOTP(secret, time.Now())); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := client.Dial(p, "Test-passphrase-123", "000000"); err == nil {
		t.Fatal("wrong code accepted")
	}

	// Log in with a raw SSH client and try to get a shell / reach other hosts.
	code := auth.CurrentTOTP(secret, time.Now())
	cc := &ssh.ClientConfig{
		User: "blue.falcon",
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, _ string, q []string, _ []bool) ([]string, error) {
			return []string{"Test-passphrase-123", code}, nil
		})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// Two failures above; one more would ban us, so this must succeed.
	c, err := ssh.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), cc)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NewSession(); err == nil {
		t.Fatal("shell session was allowed")
	}
	if ok, _, _ := c.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		A string
		P uint32
	}{"0.0.0.0", 8080})); ok {
		t.Fatal("remote forwarding was allowed")
	}
}

func TestBanAfterFailures(t *testing.T) {
	port, secret, fp, _ := startTestServer(t)
	p := config.Profile{Host: "127.0.0.1", Port: port, Username: "nobody.here", HostFingerprint: fp, LocalIP: "127.0.0.79"}
	for i := 0; i < 3; i++ {
		client.Dial(p, "x", "123456")
	}
	p.Username = "blue.falcon"
	if _, err := client.Dial(p, "Test-passphrase-123", auth.CurrentTOTP(secret, time.Now())); err == nil {
		t.Fatal("banned IP was able to log in")
	}
}
