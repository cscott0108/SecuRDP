package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/auth"
	"securdp/internal/client"
	"securdp/internal/config"
	"securdp/internal/logx"
)

// namedRDP is a fake Remote Desktop that greets with its name, then echoes.
func namedRDP(t *testing.T, name string) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.Write([]byte(name + ";")); io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

type hubFixture struct {
	port   int
	fp     string
	secret string
}

func startHub(t *testing.T, mutate func(*config.Server)) hubFixture {
	t.Helper()
	secret, _ := auth.NewTOTPSecret()
	enc, err := config.ProtectSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("Test-passphrase-123")
	cfg := config.DefaultServer()
	cfg.Mode = "hub"
	cfg.Computers = []config.Computer{
		{Name: "desktop", Address: namedRDP(t, "desktop")},
		{Name: "laptop", Address: namedRDP(t, "laptop")},
	}
	cfg.RDPTarget = namedRDP(t, "this-pc")
	cfg.Users = []config.User{{Username: "blue.falcon", PasswordHash: hash, TOTPSecret: enc, Enabled: true}}
	if mutate != nil {
		mutate(cfg)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	log, _ := logx.Open(os.DevNull, nil)
	s := &Server{log: log, cfg: cfg, static: true, lastStep: map[string]int64{},
		limiter: auth.NewLimiter(3, time.Minute, time.Minute, 5)}
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
	return hubFixture{ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey()), secret}
}

// greeting connects as login through the hub and returns the target's name.
func (h hubFixture) greeting(t *testing.T, login string, step int64) (string, error) {
	t.Helper()
	p := config.Profile{Host: "127.0.0.1", Port: h.port, Username: login, HostFingerprint: h.fp, LocalIP: "127.0.0.90"}
	// Each successful login burns its code, so use distinct time steps.
	code := auth.CurrentTOTP(h.secret, time.Now().Add(time.Duration(step)*30*time.Second))
	tun, err := client.Dial(p, "Test-passphrase-123", code)
	if err != nil {
		return "", err
	}
	defer tun.Close()
	c, err := net.Dial("tcp", tun.LocalAddr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(buf[:n]), ";"), nil
}

func TestHubRoutesByLoginSuffix(t *testing.T) {
	h := startHub(t, nil)
	// Codes from steps -1, 0, +1 are all valid; each login must use a newer one.
	if got, err := h.greeting(t, "blue.falcon+laptop", -1); err != nil || got != "laptop" {
		t.Fatalf("+laptop -> %q, %v", got, err)
	}
	if got, err := h.greeting(t, "blue.falcon+desktop", 0); err != nil || got != "desktop" {
		t.Fatalf("+desktop -> %q, %v", got, err)
	}
	if got, err := h.greeting(t, "Blue.Falcon", 1); err != nil || got != "desktop" {
		t.Fatalf("no suffix should go to the first computer, got %q, %v", got, err)
	}
}

func TestHubDefaultAndPermissions(t *testing.T) {
	h := startHub(t, func(c *config.Server) {
		c.DefaultComputer = "laptop"
		c.Users[0].Restricted = true
		c.Users[0].Computers = []string{"laptop"}
	})
	if _, err := h.greeting(t, "blue.falcon+desktop", -1); err == nil {
		t.Fatal("restricted user reached a computer not on their list")
	}
	if _, err := h.greeting(t, "blue.falcon+this-pc", -1); err == nil {
		t.Fatal("this-pc reachable although not configured on the hub")
	}
	if _, err := h.greeting(t, "blue.falcon+nas", -1); err == nil {
		t.Fatal("unknown computer accepted")
	}
	// Three refusals with correct credentials must not have banned us (limit 3),
	// and must not have burned the code.
	if got, err := h.greeting(t, "blue.falcon", -1); err != nil || got != "laptop" {
		t.Fatalf("default computer -> %q, %v", got, err)
	}
}

func TestServerModeIgnoresHubComputers(t *testing.T) {
	h := startHub(t, func(c *config.Server) { c.Mode = "" })
	if got, err := h.greeting(t, "blue.falcon", 0); err != nil || got != "this-pc" {
		t.Fatalf("server mode -> %q, %v", got, err)
	}
	if _, err := h.greeting(t, "blue.falcon+desktop", 1); err == nil {
		t.Fatal("server mode forwarded to a hub computer")
	}
}

func TestHubPickerListAndChoose(t *testing.T) {
	h := startHub(t, func(c *config.Server) {
		c.Users[0].Restricted = true
		c.Users[0].Computers = []string{"desktop", "laptop"}
		c.Computers = append(c.Computers, config.Computer{Name: "offline", Address: "127.0.0.1:1"})
	})
	p := config.Profile{Host: "127.0.0.1", Port: h.port, Username: "blue.falcon", HostFingerprint: h.fp}
	tun, err := client.Connect(p, "Test-passphrase-123", auth.CurrentTOTP(h.secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	list, err := tun.Computers()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]client.HubComputer{}
	for _, c := range list {
		got[c.Name] = c
	}
	if len(list) != 2 || !got["desktop"].Online || !got["desktop"].Default || !got["laptop"].Online || got["laptop"].Default {
		t.Fatalf("list should be desktop(default)+laptop, both online, and not offline (not allowed): %+v", list)
	}

	// One login, pick laptop.
	if err := tun.Listen("laptop", "127.0.0.91"); err != nil {
		t.Fatal(err)
	}
	if g := readGreeting(t, tun.LocalAddr); g != "laptop" {
		t.Fatalf("picked laptop, reached %q", g)
	}
}

func TestHubPickerRefusesForbiddenComputer(t *testing.T) {
	h := startHub(t, func(c *config.Server) {
		c.Users[0].Restricted = true
		c.Users[0].Computers = []string{"desktop"}
	})
	p := config.Profile{Host: "127.0.0.1", Port: h.port, Username: "blue.falcon", HostFingerprint: h.fp}
	tun, err := client.Connect(p, "Test-passphrase-123", auth.CurrentTOTP(h.secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if err := tun.Listen("laptop", "127.0.0.92"); err != nil {
		t.Fatal(err)
	}
	if g := readGreeting(t, tun.LocalAddr); g != "" {
		t.Fatalf("forbidden computer reached: %q", g)
	}
}

func readGreeting(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 32)
	n, _ := c.Read(buf)
	return strings.TrimSuffix(string(buf[:n]), ";")
}

func TestComputerValidation(t *testing.T) {
	good := []config.Computer{
		{Name: "desktop", Address: "192.168.1.50"},
		{Name: "nas-2", Address: "DESKTOP-PC:3390", MAC: "00-11-22-33-44-55"},
		{Name: config.ThisPC},
	}
	for _, c := range good {
		if err := config.ValidateComputer(c); err != nil {
			t.Errorf("%+v rejected: %v", c, err)
		}
	}
	bad := []config.Computer{
		{Name: "Desktop", Address: "1.2.3.4"}, {Name: "a b", Address: "1.2.3.4"},
		{Name: "pc", Address: ""}, {Name: "pc", Address: "1.2.3.4:99999"}, {Name: "pc", Address: "1.2.3.4", MAC: "zz"},
	}
	for _, c := range bad {
		if err := config.ValidateComputer(c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if u, c := config.SplitLogin("me+desktop"); u != "me" || c != "desktop" {
		t.Error("split")
	}
	if u, c := config.SplitLogin("+desktop"); u != "+desktop" || c != "" {
		t.Error("leading + must not be a computer")
	}
}
