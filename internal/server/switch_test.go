package server

import (
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"securdp/internal/auth"
	"securdp/internal/client"
	"securdp/internal/config"
)

// flakyProxy forwards to addr; freeze makes the connections open so far go
// silent (like Wi-Fi going away) while new connections still work.
type flakyProxy struct {
	ln   net.Listener
	mu   sync.Mutex
	gen  int
	live []*atomic.Bool
}

func newFlakyProxy(t *testing.T, addr string) *flakyProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &flakyProxy{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", addr)
			if err != nil {
				c.Close()
				continue
			}
			on := &atomic.Bool{}
			on.Store(true)
			p.mu.Lock()
			p.live = append(p.live, on)
			p.mu.Unlock()
			pipe := func(dst, src net.Conn) {
				buf := make([]byte, 32<<10)
				for {
					n, err := src.Read(buf)
					if n > 0 && on.Load() {
						dst.Write(buf[:n])
					}
					if err != nil {
						dst.Close()
						return
					}
				}
			}
			go pipe(up, c)
			go pipe(c, up)
		}
	}()
	return p
}

func (p *flakyProxy) addr() string { return p.ln.Addr().String() }

func (p *flakyProxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, on := range p.live {
		on.Store(false)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("timed out waiting for " + what)
}

// echoes sends a line through c (a laptop "Remote Desktop" that greets, then echoes).
func echoes(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write %q: %v", msg, err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo %q: got %q, %v", msg, buf, err)
	}
}

func dialRDP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len("laptop;"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "laptop;" {
		t.Fatalf("greeting: %q %v", buf, err)
	}
	return c
}

// Local -> Switch to remote keeps the port and the open Remote Desktop
// connection; a dropped network keeps the port for the grace period, a home
// login comes back by itself and a remote one reconnects with password + code.
func TestWindowsClientSwitchAndGrace(t *testing.T) {
	client.SetKeepalive(200*time.Millisecond, 300*time.Millisecond)
	client.HomeRetry = 200 * time.Millisecond
	defer func() {
		client.SetKeepalive(30*time.Second, 15*time.Second)
		client.HomeRetry = 10 * time.Second
	}()

	h := startHomeHub(t, false)
	hub := net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port))
	px := newFlakyProxy(t, hub)  // home Wi-Fi
	px2 := newFlakyProxy(t, hub) // the public address
	code := func(step int64) string {
		return auth.CurrentTOTP(h.secret, time.Now().Add(time.Duration(step)*30*time.Second))
	}
	p := config.Profile{Host: "127.0.0.1", Port: h.port, Username: "blue.falcon", HostFingerprint: h.fp}
	full, err := client.Connect(p, "Test-passphrase-123", code(-1))
	if err != nil {
		t.Fatal(err)
	}
	signer, pub := newDeviceKey(t)
	if err := full.Trust("my-pc", pub); err != nil {
		t.Fatal(err)
	}
	full.Close()

	// Local, through the "home Wi-Fi"; remote goes through the "public address".
	p.HomeHost = px.addr()
	h2, p2port, _ := net.SplitHostPort(px2.addr())
	p.Host = h2
	p.Port, _ = strconv.Atoi(p2port)
	tun, err := client.ConnectHome(p, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if err := tun.Listen("laptop", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	port := tun.LocalAddr
	rdp := dialRDP(t, port)
	defer rdp.Close()
	echoes(t, rdp, "before")
	if !tun.Home() {
		t.Fatal("not a home login")
	}

	// Wi-Fi blips at home: the port stays and the home login comes back alone.
	px.freeze()
	waitFor(t, "the drop to be noticed", tun.Lost)
	waitFor(t, "the home login to come back", func() bool { return !tun.Lost() })
	if !tun.Home() {
		t.Fatal("came back as a non-home login")
	}
	dialRDP(t, port).Close()

	// Switch to remote: same port, the open Remote Desktop connection carries on.
	rdp2 := dialRDP(t, port)
	defer rdp2.Close()
	if err := tun.SwitchRemote("Test-passphrase-123", "000000"); err == nil {
		t.Fatal("switched with a wrong code")
	}
	if err := tun.SwitchRemote("Test-passphrase-123", code(0)); err != nil {
		t.Fatal(err)
	}
	if tun.Home() || tun.Lost() {
		t.Fatal("still home / lost after the switch")
	}
	echoes(t, rdp2, "still here")
	rdp3 := dialRDP(t, port)
	echoes(t, rdp3, "new login")
	rdp3.Close()
	if tun.LocalAddr != port {
		t.Fatalf("port moved: %s -> %s", port, tun.LocalAddr)
	}

	// Mobile data hiccup while remote: the port waits; password + code reconnects.
	px2.freeze()
	waitFor(t, "the remote drop to be noticed", tun.Lost)
	time.Sleep(500 * time.Millisecond)
	if !tun.Lost() {
		t.Fatal("a remote login came back without password + code")
	}
	if c, err := net.Dial("tcp", port); err != nil {
		t.Fatal("port closed during the grace period")
	} else {
		c.Close()
	}
	if err := tun.SwitchRemote("Test-passphrase-123", code(1)); err != nil {
		t.Fatal(err)
	}
	rdp4 := dialRDP(t, port)
	echoes(t, rdp4, "reconnected")
	rdp4.Close()
	select {
	case <-tun.Done():
		t.Fatal("tunnel closed")
	default:
	}
}

// A grace period that runs out closes the tunnel; a hub that ends the login
// closes it straight away.
func TestWindowsClientGraceEnds(t *testing.T) {
	client.SetKeepalive(200*time.Millisecond, 300*time.Millisecond)
	grace := client.LostGrace
	client.LostGrace = time.Second
	defer func() {
		client.SetKeepalive(30*time.Second, 15*time.Second)
		client.LostGrace = grace
	}()
	h := startHub(t, nil)
	px := newFlakyProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port)))
	host, port, _ := net.SplitHostPort(px.addr())
	p := config.Profile{Host: host, Username: "blue.falcon", HostFingerprint: h.fp}
	p.Port, _ = strconv.Atoi(port)
	tun, err := client.Connect(p, "Test-passphrase-123", auth.CurrentTOTP(h.secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	px.freeze()
	waitFor(t, "the drop", tun.Lost)
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel still open after the grace period")
	}
}
