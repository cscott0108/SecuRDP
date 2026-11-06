package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/auth"
	"securdp/internal/config"
)

// startLinkHub is a hub with web pages "router" (granted) and "nas" (not),
// a shared folder, and app links on for the user unless off is set.
func startLinkHub(t *testing.T, off bool) hubFixture {
	t.Helper()
	svc := namedRDP(t, "webpage")
	return startHub(t, func(c *config.Server) {
		c.Folders = []config.SharedFolder{{Name: "media", Path: t.TempDir()}}
		c.Services = []config.WebService{{Name: "router", URL: "http://" + svc}, {Name: "nas", URL: "http://" + svc}}
		c.Users[0].Folders = []string{"media"}
		c.Users[0].Services = []string{"router"}
		c.Users[0].AppLinks = !off
	})
}

func (h hubFixture) sshConfig(user string, auth ...ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{User: user, Auth: auth, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}
}

// loginCode logs in with password + code (step picks a fresh code).
func (h hubFixture) loginCode(t *testing.T, step int64) *ssh.Client {
	t.Helper()
	code := auth.CurrentTOTP(h.secret, time.Now().Add(time.Duration(step)*30*time.Second))
	ki := ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
		return []string{"Test-passphrase-123", code}, nil
	})
	c, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.port), h.sshConfig("blue.falcon", ki))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func (h hubFixture) loginKey(signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.port), h.sshConfig("blue.falcon", ssh.PublicKeys(signer)))
}

// request sends one line to a pseudo destination and returns the reply.
func request(c *ssh.Client, host, line string) (string, error) {
	ch, err := c.Dial("tcp", host+":0")
	if err != nil {
		return "", err
	}
	defer ch.Close()
	io.WriteString(ch, line+"\n")
	b, err := io.ReadAll(ch)
	return string(b), err
}

func newDeviceKey(t *testing.T) (ssh.Signer, string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(k)
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

func greet(c net.Conn) string {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 32)
	n, _ := c.Read(buf)
	return strings.TrimSuffix(string(buf[:n]), ";")
}

func TestAppLinkReachesOnlyItsPage(t *testing.T) {
	h := startLinkHub(t, false)
	full := h.loginCode(t, 0)
	signer, pub := newDeviceKey(t)

	if r, _ := request(full, pairHost, "pair\tPixel 9\tnas\t"+pub); !strings.HasPrefix(r, "err") {
		t.Fatalf("paired to an ungranted page: %q", r)
	}
	if r, _ := request(full, pairHost, "pair\tPixel 9\trouter\t"+pub); r != "ok\n" {
		t.Fatalf("pair: %q", r)
	}
	if r, _ := request(full, pairHost, "list"); !strings.HasPrefix(r, "ok\nd\tPixel 9\trouter\t") {
		t.Fatalf("list: %q", r)
	}
	if r, _ := request(full, hubHost, ""); !strings.Contains(r, "A\t1\n") {
		t.Fatalf("hub info doesn't offer app links: %q", r)
	}

	link, err := h.loginKey(signer)
	if err != nil {
		t.Fatalf("key login: %v", err)
	}
	defer link.Close()
	c, err := link.Dial("tcp", "svc.router:0")
	if err != nil {
		t.Fatalf("own page: %v", err)
	}
	if g := greet(c); g != "webpage" {
		t.Fatalf("own page reached %q", g)
	}
	// Nothing else: other pages, computers, files, hub info, pairing, a shell.
	for _, dest := range []string{"svc.nas:0", "127.0.0.1:3389", "desktop:3389", "files.securdp:0", "hub.securdp:0", "list.securdp:0", "pair.securdp:0", "hold.securdp:0", "192.168.1.1:80"} {
		if c, err := link.Dial("tcp", dest); err == nil {
			c.Close()
			t.Errorf("app link reached %s", dest)
		}
	}
	if s, err := link.NewSession(); err == nil {
		s.Close()
		t.Error("app link got a session")
	}

	// Unpairing (from a full login) stops the key at once.
	if r, _ := request(full, pairHost, "unpair\tpixel 9"); r != "ok\n" {
		t.Fatalf("unpair: %q", r)
	}
	if c, err := h.loginKey(signer); err == nil {
		c.Close()
		t.Fatal("unpaired key still logs in")
	}
}

func TestAppLinksAreOptIn(t *testing.T) {
	h := startLinkHub(t, true)
	full := h.loginCode(t, 0)
	_, pub := newDeviceKey(t)
	if r, _ := request(full, pairHost, "pair\tphone\trouter\t"+pub); !strings.HasPrefix(r, "err\tapp links aren't turned on") {
		t.Fatalf("paired without app links on: %q", r)
	}
	if r, _ := request(full, hubHost, ""); strings.Contains(r, "A\t") {
		t.Fatalf("hub info offers app links: %q", r)
	}
}

func TestAppLinkStopsWhenPageUngranted(t *testing.T) {
	h := startLinkHub(t, false)
	full := h.loginCode(t, 0)
	signer, pub := newDeviceKey(t)
	if r, _ := request(full, pairHost, "pair\tphone\trouter\t"+pub); r != "ok\n" {
		t.Fatalf("pair: %q", r)
	}
	// Bad requests are refused without changing anything.
	for _, bad := range []string{"pair\t\trouter\t" + pub, "pair\tphone\trouter\tnot-a-key", "pair\tphone2\trouter\t" + pub, "frobnicate"} {
		if r, _ := request(full, pairHost, bad); !strings.HasPrefix(r, "err\t") {
			t.Errorf("%q accepted: %q", bad, r)
		}
	}
	h.server.updateConfig(func(c *config.Server) error { c.Users[0].Services = nil; return nil })
	if c, err := h.loginKey(signer); err == nil {
		c.Close()
		t.Fatal("key still works after its page was ungranted")
	}
}

func TestUnknownKeysDontBan(t *testing.T) {
	h := startLinkHub(t, false)
	for i := 0; i < 6; i++ { // the limiter bans after 3 failures
		signer, _ := newDeviceKey(t)
		if c, err := h.loginKey(signer); err == nil {
			c.Close()
			t.Fatal("unpaired key logged in")
		}
	}
	h.loginCode(t, 0) // still allowed in with password + code
}
