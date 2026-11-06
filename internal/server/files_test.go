package server

import (
	"bytes"
	"image"
	"image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"securdp/internal/auth"
	"securdp/internal/client"
	"securdp/internal/config"
)

type filesFixture struct {
	tun     *client.Tunnel
	shared  string // read-only shared folder on disk
	upload  string // writable shared folder on disk
	outside string // a folder that must never be reachable
}

func startFilesHub(t *testing.T) filesFixture {
	t.Helper()
	base := t.TempDir()
	shared, upload, outside, other := filepath.Join(base, "shared"), filepath.Join(base, "upload"),
		filepath.Join(base, "outside"), filepath.Join(base, "other")
	for _, d := range []string{shared, filepath.Join(shared, "sub"), upload, outside, other} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(shared, "hello.txt"), []byte("hello from the hub"), 0o644)
	os.WriteFile(filepath.Join(shared, "sub", "deep.txt"), []byte("deep"), 0o644)
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o644)
	f, _ := os.Create(filepath.Join(shared, "pic.png"))
	png.Encode(f, image.NewRGBA(image.Rect(0, 0, 400, 300)))
	f.Close()
	// A junction inside the shared folder pointing outside it (no admin needed).
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(shared, "escape"), outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}

	svc := namedRDP(t, "webpage")
	h := startHub(t, func(c *config.Server) {
		c.Folders = []config.SharedFolder{
			{Name: "media", Path: shared},
			{Name: "drop", Path: upload, Writable: true},
			{Name: "other", Path: other},
		}
		c.Services = []config.WebService{{Name: "router", URL: "http://" + svc + "/admin"}, {Name: "nas", URL: "http://" + svc}}
		c.Users[0].Folders = []string{"media", "drop"} // not "other"
		c.Users[0].Services = []string{"router"}       // not "nas"
	})
	p := config.Profile{Host: "127.0.0.1", Port: h.port, Username: "blue.falcon", HostFingerprint: h.fp}
	tun, err := client.Connect(p, "Test-passphrase-123", auth.CurrentTOTP(h.secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.Close)
	return filesFixture{tun, shared, upload, outside}
}

func TestHubInfoListsGrantsOnly(t *testing.T) {
	fx := startFilesHub(t)
	info, err := fx.tun.Info()
	if err != nil {
		t.Fatal(err)
	}
	var folders, services []string
	for _, f := range info.Folders {
		folders = append(folders, f.Name)
	}
	for _, s := range info.Services {
		services = append(services, s.Name+" "+s.Path)
		if !strings.HasPrefix(s.Target, "127.0.0.1:") {
			t.Errorf("service target not shared: %q", s.Target)
		}
	}
	if strings.Join(folders, ",") != "media,drop" || strings.Join(services, ",") != "router /admin" || len(info.Computers) != 2 {
		t.Fatalf("info: computers=%v folders=%v services=%v", info.Computers, folders, services)
	}
}

func TestFilesBrowseAndRead(t *testing.T) {
	fx := startFilesHub(t)
	roots, err := fx.tun.List("")
	if err != nil || len(roots) != 2 {
		t.Fatalf("roots %v %v", roots, err)
	}
	entries, err := fx.tun.List("media")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = e.Dir
	}
	if _, ok := names["hello.txt"]; !ok || !names["sub"] {
		t.Fatalf("listing %v", entries)
	}
	r, size, err := fx.tun.Get("media/hello.txt", 6)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if size != 18 || string(b) != "from the hub" {
		t.Fatalf("get with offset: size=%d %q", size, b)
	}
	if th, err := fx.tun.Thumb("media/pic.png", 96); err != nil || len(th) < 100 {
		t.Fatalf("thumbnail: %d bytes, %v", len(th), err)
	}
	if _, err := fx.tun.Thumb("media/hello.txt", 96); err == nil {
		t.Fatal("thumbnail for a text file")
	}
}

func TestFilesCannotEscape(t *testing.T) {
	fx := startFilesHub(t)
	bad := []string{
		"media/../outside/secret.txt",
		"media/escape/secret.txt", // junction pointing outside
		"media/escape",
		"other/anything", // folder not granted
		"media/sub/../../outside/secret.txt",
		`media\..\outside\secret.txt`,
		"media/hello.txt:secret", // alternate data stream
		"media/CON",
		"C:/Windows/win.ini",
		"/etc/passwd",
	}
	for _, p := range bad {
		if r, _, err := fx.tun.Get(p, 0); err == nil {
			b, _ := io.ReadAll(r)
			r.Close()
			t.Errorf("%q was readable: %q", p, b)
		}
		if _, err := fx.tun.List(p); err == nil && p != "media/escape" {
			t.Errorf("%q was listable", p)
		}
	}
	if _, err := fx.tun.List("media/escape"); err == nil {
		t.Error("junction to outside was listable")
	}
}

func TestFilesWritePermissions(t *testing.T) {
	fx := startFilesHub(t)
	data := []byte("uploaded!")
	if err := fx.tun.Put("media/new.txt", int64(len(data)), bytes.NewReader(data)); err == nil {
		t.Fatal("upload into a read-only folder succeeded")
	}
	if err := fx.tun.Delete("media/hello.txt"); err == nil {
		t.Fatal("delete in a read-only folder succeeded")
	}
	if err := fx.tun.Put("drop/new.txt", int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(fx.upload, "new.txt")); string(got) != "uploaded!" {
		t.Fatalf("uploaded content %q", got)
	}
	if err := fx.tun.Put("drop/new.txt", 1, bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("upload overwrote an existing file")
	}
	if err := fx.tun.Mkdir("drop/folder"); err != nil {
		t.Fatal(err)
	}
	if err := fx.tun.Rename("drop/new.txt", "drop/folder/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if err := fx.tun.Delete("drop/folder"); err == nil {
		t.Fatal("deleted a non-empty folder")
	}
	if err := fx.tun.Delete("drop/folder/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if err := fx.tun.Delete("drop"); err == nil {
		t.Fatal("deleted the shared folder root")
	}
	if err := fx.tun.Rename("drop/folder", "media/folder"); err == nil {
		t.Fatal("moved into a read-only folder")
	}
}

func TestWebServiceForwarding(t *testing.T) {
	fx := startFilesHub(t)
	addr, err := fx.tun.ListenService("router", "127.0.0.93")
	if err != nil {
		t.Fatal(err)
	}
	if g := readGreeting(t, addr); g != "webpage" {
		t.Fatalf("service reached %q", g)
	}
	addr, err = fx.tun.ListenService("nas", "127.0.0.94")
	if err != nil {
		t.Fatal(err)
	}
	if g := readGreeting(t, addr); g != "" {
		t.Fatalf("ungranted service reached: %q", g)
	}
	release, err := fx.tun.Hold()
	if err != nil {
		t.Fatal(err)
	}
	release()
}
