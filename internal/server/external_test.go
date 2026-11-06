package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/auth"
	"securdp/internal/config"
	"securdp/internal/logx"
)

// TestServeForExternalClient runs a throwaway gate for testing other clients
// (e.g. the Android app's JVM tests). Skipped unless SECURDP_SERVE_ADDR is set.
//
//	user: probe.user  password: Test-passphrase-123  TOTP secret: JBSWY3DPEHPK3PXP
//	hub computers: desktop (default, echo) and laptop (greets "laptop;" then echoes).
//	shared folders: media (read-only samples), drop (writable); web page: status.
//	probe.four may pair app links (devices reaching "status" by key).
func TestServeForExternalClient(t *testing.T) {
	addr := os.Getenv("SECURDP_SERVE_ADDR")
	if addr == "" {
		t.Skip("set SECURDP_SERVE_ADDR to run")
	}
	secs, _ := strconv.Atoi(os.Getenv("SECURDP_SERVE_SECONDS"))
	if secs == 0 {
		secs = 120
	}

	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	enc, err := config.ProtectSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("Test-passphrase-123")
	cfg := config.DefaultServer()
	// A hub: "desktop" (default) is a plain echo, "laptop" greets with "laptop;".
	cfg.Mode = "hub"
	cfg.Computers = []config.Computer{
		{Name: "desktop", Address: echo.Addr().String()},
		{Name: "laptop", Address: namedRDP(t, "laptop")},
	}
	// Two users with the same secret, so tests in any order don't trip replay protection.
	cfg.Users = []config.User{
		{Username: "probe.user", PasswordHash: hash, TOTPSecret: enc, Enabled: true},
		{Username: "probe.two", PasswordHash: hash, TOTPSecret: enc, Enabled: true},
		{Username: "probe.three", PasswordHash: hash, TOTPSecret: enc, Enabled: true},
		{Username: "probe.four", PasswordHash: hash, TOTPSecret: enc, Enabled: true, AppLinks: true},
	}

	// Files & web: "media" (read-only sample images, plus SECURDP_SERVE_MEDIA
	// files if given), "drop" (writable) and a "status" web page.
	media, drop := filepath.Join(t.TempDir(), "media"), t.TempDir()
	os.MkdirAll(filepath.Join(media, "Holiday"), 0o755)
	for i, c := range []color.RGBA{{220, 60, 60, 255}, {60, 160, 90, 255}, {60, 90, 220, 255}, {230, 180, 40, 255}} {
		img := image.NewRGBA(image.Rect(0, 0, 640, 420))
		for y := 0; y < 420; y++ {
			for x := 0; x < 640; x++ {
				img.Set(x, y, color.RGBA{c.R, uint8(int(c.G) * y / 420), uint8(x * 255 / 640), 255})
			}
		}
		f, _ := os.Create(filepath.Join(media, fmt.Sprintf("photo-%d.png", i+1)))
		png.Encode(f, img)
		f.Close()
	}
	os.WriteFile(filepath.Join(media, "Holiday", "notes.txt"), []byte("packing list"), 0o644)
	os.WriteFile(filepath.Join(media, "readme.pdf"), []byte("%PDF-1.4 test"), 0o644)
	if extra := os.Getenv("SECURDP_SERVE_MEDIA"); extra != "" {
		for _, p := range strings.Split(extra, ";") {
			if b, err := os.ReadFile(p); err == nil {
				os.WriteFile(filepath.Join(media, filepath.Base(p)), b, 0o644)
			}
		}
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<h1>Home status page</h1><p>Served through the SecuRDP tunnel.</p>")
	}))
	defer web.Close()
	cfg.Folders = []config.SharedFolder{{Name: "media", Path: media}, {Name: "drop", Path: drop, Writable: true}}
	cfg.Services = []config.WebService{{Name: "status", URL: web.URL + "/"}}
	for i := range cfg.Users {
		cfg.Users[i].Folders = []string{"media", "drop"}
		cfg.Users[i].Services = []string{"status"}
	}

	// The exe offered as an update (default: this test binary).
	if exe := os.Getenv("SECURDP_SERVE_EXE"); exe != "" {
		exePath = func() (string, error) { return exe, nil }
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	log, _ := logx.Open(os.DevNull, os.Stdout)
	s := &Server{log: log, cfg: cfg, static: true, lastStep: map[string]int64{},
		limiter: auth.NewLimiter(10, time.Minute, time.Minute, 5)}
	sc := s.sshConfig(signer)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	go func() { <-ctx.Done(); ln.Close() }()
	t.Logf("test gate on %s, fingerprint %s", addr, ssh.FingerprintSHA256(signer.PublicKey()))
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handle(ctx, c, sc)
	}
}
