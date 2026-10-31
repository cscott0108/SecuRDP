package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strconv"
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
