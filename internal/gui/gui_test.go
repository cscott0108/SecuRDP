package gui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBeginUserMakesQR(t *testing.T) {
	a := &app{pending: map[string]pendingUser{}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"username":"blue.falcon","password":"Long-enough-pass-1","confirm":"Long-enough-pass-1"}`))
	res, err := a.beginUser(r)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]string)
	if !strings.HasPrefix(m["qr"], "data:image/png;base64,") || len(m["secret"]) < 32 || len(a.pending) != 1 {
		t.Fatalf("unexpected: %v", m)
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"username":"admin","password":"Long-enough-pass-1","confirm":"Long-enough-pass-1"}`))
	if _, err := a.beginUser(r); err == nil {
		t.Fatal("admin username accepted")
	}
}

func TestGuard(t *testing.T) {
	a := &app{token: "secret", host: "127.0.0.1:1"}
	h := a.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	try := func(host, tok string) int {
		r := httptest.NewRequest("POST", "http://"+host+"/api/state", bytes.NewReader(nil))
		r.Host = host
		if tok != "" {
			r.Header.Set("X-Token", tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if try("127.0.0.1:1", "secret") != 200 || try("127.0.0.1:1", "") != 403 || try("evil.com", "secret") != 403 {
		t.Fatal("guard not enforcing token/host")
	}
}
