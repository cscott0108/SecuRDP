package ddns

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"myhome": "myhome", "MyHome.duckdns.org": "myhome", "https://my-home.duckdns.org/": "my-home",
	} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "my home", "a.b.duckdns.org", "x/y"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUpdate(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		if r.URL.Query().Get("token") == "good" {
			w.Write([]byte("OK"))
		} else {
			w.Write([]byte("KO"))
		}
	}))
	defer srv.Close()
	old := DuckDNSURL
	DuckDNSURL = srv.URL
	defer func() { DuckDNSURL = old }()

	if err := Update("myhome", "good", "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "domains=myhome") || !strings.Contains(got, "ip=203.0.113.7") {
		t.Fatalf("query %q", got)
	}
	err := Update("myhome", "bad", "203.0.113.7")
	if err == nil || strings.Contains(err.Error(), "bad") {
		t.Fatalf("expected rejection without leaking the token, got %v", err)
	}
}

func TestUnreachableErrorHidesToken(t *testing.T) {
	old := DuckDNSURL
	DuckDNSURL = "http://127.0.0.1:1/update"
	defer func() { DuckDNSURL = old }()
	err := Update("myhome", "secret-token-123", "203.0.113.7")
	if err == nil || strings.Contains(err.Error(), "secret-token-123") {
		t.Fatalf("token leaked or no error: %v", err)
	}
}
