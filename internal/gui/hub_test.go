package gui

import (
	"net/http/httptest"
	"strings"
	"testing"

	"securdp/internal/config"
)

// call invokes a handler with a JSON body.
func call(t *testing.T, h handlerFunc, body string) error {
	t.Helper()
	_, err := h(httptest.NewRequest("POST", "/", strings.NewReader(body)))
	return err
}

// Runs the hub settings handlers against a throwaway %ProgramData%, never
// the real server config.
func TestHubHandlers(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	config.LockServerDir = false
	defer func() { config.LockServerDir = true }()
	if err := config.SaveServer(&config.Server{ListenPort: 40000, MaxFailures: 5, BanMinutes: 30, MaxSessions: 2,
		Users: []config.User{{Username: "alex", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	load := func() *config.Server {
		c, err := config.LoadServer()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if err := call(t, setMode, `{"mode":"hub"}`); err != nil {
		t.Fatal(err)
	}
	if c := load(); !c.IsHub() || len(c.Computers) != 1 || c.Computers[0].Name != config.ThisPC {
		t.Fatalf("hub should start with this-pc: %+v", c.Computers)
	}
	for _, b := range []string{
		`{"computer":{"name":"desktop","address":"192.168.1.50","mac":"00-11-22-33-44-55"}}`,
		`{"computer":{"name":"laptop","address":"192.168.1.93"}}`,
	} {
		if err := call(t, saveComputer, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := call(t, saveComputer, `{"computer":{"name":"laptop","address":"10.0.0.1"}}`); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if err := call(t, saveComputer, `{"computer":{"name":"Bad Name","address":"10.0.0.1"}}`); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := call(t, setUserAccess, `{"username":"alex","restricted":true,"computers":["desktop","laptop"]}`); err != nil {
		t.Fatal(err)
	}
	if err := call(t, setDefaultComputer, `{"name":"desktop"}`); err != nil {
		t.Fatal(err)
	}
	// Renaming carries over access and default.
	if err := call(t, saveComputer, `{"original":"desktop","computer":{"name":"office","address":"192.168.1.50"}}`); err != nil {
		t.Fatal(err)
	}
	c := load()
	if c.DefaultComputer != "office" || c.Users[0].Computers[0] != "office" {
		t.Fatalf("rename not propagated: default=%q access=%v", c.DefaultComputer, c.Users[0].Computers)
	}
	// Removing a computer removes it from users and the default.
	if err := call(t, deleteComputer, `{"name":"office"}`); err != nil {
		t.Fatal(err)
	}
	c = load()
	if c.DefaultComputer != "" || len(c.Users[0].Computers) != 1 || c.Users[0].Computers[0] != "laptop" {
		t.Fatalf("delete not propagated: default=%q access=%v", c.DefaultComputer, c.Users[0].Computers)
	}

	// DuckDNS: enabling needs a token; the token is stored encrypted.
	if err := call(t, saveDDNS, `{"enabled":true,"domain":"myhome"}`); err == nil {
		t.Fatal("enabled without token")
	}
	if err := call(t, saveDDNS, `{"enabled":false,"domain":"myhome.duckdns.org","token":"tok-123"}`); err != nil {
		t.Fatal(err)
	}
	c = load()
	if c.DDNS.Domain != "myhome" || c.DDNS.Token == "" || strings.Contains(c.DDNS.Token, "tok-123") {
		t.Fatalf("ddns stored wrong: %+v", c.DDNS)
	}
	if got, _ := config.UnprotectSecret(c.DDNS.Token); got != "tok-123" {
		t.Fatal("token round trip")
	}
}
