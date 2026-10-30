// Package config holds the server and client configuration files.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const AppName = "SecuRDP"

// ServerDir is %ProgramData%\SecuRDP (ACL'd to SYSTEM + Administrators).
func ServerDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, AppName)
}

// ClientDir is %APPDATA%\SecuRDP (per user).
func ClientDir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, AppName)
}

// LegacyAppName is the name used before the rename to SecuRDP.
const LegacyAppName = "SecureRDP"

// MigrateClientDir moves %APPDATA%\SecureRDP to %APPDATA%\SecuRDP once.
func MigrateClientDir() {
	old := filepath.Join(filepath.Dir(ClientDir()), LegacyAppName)
	if _, err := os.Stat(ClientDir()); err == nil {
		return
	}
	if _, err := os.Stat(old); err == nil {
		os.Rename(old, ClientDir())
	}
}

// MigrateServerDir moves %ProgramData%\SecureRDP to %ProgramData%\SecuRDP
// once (the old service must already be stopped). Returns true if moved.
func MigrateServerDir() bool {
	old := filepath.Join(filepath.Dir(ServerDir()), LegacyAppName)
	if _, err := os.Stat(ServerDir()); err == nil {
		return false
	}
	if _, err := os.Stat(old); err != nil {
		return false
	}
	if os.Rename(old, ServerDir()) != nil {
		return false
	}
	os.Rename(filepath.Join(ServerDir(), "securerdp.log"), LogPath())
	os.Remove(filepath.Join(ServerDir(), "securerdp.log.1"))
	return true
}

func ServerConfigPath() string { return filepath.Join(ServerDir(), "server.json") }
func HostKeyPath() string      { return filepath.Join(ServerDir(), "hostkey") }
func LogPath() string          { return filepath.Join(ServerDir(), "securdp.log") }
func ClientConfigPath() string { return filepath.Join(ClientDir(), "client.json") }

// User is one account allowed through the gate.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // Argon2id
	TOTPSecret   string `json:"totp_secret"`   // DPAPI-protected, base64 (see secret.go)
	Enabled      bool   `json:"enabled"`
	LastTOTPStep int64  `json:"-"` // in-memory replay protection
}

// Server is the gatekeeper service configuration.
type Server struct {
	ListenPort      int    `json:"listen_port"`
	ListenAddress   string `json:"listen_address"` // "" = all interfaces
	RDPTarget       string `json:"rdp_target"`     // "" = auto-detect 127.0.0.1:<RDP port>
	MaxFailures     int    `json:"max_failures"`
	FailureWindowS  int    `json:"failure_window_seconds"`
	BanMinutes      int    `json:"ban_minutes"`
	MaxSessions     int    `json:"max_sessions"`
	IdleTimeoutMin  int    `json:"idle_timeout_minutes"` // close tunnel this long after the last RDP connection ends (0 = never)
	BlockDirectRDP  bool   `json:"block_direct_rdp"`     // firewall rule blocking 3389 from the network
	AllowedSources  []string `json:"allowed_sources"`    // optional CIDR allow-list; empty = any
	Users           []User `json:"users"`
}

func DefaultServer() *Server {
	return &Server{
		ListenPort:     0, // chosen in setup
		MaxFailures:    5,
		FailureWindowS: 600,
		BanMinutes:     30,
		MaxSessions:    2,
		IdleTimeoutMin: 5,
		BlockDirectRDP: true,
	}
}

func (s *Server) FindUser(name string) *User {
	for i := range s.Users {
		if strings.EqualFold(s.Users[i].Username, name) {
			return &s.Users[i]
		}
	}
	return nil
}

func (s *Server) Validate() error {
	if s.ListenPort < 1024 || s.ListenPort > 65535 {
		return errors.New("listen port must be between 1024 and 65535")
	}
	if s.ListenPort == 3389 {
		return errors.New("listen port must not be the RDP port")
	}
	if s.MaxFailures < 1 || s.BanMinutes < 1 || s.MaxSessions < 1 {
		return errors.New("max failures, ban minutes and max sessions must be at least 1")
	}
	return nil
}

var serverMu sync.Mutex

func LoadServer() (*Server, error) {
	serverMu.Lock()
	defer serverMu.Unlock()
	s := DefaultServer()
	b, err := os.ReadFile(ServerConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

func SaveServer(s *Server) error {
	serverMu.Lock()
	defer serverMu.Unlock()
	if err := EnsureServerDir(); err != nil {
		return err
	}
	return writeJSON(ServerConfigPath(), s)
}

// Profile is a saved connection on the client side.
type Profile struct {
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	HostFingerprint string `json:"host_fingerprint"` // pinned on first connect (SHA256:...)
	RDPFullscreen   bool   `json:"rdp_fullscreen"`
	RDPUsername     string `json:"rdp_username"` // Windows login on the remote PC (prefilled in mstsc)
	// LocalIP is a per-profile loopback address (127.0.0.x). Windows saves RDP
	// credentials per address, so each profile gets its own "Remember me".
	LocalIP string `json:"local_ip"`
}

// AssignLocalIP gives p a loopback address not used by another profile.
func (c *Client) AssignLocalIP(p *Profile) {
	if p.LocalIP != "" {
		return
	}
	used := map[string]bool{}
	for _, o := range c.Profiles {
		used[o.LocalIP] = true
	}
	for i := 10; i < 250; i++ {
		ip := fmt.Sprintf("127.0.0.%d", i)
		if !used[ip] {
			p.LocalIP = ip
			return
		}
	}
	p.LocalIP = "127.0.0.1"
}

type Client struct {
	Profiles []Profile `json:"profiles"`
}

func LoadClient() (*Client, error) {
	c := &Client{}
	b, err := os.ReadFile(ClientConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	return c, json.Unmarshal(b, c)
}

func SaveClient(c *Client) error {
	if err := os.MkdirAll(ClientDir(), 0o700); err != nil {
		return err
	}
	return writeJSON(ClientConfigPath(), c)
}

func (c *Client) Find(name string) *Profile {
	for i := range c.Profiles {
		if c.Profiles[i].Name == name {
			return &c.Profiles[i]
		}
	}
	return nil
}

// writeJSON writes atomically via a temp file + rename.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
