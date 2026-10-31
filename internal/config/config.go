// Package config holds the server and client configuration files.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	// Hub mode: when Restricted, the user may only reach Computers;
	// otherwise every computer on the hub.
	Restricted bool     `json:"restricted,omitempty"`
	Computers  []string `json:"computers,omitempty"`
}

// ThisPC is the built-in computer name for the gate PC's own Remote Desktop.
const ThisPC = "this-pc"

// Computer is a Remote Desktop target the hub may forward to. Users pick it
// by logging in as "username+name".
type Computer struct {
	Name    string `json:"name"`          // lowercase slug, e.g. "desktop"
	Address string `json:"address"`       // host or host:port on the home network ("" for this-pc)
	MAC     string `json:"mac,omitempty"` // for Wake-on-LAN
}

// DDNS keeps a dynamic DNS name pointed at this network's public IP.
type DDNS struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // "duckdns"
	Domain   string `json:"domain"`   // e.g. "myhome" for myhome.duckdns.org
	Token    string `json:"token"`    // DPAPI-protected
}

func DDNSStatusPath() string { return filepath.Join(ServerDir(), "ddns-status.json") }

// DDNSStatus is written by the service after each update attempt.
type DDNSStatus struct {
	IP      string `json:"ip"`
	Updated int64  `json:"updated"` // unix time of last successful update
	Checked int64  `json:"checked"` // unix time of last attempt
	Result  string `json:"result"`
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

	// Mode is "server" (forward to this PC only) or "hub" (forward to the
	// Computers list). Empty means "server".
	Mode            string     `json:"mode,omitempty"`
	Computers       []Computer `json:"computers,omitempty"`
	DefaultComputer string     `json:"default_computer,omitempty"`
	DDNS            DDNS       `json:"ddns"`
}

func (s *Server) IsHub() bool { return s.Mode == "hub" }

// ActiveComputers is what the gate can forward to right now. Server mode
// (and a hub with nothing configured yet) is just this PC.
func (s *Server) ActiveComputers() []Computer {
	if !s.IsHub() || len(s.Computers) == 0 {
		return []Computer{{Name: ThisPC}}
	}
	return s.Computers
}

// FindComputer looks a computer up by name among the active ones.
func (s *Server) FindComputer(name string) *Computer {
	for _, c := range s.ActiveComputers() {
		if strings.EqualFold(c.Name, name) {
			c := c
			return &c
		}
	}
	return nil
}

// CanReach reports whether u may use computer name.
func (u *User) CanReach(name string) bool {
	if !u.Restricted {
		return true
	}
	for _, c := range u.Computers {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
}

// SplitLogin splits "user+computer" into its parts ("user", "" without a +).
func SplitLogin(login string) (user, computer string) {
	if i := strings.LastIndexByte(login, '+'); i > 0 {
		return login[:i], strings.ToLower(login[i+1:])
	}
	return login, ""
}

// ResolveTarget picks the computer for a login: the one named after '+', or
// the default computer, or the user's first reachable one.
func (s *Server) ResolveTarget(u *User, requested string) (*Computer, error) {
	if requested != "" {
		c := s.FindComputer(requested)
		if c == nil {
			return nil, fmt.Errorf("unknown computer %q", requested)
		}
		if !u.CanReach(c.Name) {
			return nil, fmt.Errorf("user %s may not reach %q", u.Username, c.Name)
		}
		return c, nil
	}
	if s.DefaultComputer != "" {
		if c := s.FindComputer(s.DefaultComputer); c != nil && u.CanReach(c.Name) {
			return c, nil
		}
	}
	for _, c := range s.ActiveComputers() {
		if u.CanReach(c.Name) {
			c := c
			return &c, nil
		}
	}
	return nil, fmt.Errorf("user %s has no computers assigned", u.Username)
}

var computerName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidateComputer checks a computer entry (name slug, address, MAC).
func ValidateComputer(c Computer) error {
	if !computerName.MatchString(c.Name) {
		return errors.New("computer name must be 1-32 lowercase letters, digits or '-' (it's typed after '+' in the username)")
	}
	if c.Name == ThisPC {
		return nil
	}
	if c.Address == "" {
		return errors.New("address is required")
	}
	host, port := c.Address, "3389"
	if h, p, err := net.SplitHostPort(c.Address); err == nil {
		host, port = h, p
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("port must be 1-65535")
	}
	if host == "" || strings.ContainsAny(host, " /\\") {
		return errors.New("address must be an IP address or computer name, optionally with :port")
	}
	if c.MAC != "" {
		if _, err := net.ParseMAC(c.MAC); err != nil {
			return errors.New("MAC address should look like 00-11-22-33-44-55")
		}
	}
	return nil
}

// DialAddress returns host:port for a computer (default port 3389).
func (c Computer) DialAddress() string {
	if _, _, err := net.SplitHostPort(c.Address); err == nil {
		return c.Address
	}
	return net.JoinHostPort(c.Address, "3389")
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
	// Hub profiles: Computer is the PC to connect to without asking ("" =
	// show the picker); ComputerIPs gives each hub PC its own loopback
	// address so Remote Desktop keeps a separate saved login per PC.
	Computer    string            `json:"computer,omitempty"`
	ComputerIPs map[string]string `json:"computer_ips,omitempty"`
}

func (c *Client) usedIPs() map[string]bool {
	used := map[string]bool{}
	for _, o := range c.Profiles {
		used[o.LocalIP] = true
		for _, ip := range o.ComputerIPs {
			used[ip] = true
		}
	}
	return used
}

func freeIP(used map[string]bool) string {
	for i := 10; i < 250; i++ {
		if ip := fmt.Sprintf("127.0.0.%d", i); !used[ip] {
			return ip
		}
	}
	return "127.0.0.1"
}

// AssignLocalIP gives p a loopback address not used by another profile.
func (c *Client) AssignLocalIP(p *Profile) {
	if p.LocalIP == "" {
		p.LocalIP = freeIP(c.usedIPs())
	}
}

// ComputerIP returns (assigning if needed) the loopback address for a hub
// computer within profile p. The caller saves the client config.
func (c *Client) ComputerIP(p *Profile, computer string) string {
	if computer == "" {
		return p.LocalIP
	}
	if ip, ok := p.ComputerIPs[computer]; ok {
		return ip
	}
	if p.ComputerIPs == nil {
		p.ComputerIPs = map[string]string{}
	}
	ip := freeIP(c.usedIPs())
	p.ComputerIPs[computer] = ip
	return ip
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
