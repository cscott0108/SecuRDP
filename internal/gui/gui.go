// Package gui serves the configuration/connect UI on a loopback-only HTTP
// server and shows it in a native WebView2 window.
package gui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	webview2 "github.com/jchv/go-webview2"
	qrcode "github.com/skip2/go-qrcode"

	"securdp/internal/auth"
	"securdp/internal/client"
	"securdp/internal/config"
	"securdp/internal/logx"
	"securdp/internal/server"
	"securdp/internal/service"
	"securdp/internal/tray"
	"securdp/internal/winutil"
)

//go:embed web
var webFS embed.FS

type app struct {
	token string
	host  string

	mu      sync.Mutex
	pending map[string]pendingUser
	tunnels  map[string]*client.Tunnel // by profile name
	choosing map[string]*client.Tunnel // logged in, waiting for a picker choice
	quit    chan struct{}
	pubIP   publicIP
}

type pendingUser struct {
	username, password, secret string
	created                    time.Time
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Options: Browser uses the default browser instead of a window; NoOpen
// only prints the URL (useful for debugging the UI).
type Options struct{ Browser, NoOpen bool }

// Run starts the UI and blocks until the window is closed.
func Run(opt Options) error {
	a := &app{token: randHex(32), pending: map[string]pendingUser{}, tunnels: map[string]*client.Tunnel{},
		choosing: map[string]*client.Tunnel{}, quit: make(chan struct{})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	a.host = ln.Addr().String()
	config.MigrateClientDir()
	if winutil.IsElevated() {
		if err := service.MigrateLegacy(); err != nil {
			logUIError("migrate", err)
		}
		if err := config.EnsureServerDir(); err != nil {
			logUIError("startup", err)
		}
	}
	srv := &http.Server{Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer a.closeTunnels()

	url := "http://" + a.host + "/?t=" + a.token
	os.MkdirAll(config.ClientDir(), 0o700)
	title := "SecuRDP"
	if winutil.IsElevated() {
		title += " (Administrator)"
	}
	if opt.Browser || opt.NoOpen {
		fmt.Println("SecuRDP UI:", url)
		if !opt.NoOpen {
			exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		}
		<-a.quit
		return nil
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(config.ClientDir(), "webview"),
		WindowOptions: webview2.WindowOptions{
			Title: title, Width: 1040, Height: 780, Center: true, IconId: 1, // RT_GROUP_ICON #1 from tools/mkres
		},
	})
	if w == nil {
		// No WebView2 runtime: fall back to the default browser.
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		fmt.Println("SecuRDP UI opened in your browser. Close this window (or use Quit in the UI) to exit.")
		<-a.quit
		return nil
	}
	defer w.Destroy()
	go tray.ServeShowRequests(uintptr(w.Window())) // tray / second launch -> focus this window
	go func() { <-a.quit; w.Dispatch(w.Terminate) }()
	w.Navigate(url)
	w.Run()
	return nil
}

func (a *app) closeTunnels() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tunnels {
		t.Close()
	}
	for _, t := range a.choosing {
		t.Close()
	}
}

// guard blocks DNS-rebinding (Host check) and other local processes or web
// pages (secret token) from driving the API.
func (a *app) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != a.host {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(a.token)) != 1 || r.Method != http.MethodPost {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type handlerFunc func(r *http.Request) (any, error)

func (a *app) api(mux *http.ServeMux, path string, admin bool, h handlerFunc) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if admin && !winutil.IsElevated() {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Administrator rights are needed - click 'Restart as administrator'."})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		res, err := h(r)
		if err != nil {
			logUIError(path, err)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if res == nil {
			res = map[string]bool{"ok": true}
		}
		json.NewEncoder(w).Encode(res)
	})
}

// logUIError records failed UI actions in %APPDATA%\SecuRDP\ui.log so
// problems can be diagnosed after the on-screen message is gone.
func logUIError(path string, err error) {
	os.MkdirAll(config.ClientDir(), 0o700)
	f, ferr := os.OpenFile(filepath.Join(config.ClientDir(), "ui.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if ferr != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s  %s  %v\n", time.Now().Format("2006-01-02 15:04:05"), path, err)
}

func decode[T any](r *http.Request) (T, error) {
	var v T
	err := json.NewDecoder(r.Body).Decode(&v)
	return v, err
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServerFS(sub))

	a.api(mux, "/api/state", false, a.state)
	a.api(mux, "/api/elevate", false, func(r *http.Request) (any, error) {
		if err := winutil.RelaunchElevated(); err != nil {
			return nil, err
		}
		go func() { time.Sleep(300 * time.Millisecond); close(a.quit) }()
		return nil, nil
	})
	a.api(mux, "/api/publicip/refresh", false, func(*http.Request) (any, error) {
		a.pubIP.get(true)
		return nil, nil
	})
	a.api(mux, "/api/quit", false, func(r *http.Request) (any, error) {
		go func() { time.Sleep(200 * time.Millisecond); close(a.quit) }()
		return nil, nil
	})

	// --- server side (admin) ---
	a.api(mux, "/api/server/settings", true, a.saveSettings)
	a.api(mux, "/api/users/begin", true, a.beginUser)
	a.api(mux, "/api/users/confirm", true, a.confirmUser)
	a.api(mux, "/api/users/delete", true, a.deleteUser)
	a.api(mux, "/api/users/toggle", true, a.toggleUser)
	a.api(mux, "/api/service/install", true, func(*http.Request) (any, error) { return nil, service.Install() })
	a.api(mux, "/api/service/uninstall", true, func(*http.Request) (any, error) { return nil, service.Uninstall() })
	a.api(mux, "/api/service/restart", true, func(*http.Request) (any, error) { return nil, service.Restart() })
	a.api(mux, "/api/service/stop", true, func(*http.Request) (any, error) { return nil, service.Stop() })
	a.api(mux, "/api/rdp/enable", true, func(*http.Request) (any, error) { return nil, winutil.EnableRDP() })

	// --- hub (admin) ---
	a.api(mux, "/api/hub/mode", true, setMode)
	a.api(mux, "/api/computers/save", true, saveComputer)
	a.api(mux, "/api/computers/delete", true, deleteComputer)
	a.api(mux, "/api/computers/default", true, setDefaultComputer)
	a.api(mux, "/api/computers/test", true, testComputer)
	a.api(mux, "/api/computers/wake", true, wakeComputer)
	a.api(mux, "/api/users/access", true, setUserAccess)
	a.api(mux, "/api/ddns/save", true, saveDDNS)
	a.api(mux, "/api/ddns/update", true, updateDDNS)

	// --- client side ---
	a.api(mux, "/api/profiles/save", false, a.saveProfile)
	a.api(mux, "/api/profiles/delete", false, a.deleteProfile)
	a.api(mux, "/api/connect", false, a.connect)
	a.api(mux, "/api/connect/choose", false, a.choose)
	a.api(mux, "/api/disconnect", false, a.disconnect)

	return a.guard(mux)
}

type userView struct {
	Username   string   `json:"username"`
	Enabled    bool     `json:"enabled"`
	Restricted bool     `json:"restricted"`
	Computers  []string `json:"computers"`
}

func (a *app) state(*http.Request) (any, error) {
	elev := winutil.IsElevated()
	st := map[string]any{
		"elevated": elev,
		"service":  service.Status(),
		"rdp":      winutil.GetRDPInfo(),
		"lan_ips":  lanIPs(),
	}
	ip, checked, ipErr := a.pubIP.get(false)
	st["public_ip"], st["public_ip_error"] = ip, ipErr
	if !checked.IsZero() {
		st["public_ip_checked"] = checked.Unix()
	}
	if elev {
		cfg, err := config.LoadServer()
		if err == nil {
			users := []userView{}
			for _, u := range cfg.Users {
				users = append(users, userView{u.Username, u.Enabled, u.Restricted, append([]string{}, u.Computers...)})
			}
			st["hub"] = hubState(cfg)
			st["settings"] = map[string]any{
				"listen_port": cfg.ListenPort, "block_direct_rdp": cfg.BlockDirectRDP,
				"max_failures": cfg.MaxFailures, "ban_minutes": cfg.BanMinutes,
				"max_sessions": cfg.MaxSessions, "idle_timeout_minutes": cfg.IdleTimeoutMin,
				"allowed_sources": strings.Join(cfg.AllowedSources, ", "),
			}
			st["users"] = users
		}
		if fp, err := server.HostFingerprint(); err == nil {
			st["fingerprint"] = fp
		}
		st["log"] = logx.Tail(config.LogPath(), 16<<10)
	}
	cc, _ := config.LoadClient()
	if cc == nil {
		cc = &config.Client{}
	}
	if cc.Profiles == nil {
		cc.Profiles = []config.Profile{}
	}
	st["profiles"] = cc.Profiles
	a.mu.Lock()
	conn := map[string]string{}
	for n, t := range a.tunnels {
		select {
		case <-t.Done():
			delete(a.tunnels, n)
		default:
			conn[n] = t.LocalAddr
			if t.Computer != "" {
				conn[n] += " → " + t.Computer
			}
		}
	}
	a.mu.Unlock()
	st["connected"] = conn
	return st, nil
}

// lanIPs lists this PC's private IPv4 addresses (for the router port-forward hint).
func lanIPs() []string {
	ips := []string{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			ips = append(ips, n.IP.String())
		}
	}
	return ips
}

func (a *app) saveSettings(r *http.Request) (any, error) {
	in, err := decode[struct {
		ListenPort     int    `json:"listen_port"`
		BlockDirectRDP bool   `json:"block_direct_rdp"`
		MaxFailures    int    `json:"max_failures"`
		BanMinutes     int    `json:"ban_minutes"`
		MaxSessions    int    `json:"max_sessions"`
		IdleTimeout    int    `json:"idle_timeout_minutes"`
		AllowedSources string `json:"allowed_sources"`
	}](r)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return nil, err
	}
	cfg.ListenPort, cfg.BlockDirectRDP = in.ListenPort, in.BlockDirectRDP
	cfg.MaxFailures, cfg.BanMinutes, cfg.MaxSessions, cfg.IdleTimeoutMin = in.MaxFailures, in.BanMinutes, in.MaxSessions, in.IdleTimeout
	cfg.AllowedSources = nil
	for _, s := range strings.Split(in.AllowedSources, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err != nil && net.ParseIP(s) == nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR range", s)
		}
		cfg.AllowedSources = append(cfg.AllowedSources, s)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := config.SaveServer(cfg); err != nil {
		return nil, err
	}
	if service.Status() == "running" {
		return map[string]string{"note": "Saved and service restarted."}, service.Restart()
	}
	return map[string]string{"note": "Saved."}, nil
}

func (a *app) beginUser(r *http.Request) (any, error) {
	in, err := decode[struct{ Username, Password, Confirm string }](r)
	if err != nil {
		return nil, err
	}
	if err := auth.ValidateUsername(in.Username); err != nil {
		return nil, err
	}
	if err := auth.ValidatePassword(in.Password, in.Username); err != nil {
		return nil, err
	}
	if in.Password != in.Confirm {
		return nil, errors.New("passwords do not match")
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	uri := auth.TOTPURI(secret, "SecuRDP", in.Username+"@"+host)
	png, err := qrcode.Encode(uri, qrcode.Medium, 320)
	if err != nil {
		return nil, err
	}
	id := randHex(16)
	a.mu.Lock()
	for k, p := range a.pending {
		if time.Since(p.created) > 15*time.Minute {
			delete(a.pending, k)
		}
	}
	a.pending[id] = pendingUser{in.Username, in.Password, secret, time.Now()}
	a.mu.Unlock()
	// Group the secret in 4s for easier manual typing.
	var grouped []string
	for i := 0; i < len(secret); i += 4 {
		grouped = append(grouped, secret[i:min(i+4, len(secret))])
	}
	return map[string]string{
		"id":     id,
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		"secret": strings.Join(grouped, " "),
	}, nil
}

func (a *app) confirmUser(r *http.Request) (any, error) {
	in, err := decode[struct{ ID, Code string }](r)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	p, ok := a.pending[in.ID]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("setup expired - start again")
	}
	if _, ok := auth.VerifyTOTP(p.secret, in.Code, time.Now()); !ok {
		return nil, errors.New("that code doesn't match. Make sure this PC's clock and your phone's clock are both set automatically, then try the newest code")
	}
	hash, err := auth.HashPassword(p.password)
	if err != nil {
		return nil, err
	}
	enc, err := config.ProtectSecret(p.secret)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return nil, err
	}
	u := config.User{Username: p.username, PasswordHash: hash, TOTPSecret: enc, Enabled: true}
	if ex := cfg.FindUser(p.username); ex != nil {
		*ex = u // replacing = password/authenticator reset
	} else {
		cfg.Users = append(cfg.Users, u)
	}
	if err := config.SaveServer(cfg); err != nil {
		return nil, err
	}
	a.mu.Lock()
	delete(a.pending, in.ID)
	a.mu.Unlock()
	return nil, nil
}

func (a *app) deleteUser(r *http.Request) (any, error) {
	in, err := decode[struct{ Username string }](r)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return nil, err
	}
	out := cfg.Users[:0]
	for _, u := range cfg.Users {
		if !strings.EqualFold(u.Username, in.Username) {
			out = append(out, u)
		}
	}
	cfg.Users = out
	return nil, config.SaveServer(cfg)
}

func (a *app) toggleUser(r *http.Request) (any, error) {
	in, err := decode[struct{ Username string }](r)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return nil, err
	}
	u := cfg.FindUser(in.Username)
	if u == nil {
		return nil, errors.New("no such user")
	}
	u.Enabled = !u.Enabled
	return nil, config.SaveServer(cfg)
}

func (a *app) saveProfile(r *http.Request) (any, error) {
	in, err := decode[struct {
		Original string         `json:"original"`
		Profile  config.Profile `json:"profile"`
	}](r)
	if err != nil {
		return nil, err
	}
	p := in.Profile
	p.Name, p.Host, p.Username = strings.TrimSpace(p.Name), strings.TrimSpace(p.Host), strings.TrimSpace(p.Username)
	if p.Name == "" || p.Host == "" || p.Username == "" || p.Port < 1 || p.Port > 65535 {
		return nil, errors.New("name, host, port and username are required")
	}
	cc, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	if ex := cc.Find(in.Original); ex != nil && in.Original != "" {
		// Changing host or port invalidates the pinned server identity.
		if ex.Host != p.Host || ex.Port != p.Port {
			p.HostFingerprint = ""
		} else {
			p.HostFingerprint = ex.HostFingerprint
		}
		p.LocalIP, p.ComputerIPs = ex.LocalIP, ex.ComputerIPs
		cc.AssignLocalIP(&p)
		*ex = p
	} else {
		if cc.Find(p.Name) != nil {
			return nil, errors.New("a profile with that name already exists")
		}
		p.HostFingerprint, p.LocalIP, p.ComputerIPs = "", "", nil
		cc.AssignLocalIP(&p)
		cc.Profiles = append(cc.Profiles, p)
	}
	return nil, config.SaveClient(cc)
}

func (a *app) deleteProfile(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	cc, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	out := cc.Profiles[:0]
	for _, p := range cc.Profiles {
		if p.Name != in.Name {
			out = append(out, p)
		}
	}
	cc.Profiles = out
	return nil, config.SaveClient(cc)
}

func (a *app) connect(r *http.Request) (any, error) {
	in, err := decode[struct {
		Name, Password, Code string
		TrustFingerprint    string `json:"trust_fingerprint"`
	}](r)
	if err != nil {
		return nil, err
	}
	cc, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	p := cc.Find(in.Name)
	if p == nil {
		return nil, errors.New("profile not found")
	}
	a.mu.Lock()
	if t, ok := a.tunnels[in.Name]; ok {
		select {
		case <-t.Done():
		default:
			a.mu.Unlock()
			return nil, errors.New("already connected")
		}
	}
	a.mu.Unlock()

	if p.HostFingerprint == "" && in.TrustFingerprint != "" {
		p.HostFingerprint = in.TrustFingerprint
		if err := config.SaveClient(cc); err != nil {
			return nil, err
		}
	}
	t, err := client.Connect(*p, in.Password, in.Code)
	var uh *client.UnknownHostError
	if errors.As(err, &uh) {
		return map[string]string{"status": "verify_host", "fingerprint": uh.Fingerprint}, nil
	}
	if err != nil {
		return nil, err
	}

	// A hub with several computers: use the profile's saved choice, or ask.
	list, _ := t.Computers()
	if len(list) > 1 {
		for _, c := range list {
			if c.Name == p.Computer {
				return a.startForward(in.Name, t, c.Name, false)
			}
		}
		a.mu.Lock()
		if old := a.choosing[in.Name]; old != nil {
			old.Close()
		}
		a.choosing[in.Name] = t
		a.mu.Unlock()
		// Don't hold a logged-in tunnel forever if the picker is abandoned.
		time.AfterFunc(3*time.Minute, func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.choosing[in.Name] == t {
				delete(a.choosing, in.Name)
				t.Close()
			}
		})
		return map[string]any{"status": "choose", "computers": list}, nil
	}
	return a.startForward(in.Name, t, "", false)
}

// choose finishes a picker connect: forward to the chosen hub computer.
func (a *app) choose(r *http.Request) (any, error) {
	in, err := decode[struct {
		Name, Computer string
		Remember       bool
	}](r)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	t := a.choosing[in.Name]
	delete(a.choosing, in.Name)
	a.mu.Unlock()
	if t == nil {
		return nil, errors.New("the login expired - connect again")
	}
	if in.Computer == "" {
		t.Close() // picker cancelled
		return nil, nil
	}
	return a.startForward(in.Name, t, in.Computer, in.Remember)
}

// startForward listens locally for computer ("" = the login's computer) on
// that PC's own loopback address and launches Remote Desktop.
func (a *app) startForward(name string, t *client.Tunnel, computer string, remember bool) (any, error) {
	cc, err := config.LoadClient()
	if err != nil {
		t.Close()
		return nil, err
	}
	p := cc.Find(name)
	if p == nil {
		t.Close()
		return nil, errors.New("profile not found")
	}
	ip := cc.ComputerIP(p, computer)
	if remember {
		p.Computer = computer
	}
	config.SaveClient(cc)
	if err := t.Listen(computer, ip); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.LaunchRDP(); err != nil {
		t.Close()
		return nil, err
	}
	a.mu.Lock()
	a.tunnels[name] = t
	a.mu.Unlock()
	return map[string]string{"status": "connected", "local": t.LocalAddr, "computer": computer}, nil
}

func (a *app) disconnect(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.tunnels[in.Name]; ok {
		t.Close()
		delete(a.tunnels, in.Name)
	}
	return nil, nil
}
