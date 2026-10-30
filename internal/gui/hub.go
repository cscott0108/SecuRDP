package gui

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"securdp/internal/config"
	"securdp/internal/ddns"
	"securdp/internal/server"
	"securdp/internal/winutil"
)

// The service reloads server.json when it changes, so none of these handlers
// need to restart it.

type computerView struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	MAC     string `json:"mac"`
	Dial    string `json:"dial"`
}

func hubState(cfg *config.Server) map[string]any {
	comps := []computerView{}
	for _, c := range cfg.Computers {
		dial := c.DialAddress()
		if c.Name == config.ThisPC {
			dial = "this PC"
		}
		comps = append(comps, computerView{c.Name, c.Address, c.MAC, dial})
	}
	st := ddns.LoadStatus()
	return map[string]any{
		"mode":             map[bool]string{true: "hub", false: "server"}[cfg.IsHub()],
		"computers":        comps,
		"default_computer": cfg.DefaultComputer,
		"ddns": map[string]any{
			"enabled":   cfg.DDNS.Enabled,
			"domain":    cfg.DDNS.Domain,
			"hostname":  ddns.Hostname(cfg.DDNS.Domain),
			"has_token": cfg.DDNS.Token != "",
			"status":    st,
		},
	}
}

func withConfig(fn func(cfg *config.Server) error) error {
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	return config.SaveServer(cfg)
}

func setMode(r *http.Request) (any, error) {
	in, err := decode[struct{ Mode string }](r)
	if err != nil {
		return nil, err
	}
	if in.Mode != "hub" && in.Mode != "server" {
		return nil, errors.New("mode must be server or hub")
	}
	return nil, withConfig(func(cfg *config.Server) error {
		cfg.Mode = in.Mode
		// Starting a hub: keep this PC reachable until other computers are added.
		if cfg.IsHub() && len(cfg.Computers) == 0 {
			cfg.Computers = []config.Computer{{Name: config.ThisPC}}
		}
		return nil
	})
}

func saveComputer(r *http.Request) (any, error) {
	in, err := decode[struct {
		Original string          `json:"original"`
		Computer config.Computer `json:"computer"`
	}](r)
	if err != nil {
		return nil, err
	}
	c := in.Computer
	c.Name = strings.ToLower(strings.TrimSpace(c.Name))
	c.Address = strings.TrimSpace(c.Address)
	c.MAC = strings.TrimSpace(c.MAC)
	if c.Name == config.ThisPC {
		c.Address = ""
	}
	if err := config.ValidateComputer(c); err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		idx := -1
		for i, x := range cfg.Computers {
			if x.Name == in.Original && in.Original != "" {
				idx = i
			} else if x.Name == c.Name {
				return errors.New("a computer with that name already exists")
			}
		}
		if idx >= 0 {
			old := cfg.Computers[idx].Name
			cfg.Computers[idx] = c
			if old != c.Name { // keep users' access and the default pointing at the renamed computer
				renameComputer(cfg, old, c.Name)
			}
		} else {
			cfg.Computers = append(cfg.Computers, c)
		}
		return nil
	})
}

func renameComputer(cfg *config.Server, old, name string) {
	if cfg.DefaultComputer == old {
		cfg.DefaultComputer = name
	}
	for i := range cfg.Users {
		for j, c := range cfg.Users[i].Computers {
			if c == old {
				cfg.Users[i].Computers[j] = name
			}
		}
	}
}

func deleteComputer(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		out := cfg.Computers[:0]
		for _, c := range cfg.Computers {
			if c.Name != in.Name {
				out = append(out, c)
			}
		}
		cfg.Computers = out
		if cfg.DefaultComputer == in.Name {
			cfg.DefaultComputer = ""
		}
		for i := range cfg.Users {
			keep := cfg.Users[i].Computers[:0]
			for _, c := range cfg.Users[i].Computers {
				if c != in.Name {
					keep = append(keep, c)
				}
			}
			cfg.Users[i].Computers = keep
		}
		return nil
	})
}

func setDefaultComputer(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		if in.Name != "" && cfg.FindComputer(in.Name) == nil {
			return errors.New("no such computer")
		}
		cfg.DefaultComputer = in.Name
		return nil
	})
}

func findComputer(name string) (*config.Computer, error) {
	cfg, err := config.LoadServer()
	if err != nil {
		return nil, err
	}
	for _, c := range cfg.Computers {
		if c.Name == name {
			return &c, nil
		}
	}
	return nil, errors.New("no such computer")
}

func testComputer(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	c, err := findComputer(in.Name)
	if err != nil {
		return nil, err
	}
	addr := c.DialAddress()
	if c.Name == config.ThisPC {
		addr = "127.0.0.1:" + strconv.Itoa(winutil.GetRDPInfo().Port)
	}
	if err := server.Probe(addr); err != nil {
		hint := "Make sure the PC is on, Remote Desktop is enabled, and its firewall allows RDP from this hub."
		return map[string]any{"ok": false, "message": "No answer from " + addr + ". " + hint}, nil
	}
	return map[string]any{"ok": true, "message": "Remote Desktop answers at " + addr}, nil
}

func wakeComputer(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	c, err := findComputer(in.Name)
	if err != nil {
		return nil, err
	}
	if c.MAC == "" {
		return nil, errors.New("add the computer's MAC address to use Wake-on-LAN")
	}
	return map[string]string{"note": "Wake-up signal sent to " + c.Name + "."}, server.WakeComputer(*c)
}

func setUserAccess(r *http.Request) (any, error) {
	in, err := decode[struct {
		Username   string   `json:"username"`
		Restricted bool     `json:"restricted"`
		Computers  []string `json:"computers"`
	}](r)
	if err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		u := cfg.FindUser(in.Username)
		if u == nil {
			return errors.New("no such user")
		}
		u.Restricted, u.Computers = in.Restricted, in.Computers
		return nil
	})
}

func saveDDNS(r *http.Request) (any, error) {
	in, err := decode[struct {
		Enabled bool   `json:"enabled"`
		Domain  string `json:"domain"`
		Token   string `json:"token"` // empty = keep the saved one
	}](r)
	if err != nil {
		return nil, err
	}
	var saved *config.Server
	err = withConfig(func(cfg *config.Server) error {
		if in.Enabled || in.Domain != "" {
			d, err := ddns.NormalizeDomain(in.Domain)
			if err != nil {
				return err
			}
			cfg.DDNS.Domain = d
		}
		if t := strings.TrimSpace(in.Token); t != "" {
			enc, err := config.ProtectSecret(t)
			if err != nil {
				return err
			}
			cfg.DDNS.Token = enc
		}
		if in.Enabled && cfg.DDNS.Token == "" {
			return errors.New("paste your DuckDNS token (shown at the top of duckdns.org after you sign in)")
		}
		cfg.DDNS.Enabled, cfg.DDNS.Provider = in.Enabled, "duckdns"
		saved = cfg
		return nil
	})
	if err != nil {
		return nil, err
	}
	if saved.DDNS.Enabled {
		return ddns.Sync(saved, true, nil), nil
	}
	return ddns.LoadStatus(), nil
}

func updateDDNS(*http.Request) (any, error) {
	cfg, err := config.LoadServer()
	if err != nil {
		return nil, err
	}
	if !cfg.DDNS.Enabled {
		return nil, errors.New("DuckDNS isn't turned on")
	}
	return ddns.Sync(cfg, true, nil), nil
}
