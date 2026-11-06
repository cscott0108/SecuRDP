package gui

import (
	"errors"
	"net/http"
	"strings"

	"securdp/internal/config"
	"securdp/internal/server"
)

// Admin handlers for shared folders, web services and per-user grants.
// Like the hub handlers, the service picks changes up without a restart.

func saveFolder(r *http.Request) (any, error) {
	in, err := decode[struct {
		Original string              `json:"original"`
		Folder   config.SharedFolder `json:"folder"`
	}](r)
	if err != nil {
		return nil, err
	}
	f := in.Folder
	f.Name = strings.ToLower(strings.TrimSpace(f.Name))
	f.Path = strings.TrimRight(strings.TrimSpace(f.Path), `\`)
	if len(f.Path) == 2 && f.Path[1] == ':' {
		f.Path += `\` // "D:" -> "D:\"
	}
	if err := config.ValidateFolder(f); err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		idx := -1
		for i, x := range cfg.Folders {
			if x.Name == in.Original && in.Original != "" {
				idx = i
			} else if x.Name == f.Name {
				return errors.New("a shared folder with that name already exists")
			}
		}
		if idx >= 0 {
			renameGrant(cfg, func(u *config.User) *[]string { return &u.Folders }, cfg.Folders[idx].Name, f.Name)
			cfg.Folders[idx] = f
		} else {
			cfg.Folders = append(cfg.Folders, f)
		}
		return nil
	})
}

func deleteFolder(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		out := cfg.Folders[:0]
		for _, f := range cfg.Folders {
			if f.Name != in.Name {
				out = append(out, f)
			}
		}
		cfg.Folders = out
		renameGrant(cfg, func(u *config.User) *[]string { return &u.Folders }, in.Name, "")
		return nil
	})
}

func saveService(r *http.Request) (any, error) {
	in, err := decode[struct {
		Original string            `json:"original"`
		Service  config.WebService `json:"service"`
	}](r)
	if err != nil {
		return nil, err
	}
	w := in.Service
	w.Name = strings.ToLower(strings.TrimSpace(w.Name))
	w.URL = strings.TrimSpace(w.URL)
	if w.URL != "" && !strings.Contains(w.URL, "://") {
		w.URL = "http://" + w.URL
	}
	if err := config.ValidateService(w); err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		idx := -1
		for i, x := range cfg.Services {
			if x.Name == in.Original && in.Original != "" {
				idx = i
			} else if x.Name == w.Name {
				return errors.New("a web service with that name already exists")
			}
		}
		if idx >= 0 {
			renameGrant(cfg, func(u *config.User) *[]string { return &u.Services }, cfg.Services[idx].Name, w.Name)
			cfg.Services[idx] = w
		} else {
			cfg.Services = append(cfg.Services, w)
		}
		return nil
	})
}

func deleteService(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		out := cfg.Services[:0]
		for _, w := range cfg.Services {
			if w.Name != in.Name {
				out = append(out, w)
			}
		}
		cfg.Services = out
		renameGrant(cfg, func(u *config.User) *[]string { return &u.Services }, in.Name, "")
		return nil
	})
}

func testService(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return nil, err
	}
	for _, w := range cfg.Services {
		if w.Name == in.Name {
			addr, _, _, err := w.Target()
			if err != nil {
				return nil, err
			}
			if err := server.Probe(addr); err != nil {
				return map[string]any{"ok": false, "message": "No answer from " + addr + "."}, nil
			}
			return map[string]any{"ok": true, "message": w.Name + " answers at " + addr}, nil
		}
	}
	return nil, errors.New("no such service")
}

// renameGrant renames (or with to == "" removes) a grant in every user.
func renameGrant(cfg *config.Server, list func(*config.User) *[]string, from, to string) {
	for i := range cfg.Users {
		l := list(&cfg.Users[i])
		out := (*l)[:0]
		for _, n := range *l {
			switch {
			case n != from:
				out = append(out, n)
			case to != "":
				out = append(out, to)
			}
		}
		*l = out
	}
}

func setUserGrants(r *http.Request) (any, error) {
	in, err := decode[struct {
		Username string   `json:"username"`
		Folders  []string `json:"folders"`
		Services []string `json:"services"`
	}](r)
	if err != nil {
		return nil, err
	}
	return nil, withConfig(func(cfg *config.Server) error {
		u := cfg.FindUser(in.Username)
		if u == nil {
			return errors.New("no such user")
		}
		u.Folders, u.Services = in.Folders, in.Services
		return nil
	})
}
