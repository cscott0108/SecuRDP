package gui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"

	"securdp/internal/client"
	"securdp/internal/config"
)

// A hub session is a logged-in tunnel shown on the hub screen. It stays
// open while anything uses it (the hub screen, a file browser, a web page
// window, a Remote Desktop window) - see client.Tunnel Acquire/Release.
type session struct {
	t    *client.Tunnel
	info *client.HubInfo

	mu       sync.Mutex
	holds    int               // file browsers / web windows open
	release  func()            // lets go of the hub-side hold
	svcAddr  map[string]string // web page -> local tunnel address
	external map[string]bool   // web pages opened in the default browser
}

func (a *app) openSession(name string, t *client.Tunnel, info *client.HubInfo) {
	s := &session{t: t, info: info}
	t.Acquire() // the hub screen itself
	a.mu.Lock()
	a.tunnels[name] = t
	a.sessions[name] = s
	a.mu.Unlock()
	go func() {
		<-t.Done()
		a.mu.Lock()
		if a.sessions[name] == s {
			delete(a.sessions, name)
		}
		a.mu.Unlock()
	}()
}

func (a *app) session(name string) (*session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[name]
	if s == nil {
		return nil, errors.New("not connected - connect again")
	}
	select {
	case <-s.t.Done():
		return nil, errors.New("the connection closed - connect again")
	default:
	}
	return s, nil
}

// hold / unhold keep the tunnel alive (locally and on the hub) while a file
// browser or web page window is open.
func (s *session) hold() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.t.Acquire()
	if s.holds++; s.holds == 1 {
		s.release, _ = s.t.Hold()
	}
}

func (s *session) unhold() {
	s.mu.Lock()
	if s.holds > 0 {
		if s.holds--; s.holds == 0 && s.release != nil {
			s.release()
			s.release = nil
		}
	}
	s.mu.Unlock()
	s.t.Release()
}

type nameReq struct {
	Name     string `json:"name"`
	Computer string `json:"computer"`
	Remember bool   `json:"remember"`
	Service  string `json:"service"`
	Path     string `json:"path"`
	To       string `json:"to"`
	On       bool   `json:"on"`
}

func (a *app) sessionRoutes(mux *http.ServeMux) {
	a.api(mux, "/api/hub/rdp", false, func(r *http.Request) (any, error) {
		in, err := decode[nameReq](r)
		if err != nil {
			return nil, err
		}
		s, err := a.session(in.Name)
		if err != nil {
			return nil, err
		}
		return a.startForward(in.Name, s.t, in.Computer, in.Remember, false)
	})
	a.api(mux, "/api/hub/done", false, func(r *http.Request) (any, error) {
		in, err := decode[nameReq](r)
		if err != nil {
			return nil, err
		}
		if s, err := a.session(in.Name); err == nil {
			s.t.Release() // the hub screen; closes the tunnel if nothing else uses it
		}
		return nil, nil
	})
	a.api(mux, "/api/hub/web", false, a.openWeb)
	a.api(mux, "/api/hub/webext", false, a.openExternal)

	a.api(mux, "/api/files/browse", false, func(r *http.Request) (any, error) {
		in, err := decode[nameReq](r)
		if err != nil {
			return nil, err
		}
		s, err := a.session(in.Name)
		if err != nil {
			return nil, err
		}
		if in.On {
			s.hold()
		} else {
			s.unhold()
		}
		return nil, nil
	})
	a.api(mux, "/api/files/list", false, func(r *http.Request) (any, error) {
		in, err := decode[nameReq](r)
		if err != nil {
			return nil, err
		}
		s, err := a.session(in.Name)
		if err != nil {
			return nil, err
		}
		entries, err := s.t.List(in.Path)
		if entries == nil {
			entries = []client.FileEntry{}
		}
		return entries, err
	})
	simple := func(op func(t *client.Tunnel, in nameReq) error) handlerFunc {
		return func(r *http.Request) (any, error) {
			in, err := decode[nameReq](r)
			if err != nil {
				return nil, err
			}
			s, err := a.session(in.Name)
			if err != nil {
				return nil, err
			}
			return nil, op(s.t, in)
		}
	}
	a.api(mux, "/api/files/mkdir", false, simple(func(t *client.Tunnel, in nameReq) error { return t.Mkdir(in.Path) }))
	a.api(mux, "/api/files/delete", false, simple(func(t *client.Tunnel, in nameReq) error { return t.Delete(in.Path) }))
	a.api(mux, "/api/files/rename", false, simple(func(t *client.Tunnel, in nameReq) error { return t.Rename(in.Path, in.To) }))
	a.api(mux, "/api/files/open", false, a.openFile)

	// Uploads stream the raw body (no JSON, no 1 MB API limit).
	mux.HandleFunc("/api/files/upload", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		s, err := a.session(q.Get("name"))
		if err == nil {
			err = s.t.Put(q.Get("path"), r.ContentLength, r.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		io.WriteString(w, `{"ok":true}`)
	})

	mux.HandleFunc("/dl/thumb", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		s, err := a.session(q.Get("name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		px, _ := strconv.Atoi(q.Get("px"))
		key := q.Get("name") + "\x00" + q.Get("path") + "\x00" + q.Get("px")
		img, ok := a.thumbs.get(key)
		if !ok {
			if img, err = s.t.Thumb(q.Get("path"), px); err != nil {
				http.Error(w, "no thumbnail", http.StatusNotFound)
				return
			}
			a.thumbs.put(key, img)
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=600")
		w.Write(img)
	})
	mux.HandleFunc("/dl/file", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		s, err := a.session(q.Get("name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		body, size, err := s.t.Get(q.Get("path"), 0)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer body.Close()
		name := path.Base(q.Get("path"))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		io.Copy(w, body)
	})
}

// openFile downloads a file to a private temp folder and opens it with its
// default Windows app.
func (a *app) openFile(r *http.Request) (any, error) {
	in, err := decode[nameReq](r)
	if err != nil {
		return nil, err
	}
	s, err := a.session(in.Name)
	if err != nil {
		return nil, err
	}
	body, _, err := s.t.Get(in.Path, 0)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b := make([]byte, 8)
	rand.Read(b)
	dir := filepath.Join(os.TempDir(), "SecuRDP", hex.EncodeToString(b))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	name := path.Base(in.Path)
	if strings.ContainsAny(name, `\/:*?"<>|`) || name == "." || name == ".." {
		return nil, errors.New("bad file name")
	}
	dst := filepath.Join(dir, name)
	f, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(f, body)
	f.Close()
	if err != nil {
		return nil, err
	}
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(dst)
	return nil, windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// openWeb forwards a local port to a hub web service and opens it in a
// SecuRDP browser window (a separate process, so it can't freeze this UI).
func (a *app) openWeb(r *http.Request) (any, error) {
	in, err := decode[nameReq](r)
	if err != nil {
		return nil, err
	}
	s, err := a.session(in.Name)
	if err != nil {
		return nil, err
	}
	url, svc, err := s.serviceURL(in.Name, in.Service)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "web", "--title", in.Name+" - "+svc.Name, "--url", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // no console
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s.hold()
	go func() { cmd.Wait(); s.unhold() }()
	return map[string]string{"url": url}, nil
}

// serviceURL returns the local tunnel URL for a hub web page, starting its
// listener once per session. A stable loopback address per service keeps
// its cookies and logins between visits.
func (s *session) serviceURL(profile, service string) (string, *client.HubService, error) {
	var svc *client.HubService
	for i := range s.info.Services {
		if s.info.Services[i].Name == service {
			svc = &s.info.Services[i]
		}
	}
	if svc == nil {
		return "", nil, errors.New("no such web page")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svcAddr == nil {
		s.svcAddr = map[string]string{}
	}
	addr, ok := s.svcAddr[service]
	if !ok {
		cc, err := config.LoadClient()
		if err != nil {
			return "", nil, err
		}
		p := cc.Find(profile)
		if p == nil {
			return "", nil, errors.New("profile not found")
		}
		ip := cc.ComputerIP(p, "web:"+svc.Name)
		config.SaveClient(cc)
		if addr, err = s.t.ListenService(svc.Name, ip); err != nil {
			return "", nil, err
		}
		s.svcAddr[service] = addr
	}
	return svc.Scheme + "://" + addr + svc.Path, svc, nil
}

// openExternal opens (on) or stops (off) a hub web page in the default
// browser. The tunnel can't tell when the browser tab closes, so it stays
// up until the user clicks Stop on the hub screen (or disconnects).
func (a *app) openExternal(r *http.Request) (any, error) {
	in, err := decode[nameReq](r)
	if err != nil {
		return nil, err
	}
	s, err := a.session(in.Name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	open := s.external[in.Service]
	s.mu.Unlock()
	if !in.On {
		if open {
			s.mu.Lock()
			delete(s.external, in.Service)
			s.mu.Unlock()
			s.unhold()
		}
		return nil, nil
	}
	url, _, err := s.serviceURL(in.Name, in.Service)
	if err != nil {
		return nil, err
	}
	if !open {
		s.hold()
		s.mu.Lock()
		if s.external == nil {
			s.external = map[string]bool{}
		}
		s.external[in.Service] = true
		s.mu.Unlock()
	}
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(url)
	if err := windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return nil, err
	}
	return map[string]string{"url": url}, nil
}

// externalPages lists web pages currently opened in the default browser.
func (s *session) externalPages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for n := range s.external {
		out = append(out, n)
	}
	return out
}

// thumbCache keeps recent thumbnails so scrolling back doesn't refetch.
type thumbCache struct {
	mu    sync.Mutex
	m     map[string][]byte
	order []string
}

func (c *thumbCache) get(k string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.m[k]
	return b, ok
}

func (c *thumbCache) put(k string, b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string][]byte{}
	}
	if _, ok := c.m[k]; !ok {
		c.order = append(c.order, k)
	}
	c.m[k] = b
	for len(c.order) > 600 {
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
}
