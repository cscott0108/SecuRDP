package client

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// HubFolder / HubService are what a hub offers this login besides computers.
type HubFolder struct {
	Name     string `json:"name"`
	Writable bool   `json:"writable"`
}

type HubService struct {
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
	Path   string `json:"path"`
	Target string `json:"target,omitempty"` // host:port on the home network (1.6+ hubs)
}

type HubInfo struct {
	Computers []HubComputer `json:"computers"`
	Folders   []HubFolder   `json:"folders"`
	Services  []HubService  `json:"services"`
}

// readAll opens a pseudo destination and reads its whole reply, giving up
// after a few seconds (older gates forward unknown names to Remote Desktop,
// which never sends anything first).
func (t *Tunnel) readAll(dest string, wait time.Duration) ([]byte, error) {
	type res struct {
		b   []byte
		err error
	}
	c := make(chan res, 1)
	go func() {
		ch, err := t.ssh.Dial("tcp", dest)
		if err != nil {
			c <- res{nil, err}
			return
		}
		defer ch.Close()
		b, err := io.ReadAll(io.LimitReader(ch, 1<<20))
		c <- res{b, err}
	}()
	select {
	case r := <-c:
		return r.b, r.err
	case <-time.After(wait):
		return nil, errors.New("no reply")
	}
}

// Info asks the hub for computers, shared folders and web services. With a
// pre-1.5 hub it falls back to the computer list only.
func (t *Tunnel) Info() (*HubInfo, error) {
	b, err := t.readAll("hub.securdp:0", 4*time.Second)
	info := &HubInfo{}
	if err == nil && len(b) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Split(line, "\t")
			switch {
			case f[0] == "c" && len(f) == 4:
				info.Computers = append(info.Computers, HubComputer{f[1], f[2] == "1", f[3] == "1"})
			case f[0] == "f" && len(f) == 3:
				info.Folders = append(info.Folders, HubFolder{f[1], f[2] == "1"})
			case f[0] == "s" && len(f) == 4:
				info.Services = append(info.Services, HubService{Name: f[1], Scheme: f[2], Path: f[3]})
			case f[0] == "S" && len(f) == 3:
				for i := range info.Services {
					if info.Services[i].Name == f[1] {
						info.Services[i].Target = f[2]
					}
				}
			}
		}
		if len(info.Computers)+len(info.Folders)+len(info.Services) > 0 {
			return info, nil
		}
	}
	list, err := t.Computers()
	info.Computers = list
	return info, err
}

// Hold keeps the tunnel open on the hub while files or web pages are in use
// (no Remote Desktop session needed). Call the returned func to let go.
func (t *Tunnel) Hold() (func(), error) {
	ch, err := t.ssh.Dial("tcp", "hold.securdp:0")
	if err != nil {
		return func() {}, err
	}
	return func() { ch.Close() }, nil
}

// FileEntry is one item of a folder listing.
type FileEntry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

// fileRequest sends one request and returns the channel positioned after
// the status line, plus the status line's number field.
func (t *Tunnel) fileRequest(body io.Reader, op string, args ...string) (io.ReadCloser, int64, error) {
	ch, err := t.ssh.Dial("tcp", "files.securdp:0")
	if err != nil {
		return nil, 0, fmt.Errorf("file access refused: %w", err)
	}
	line := strings.Join(append([]string{op}, args...), "\t") + "\n"
	if _, err := io.WriteString(ch, line); err != nil {
		ch.Close()
		return nil, 0, err
	}
	if body != nil {
		if _, err := io.Copy(ch, body); err != nil {
			ch.Close()
			return nil, 0, err
		}
	}
	br := bufio.NewReader(ch)
	status, err := br.ReadString('\n')
	if err != nil {
		ch.Close()
		return nil, 0, errors.New("no reply from the hub")
	}
	f := strings.SplitN(strings.TrimRight(status, "\n"), "\t", 2)
	if f[0] != "ok" {
		ch.Close()
		if len(f) == 2 {
			return nil, 0, errors.New(f[1])
		}
		return nil, 0, errors.New("request failed")
	}
	var n int64
	if len(f) == 2 {
		n, _ = strconv.ParseInt(f[1], 10, 64)
	}
	return struct {
		io.Reader
		io.Closer
	}{br, ch}, n, nil
}

func (t *Tunnel) simple(op string, args ...string) error {
	r, _, err := t.fileRequest(nil, op, args...)
	if err == nil {
		r.Close()
	}
	return err
}

// List returns a folder's entries; path "" lists the shared folders.
func (t *Tunnel) List(path string) ([]FileEntry, error) {
	op, args := "list", []string{path}
	if path == "" {
		op, args = "roots", nil
	}
	r, _, err := t.fileRequest(nil, op, args...)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []FileEntry
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Split(line, "\t")
		switch {
		case path == "" && len(f) == 2:
			out = append(out, FileEntry{Name: f[0], Dir: true})
		case len(f) == 4:
			size, _ := strconv.ParseInt(f[1], 10, 64)
			mt, _ := strconv.ParseInt(f[2], 10, 64)
			out = append(out, FileEntry{Name: f[3], Dir: f[0] == "d", Size: size, MTime: mt})
		}
	}
	return out, nil
}

// Get streams a file from offset; size is the whole file's size.
func (t *Tunnel) Get(path string, offset int64) (io.ReadCloser, int64, error) {
	return t.fileRequest(nil, "get", path, strconv.FormatInt(offset, 10))
}

// Thumb returns a JPEG thumbnail (images and videos only).
func (t *Tunnel) Thumb(path string, px int) ([]byte, error) {
	r, n, err := t.fileRequest(nil, "thumb", path, strconv.Itoa(px))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b := make([]byte, n)
	_, err = io.ReadFull(r, b)
	return b, err
}

// Put uploads size bytes from body as path (which must not exist yet).
func (t *Tunnel) Put(path string, size int64, body io.Reader) error {
	r, _, err := t.fileRequest(io.LimitReader(body, size), "put", path, strconv.FormatInt(size, 10))
	if err == nil {
		r.Close()
	}
	return err
}

func (t *Tunnel) Mkdir(path string) error      { return t.simple("mkdir", path) }
func (t *Tunnel) Delete(path string) error     { return t.simple("delete", path) }
func (t *Tunnel) Rename(from, to string) error { return t.simple("rename", from, to) }
