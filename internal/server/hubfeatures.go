package server

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/files"
	"securdp/internal/thumb"
)

// Pseudo destinations a client can open besides Remote Desktop. Each is
// checked against the logged-in user's grants.
const (
	// hubHost returns everything this user may use, tab-separated:
	//   c \t name \t online \t default      (computers)
	//   f \t name \t writable               (shared folders)
	//   s \t name \t scheme \t path         (web services)
	//   S \t name \t host:port              (a web service's own address, 1.6+)
	hubHost   = "hub.securdp"
	filesHost = "files.securdp" // one file request per channel (see package files)
	holdHost  = "hold.securdp"  // held open by a client browsing files or web pages
	svcPrefix = "svc."          // "svc.<name>" forwards to that web service
)

func accept(nc ssh.NewChannel) (ssh.Channel, bool) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return nil, false
	}
	go ssh.DiscardRequests(reqs)
	return ch, true
}

func (s *Server) sendHubInfo(nc ssh.NewChannel, user, loginComputer string) {
	ch, ok := accept(nc)
	if !ok {
		return
	}
	defer ch.Close()
	var b strings.Builder
	for _, c := range s.reachable(user, loginComputer) {
		fmt.Fprintf(&b, "c\t%s\t%d\t%d\n", c.name, b2i(c.online), b2i(c.isDefault))
	}
	cfg := s.config()
	if u := cfg.FindUser(user); u != nil {
		for _, f := range cfg.GrantedFolders(u) {
			fmt.Fprintf(&b, "f\t%s\t%d\n", f.Name, b2i(f.Writable))
		}
		for _, w := range cfg.GrantedServices(u) {
			if hostport, scheme, path, err := w.Target(); err == nil {
				fmt.Fprintf(&b, "s\t%s\t%s\t%s\n", w.Name, scheme, path)
				// The service's own address, so clients can route links a page
				// builds with it back through the tunnel. A separate line type
				// keeps pre-1.6 clients (which skip unknown lines) working.
				fmt.Fprintf(&b, "S\t%s\t%s\n", w.Name, hostport)
			}
		}
	}
	io.WriteString(ch, b.String())
}

func (s *Server) serveFiles(nc ssh.NewChannel, tr *tracker, user, ip string) {
	cfg := s.config()
	u := cfg.FindUser(user)
	if u == nil || len(cfg.GrantedFolders(u)) == 0 {
		nc.Reject(ssh.Prohibited, "no shared folders for this user")
		s.log.Printf("REJECT %s user=%s: file access not granted", ip, user)
		return
	}
	ch, ok := accept(nc)
	if !ok {
		return
	}
	defer ch.Close()
	tr.opened() // file activity counts as use, like an RDP connection
	defer tr.closed()
	h := &files.Handler{Folders: cfg.GrantedFolders(u), User: user, Log: s.log.Printf, Thumb: thumb.Get}
	h.Serve(ch)
	ch.CloseWrite()
}

// hold keeps the tunnel open while a client has a file browser or web page
// open, even with no Remote Desktop session.
func (s *Server) hold(nc ssh.NewChannel, tr *tracker, user string) {
	cfg := s.config()
	u := cfg.FindUser(user)
	if u == nil || (len(cfg.GrantedFolders(u)) == 0 && len(cfg.GrantedServices(u)) == 0) {
		nc.Reject(ssh.Prohibited, "nothing to hold open")
		return
	}
	ch, ok := accept(nc)
	if !ok {
		return
	}
	tr.opened()
	defer tr.closed()
	io.Copy(io.Discard, ch) // until the client closes it
	ch.Close()
}

func (s *Server) forwardService(nc ssh.NewChannel, tr *tracker, user, ip, name string) {
	cfg := s.config()
	u := cfg.FindUser(user)
	var target string
	if u != nil {
		for _, w := range cfg.GrantedServices(u) {
			if strings.EqualFold(w.Name, name) {
				target, _, _, _ = w.Target()
			}
		}
	}
	if target == "" {
		nc.Reject(ssh.Prohibited, "you may not use that service")
		s.log.Printf("REJECT %s user=%s: service %q not granted", ip, user, name)
		return
	}
	dst, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, "the service isn't answering")
		return
	}
	ch, ok := accept(nc)
	if !ok {
		dst.Close()
		return
	}
	tr.opened()
	defer tr.closed()
	done := make(chan struct{}, 2)
	go func() { io.Copy(dst, ch); dst.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(ch, dst); ch.CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
	ch.Close()
	dst.Close()
}
