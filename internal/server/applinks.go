package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/config"
)

// App links: a device paired from a full password + code session gets a key
// that logs in without prompts but can only reach one granted web service
// (e.g. a background app's API on the hub). Everything else is refused.

// pairHost is the pseudo destination for managing the login's paired
// devices. One request line per channel:
//
//	pair \t name \t service \t authorized-key   -> "ok"
//	unpair \t name                             -> "ok"
//	list                                       -> "ok", then "d \t name \t service \t added" lines
//
// Errors are "err \t message".
const pairHost = "pair.securdp"

// maxLinkSessions caps concurrent app-link sessions (kept apart from
// MaxSessions so a background link never blocks a Remote Desktop login).
const maxLinkSessions = 4

var errDenied = errors.New("denied")

// keyLogin authenticates an app link by its paired device key.
func (s *Server) keyLogin(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	ip := ipOf(conn.RemoteAddr())
	if banned, _ := s.limiter.Banned(ip); banned {
		return nil, errDenied
	}
	cfg := s.config()
	login, _ := config.SplitLogin(conn.User())
	u := cfg.FindUser(login)
	if u == nil || !u.Enabled || !u.AppLinks {
		return nil, errDenied
	}
	want := key.Marshal()
	for _, d := range u.Devices {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.Key))
		if err != nil || !bytes.Equal(pk.Marshal(), want) {
			continue
		}
		granted := false
		for _, w := range cfg.GrantedServices(u) {
			granted = granted || strings.EqualFold(w.Name, d.Service)
		}
		if !granted {
			s.log.Printf("REJECT %s user=%s device=%q: web page %q is no longer granted", ip, u.Username, d.Name, d.Service)
			return nil, errDenied
		}
		return &ssh.Permissions{Extensions: map[string]string{
			"user": u.Username, "device": d.Name, "service": strings.ToLower(d.Service),
		}}, nil
	}
	// Not counted towards a ban: a removed device keeps trying in the
	// background, and banning its IP would also lock out the user's own logins.
	s.log.Printf("FAIL key login from %s user=%q: unknown device key %s", ip, conn.User(), ssh.FingerprintSHA256(key))
	return nil, errDenied
}

// linkChannel serves a channel on an app-link session: only its own service.
func (s *Server) linkChannel(nc ssh.NewChannel, tr *tracker, user, device, service, ip, host string) {
	if nc.ChannelType() != "direct-tcpip" || host != svcPrefix+service {
		nc.Reject(ssh.Prohibited, "this device may only reach its own web page")
		s.log.Printf("REJECT %s user=%s device=%q: may only reach %q, asked for %q", ip, user, device, service, host)
		return
	}
	s.forwardService(nc, tr, user, ip, service)
}

// updateConfig changes server.json (the service reloads it on the next use).
func (s *Server) updateConfig(fn func(*config.Server) error) error {
	if s.static {
		s.mu.Lock()
		defer s.mu.Unlock()
		return fn(s.cfg)
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	return config.SaveServer(cfg)
}

// pair handles one pairing request from a password + code session.
func (s *Server) pair(nc ssh.NewChannel, user, ip string) {
	ch, ok := accept(nc)
	if !ok {
		return
	}
	defer ch.Close()
	defer time.AfterFunc(30*time.Second, func() { ch.Close() }).Stop()
	line, err := bufio.NewReader(io.LimitReader(ch, 8<<10)).ReadString('\n')
	if err != nil {
		return
	}
	reply, err := s.pairRequest(user, ip, strings.Split(strings.TrimRight(line, "\r\n"), "\t"))
	if err != nil {
		fmt.Fprintf(ch, "err\t%s\n", err)
	} else {
		io.WriteString(ch, "ok\n"+reply)
	}
	ch.CloseWrite()
}

func (s *Server) pairRequest(user, ip string, f []string) (string, error) {
	cfg := s.config()
	u := cfg.FindUser(user)
	if u == nil || !u.AppLinks {
		return "", errors.New("app links aren't turned on for your account (hub: Users tab)")
	}
	switch {
	case f[0] == "list" && len(f) == 1:
		var b strings.Builder
		for _, d := range u.Devices {
			fmt.Fprintf(&b, "d\t%s\t%s\t%d\n", d.Name, d.Service, d.Added)
		}
		return b.String(), nil

	case f[0] == "unpair" && len(f) == 2:
		removed := false
		err := s.updateConfig(func(c *config.Server) error {
			if cu := c.FindUser(user); cu != nil {
				removed = cu.RemoveDevice(f[1])
			}
			return nil
		})
		if err == nil && removed {
			s.log.Printf("UNPAIR %s user=%s device=%q", ip, user, f[1])
		}
		return "", err

	case f[0] == "pair" && len(f) == 4:
		name, service := strings.TrimSpace(f[1]), strings.ToLower(f[2])
		if err := config.ValidateDeviceName(name); err != nil {
			return "", err
		}
		granted := false
		for _, w := range cfg.GrantedServices(u) {
			granted = granted || strings.EqualFold(w.Name, service)
		}
		if !granted {
			return "", fmt.Errorf("you don't have the web page %q", service)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f[3]))
		if err != nil {
			return "", errors.New("that isn't a valid public key")
		}
		switch pk.Type() {
		case ssh.KeyAlgoECDSA256, ssh.KeyAlgoED25519:
		default:
			return "", errors.New("unsupported key type (use ECDSA P-256 or Ed25519)")
		}
		dev := config.Device{Name: name, Key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), Service: service, Added: time.Now().Unix()}
		err = s.updateConfig(func(c *config.Server) error {
			cu := c.FindUser(user)
			if cu == nil {
				return errors.New("no such user")
			}
			cu.RemoveDevice(name) // pairing again under the same name replaces it
			for _, u := range c.Users {
				for _, d := range u.Devices {
					if d.Key == dev.Key {
						return errors.New("that key is already paired")
					}
				}
			}
			if len(cu.Devices) >= config.MaxDevices {
				return fmt.Errorf("at most %d paired devices per user; remove one first", config.MaxDevices)
			}
			cu.Devices = append(cu.Devices, dev)
			return nil
		})
		if err == nil {
			s.log.Printf("PAIR %s user=%s device=%q web page=%s key %s", ip, user, name, service, ssh.FingerprintSHA256(pk))
		}
		return "", err
	}
	return "", errors.New("unknown request")
}
