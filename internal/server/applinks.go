package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"securdp/internal/config"
)

// Paired devices: a device paired from a full password + code session gets a
// key that logs in without prompts. Two kinds (see config.Device):
//   - app links reach one granted web service (e.g. a background app's API
//     on the hub), from anywhere. Everything else is refused.
//   - home devices log in as the user, but only from the home network: the
//     key AND a home-network source address are both required.

// pairHost is the pseudo destination for managing the login's paired
// devices. One request line per channel:
//
//	pair \t name \t service \t authorized-key   -> "ok"   (app link)
//	unpair \t name                             -> "ok"
//	trust \t name \t authorized-key             -> "ok"   (home device)
//	untrust \t name                            -> "ok"
//	list                                       -> "ok", then "d \t name \t service \t added"
//	                                              and "h \t name \t added" lines
//
// Errors are "err \t message".
const pairHost = "pair.securdp"

// maxLinkSessions caps concurrent app-link sessions (kept apart from
// MaxSessions so a background link never blocks a Remote Desktop login).
const maxLinkSessions = 4

var errDenied = errors.New("denied")

// keyLogin authenticates a paired device by its key.
func (s *Server) keyLogin(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	ip := ipOf(conn.RemoteAddr())
	if banned, _ := s.limiter.Banned(ip); banned {
		return nil, errDenied
	}
	cfg := s.config()
	login, wanted := config.SplitLogin(conn.User())
	u := cfg.FindUser(login)
	if u == nil || !u.Enabled {
		return nil, errDenied
	}
	want := key.Marshal()
	for _, d := range u.Devices {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.Key))
		if err != nil || !bytes.Equal(pk.Marshal(), want) {
			continue
		}
		if d.Home {
			return s.homeLogin(cfg, u, d, ip, wanted)
		}
		if !u.AppLinks {
			return nil, errDenied
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

// homeLogin lets a trusted home device in as its user (like a password +
// code login), but only from the home network.
func (s *Server) homeLogin(cfg *config.Server, u *config.User, d config.Device, ip, wanted string) (*ssh.Permissions, error) {
	if !u.HomeLogin {
		return nil, errDenied
	}
	if !s.fromHome(ip) {
		s.log.Printf("REJECT %s user=%s home device=%q: not on the home network (use password + code away from home)", ip, u.Username, d.Name)
		return nil, errDenied
	}
	target, err := cfg.ResolveTarget(u, wanted)
	if err != nil {
		s.log.Printf("REJECT %s user=%s: %v", ip, u.Username, err)
		return nil, errDenied
	}
	if target.MAC != "" {
		go s.wakeIfAsleep(target)
	}
	return &ssh.Permissions{Extensions: map[string]string{
		"user": u.Username, "computer": target.Name, "home": d.Name,
	}}, nil
}

// fromHome reports whether ip is on one of the hub's own private networks
// (its LAN subnets). Addresses forwarded in from the internet aren't, and a
// router that disguises them as local still can't get in without the key.
func (s *Server) fromHome(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	nets := s.homeNets
	if nets == nil {
		nets = localSubnets
	}
	for _, n := range nets() {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// localSubnets lists the private (RFC 1918 / ULA) networks this PC is on.
func localSubnets() []*net.IPNet {
	var out []*net.IPNet
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsPrivate() {
			out = append(out, &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask})
		}
	}
	return out
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
	if u == nil {
		return "", errors.New("no such user")
	}
	noLinks := errors.New("app links aren't turned on for your account (hub: Users tab)")
	noHome := errors.New("trusted home devices aren't turned on for your account (hub: Users tab)")
	switch {
	case f[0] == "list" && len(f) == 1:
		var b strings.Builder
		for _, d := range u.Devices {
			if d.Home {
				fmt.Fprintf(&b, "h\t%s\t%d\n", d.Name, d.Added)
			} else {
				fmt.Fprintf(&b, "d\t%s\t%s\t%d\n", d.Name, d.Service, d.Added)
			}
		}
		return b.String(), nil

	case (f[0] == "unpair" || f[0] == "untrust") && len(f) == 2:
		home := f[0] == "untrust"
		removed := false
		err := s.updateConfig(func(c *config.Server) error {
			if cu := c.FindUser(user); cu != nil {
				removed = cu.RemoveDevice(f[1], home)
			}
			return nil
		})
		if err == nil && removed {
			s.log.Printf("UNPAIR %s user=%s %s=%q", ip, user, kindName(home), f[1])
		}
		return "", err

	case f[0] == "pair" && len(f) == 4:
		if !u.AppLinks {
			return "", noLinks
		}
		service := strings.ToLower(f[2])
		granted := false
		for _, w := range cfg.GrantedServices(u) {
			granted = granted || strings.EqualFold(w.Name, service)
		}
		if !granted {
			return "", fmt.Errorf("you don't have the web page %q", service)
		}
		return "", s.addDevice(user, ip, config.Device{Name: strings.TrimSpace(f[1]), Service: service}, f[3])

	case f[0] == "trust" && len(f) == 3:
		if !u.HomeLogin {
			return "", noHome
		}
		return "", s.addDevice(user, ip, config.Device{Name: strings.TrimSpace(f[1]), Home: true}, f[2])
	}
	return "", errors.New("unknown request")
}

func kindName(home bool) string {
	if home {
		return "home device"
	}
	return "device"
}

// addDevice validates and saves a newly paired device (replacing one of the
// same name and kind).
func (s *Server) addDevice(user, ip string, dev config.Device, key string) error {
	if err := config.ValidateDeviceName(dev.Name); err != nil {
		return err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return errors.New("that isn't a valid public key")
	}
	switch pk.Type() {
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoED25519:
	default:
		return errors.New("unsupported key type (use ECDSA P-256 or Ed25519)")
	}
	dev.Key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	dev.Added = time.Now().Unix()
	err = s.updateConfig(func(c *config.Server) error {
		cu := c.FindUser(user)
		if cu == nil {
			return errors.New("no such user")
		}
		cu.RemoveDevice(dev.Name, dev.Home) // pairing again under the same name replaces it
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
		what := "web page=" + dev.Service
		if dev.Home {
			what = "home login (home network only)"
		}
		s.log.Printf("PAIR %s user=%s %s=%q %s key %s", ip, user, kindName(dev.Home), dev.Name, what, ssh.FingerprintSHA256(pk))
	}
	return err
}
