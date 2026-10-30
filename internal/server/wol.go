package server

import (
	"net"
	"time"

	"securdp/internal/config"
)

// wakeOnLAN broadcasts a Wake-on-LAN magic packet (6 x 0xFF then the MAC 16
// times) to the global broadcast and every local IPv4 subnet's broadcast.
func wakeOnLAN(mac string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	pkt := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xFF)
	}
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	targets := []net.IP{net.IPv4bcast}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || !n.IP.IsPrivate() {
			continue
		}
		ip, mask := n.IP.To4(), n.Mask
		b := make(net.IP, 4)
		for i := range b {
			b[i] = ip[i] | ^mask[len(mask)-4+i]
		}
		targets = append(targets, b)
	}
	for _, ip := range targets {
		for _, port := range []int{9, 7} {
			if c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: port}); err == nil {
				c.Write(pkt)
				c.Close()
			}
		}
	}
	return nil
}

// WakeComputer sends a wake-up packet for a configured computer (UI button).
func WakeComputer(c config.Computer) error { return wakeOnLAN(c.MAC) }

// wakeIfAsleep wakes a computer right at login if its RDP port doesn't
// answer, so it is booting while the client sets up Remote Desktop.
func (s *Server) wakeIfAsleep(c *config.Computer) {
	addr := c.DialAddress()
	if conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond); err == nil {
		conn.Close()
		return
	}
	if wakeOnLAN(c.MAC) == nil {
		s.log.Printf("WAKE %s (%s): sent Wake-on-LAN", c.Name, c.MAC)
	}
}

// Probe reports whether a computer's Remote Desktop port answers (UI "Test").
func Probe(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}
