// Package netinfo finds this network's public IPv4 address.
package netinfo

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Services that return just the caller's public IPv4 address, tried in order.
var Services = []string{
	"https://api.ipify.org",
	"https://checkip.amazonaws.com",
	"https://ipv4.icanhazip.com",
}

// PublicIP returns the public IPv4 address, or an error message.
func PublicIP() (string, error) {
	client := &http.Client{Timeout: 6 * time.Second}
	var last error = errNoService
	for _, u := range Services {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		cancel()
		if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
		last = &badReply{u}
	}
	return "", last
}

type badReply struct{ url string }

func (e *badReply) Error() string { return "unexpected reply from " + e.url }

var errNoService = &badReply{"any lookup service"}
