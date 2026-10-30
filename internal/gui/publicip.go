package gui

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Public IPv4 lookup services, tried in order. Each returns just the address.
var ipServices = []string{
	"https://api.ipify.org",
	"https://checkip.amazonaws.com",
	"https://ipv4.icanhazip.com",
}

const ipRefresh = 5 * time.Minute

// publicIP caches this network's public address so the UI can show what to
// connect to from outside. Lookups happen in the background, never blocking
// the UI.
type publicIP struct {
	mu       sync.Mutex
	ip       string
	checked  time.Time
	err      string
	fetching bool
}

// get returns the cached address, starting a refresh if it is stale (or
// force is set).
func (p *publicIP) get(force bool) (ip string, checked time.Time, errMsg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.fetching && (force || time.Since(p.checked) > ipRefresh) {
		p.fetching = true
		go p.fetch()
	}
	return p.ip, p.checked, p.err
}

func (p *publicIP) fetch() {
	ip, err := lookupPublicIP()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetching = false
	p.checked = time.Now()
	if err != "" {
		p.err = err
		return
	}
	p.ip, p.err = ip, ""
}

func lookupPublicIP() (string, string) {
	client := &http.Client{Timeout: 6 * time.Second}
	last := "no lookup service reachable"
	for _, u := range ipServices {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			last = err.Error()
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		cancel()
		s := strings.TrimSpace(string(b))
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return ip.String(), ""
		}
		last = "unexpected reply from " + u
	}
	return "", last
}
