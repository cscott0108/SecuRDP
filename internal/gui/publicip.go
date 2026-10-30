package gui

import (
	"sync"
	"time"

	"securdp/internal/netinfo"
)

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
	ip, err := netinfo.PublicIP()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetching = false
	p.checked = time.Now()
	if err != nil {
		p.err = err.Error()
		return
	}
	p.ip, p.err = ip, ""
}
