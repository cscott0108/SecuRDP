// Package ddns keeps a DuckDNS name pointed at this network's public IP.
package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"securdp/internal/config"
	"securdp/internal/logx"
	"securdp/internal/netinfo"
)

const (
	checkEvery   = 5 * time.Minute
	refreshEvery = 24 * time.Hour // re-send even if unchanged, so the name never goes stale
)

// DuckDNSURL is the update endpoint (overridable in tests).
var DuckDNSURL = "https://www.duckdns.org/update"

// lookupIP finds the public IP (overridable in tests).
var lookupIP = netinfo.PublicIP

var subdomain = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// NormalizeDomain accepts "myhome" or "myhome.duckdns.org" and returns "myhome".
func NormalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	d = strings.TrimSuffix(strings.TrimSuffix(d, "/"), ".duckdns.org")
	if !subdomain.MatchString(d) {
		return "", errors.New("enter your DuckDNS name, e.g. myhome or myhome.duckdns.org")
	}
	return d, nil
}

// Hostname is the full name clients connect to.
func Hostname(domain string) string {
	if domain == "" {
		return ""
	}
	return domain + ".duckdns.org"
}

// Update sets domain to ip at DuckDNS. token is the plain (decrypted) token.
func Update(domain, token, ip string) error {
	q := url.Values{"domains": {domain}, "token": {token}, "ip": {ip}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, DuckDNSURL+"?"+q.Encode(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Don't echo the URL: it contains the token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("DuckDNS unreachable: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	switch strings.TrimSpace(string(b)) {
	case "OK":
		return nil
	case "KO":
		return errors.New("DuckDNS rejected the update - check the name and token")
	}
	return fmt.Errorf("unexpected DuckDNS reply (HTTP %d)", resp.StatusCode)
}

func LoadStatus() config.DDNSStatus {
	var st config.DDNSStatus
	if b, err := os.ReadFile(config.DDNSStatusPath()); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func saveStatus(st config.DDNSStatus) {
	if b, err := json.Marshal(st); err == nil {
		os.WriteFile(config.DDNSStatusPath(), b, 0o600)
	}
}

// Sync updates DuckDNS if the public IP changed (or force / daily refresh).
// It returns the resulting status; log may be nil.
func Sync(cfg *config.Server, force bool, log *logx.Logger) config.DDNSStatus {
	st := LoadStatus()
	if !cfg.DDNS.Enabled || cfg.DDNS.Domain == "" || cfg.DDNS.Token == "" {
		return st
	}
	now := time.Now()
	st.Checked = now.Unix()
	ip, err := lookupIP()
	if err != nil {
		st.Result = "couldn't find public IP: " + err.Error()
		saveStatus(st)
		return st
	}
	if !force && ip == st.IP && now.Sub(time.Unix(st.Updated, 0)) < refreshEvery {
		st.Result = "up to date"
		saveStatus(st)
		return st
	}
	token, err := config.UnprotectSecret(cfg.DDNS.Token)
	if err != nil {
		st.Result = "can't read the saved token - enter it again"
		saveStatus(st)
		return st
	}
	if err := Update(cfg.DDNS.Domain, token, ip); err != nil {
		st.Result = err.Error()
		if log != nil {
			log.Printf("DDNS %s: %v", Hostname(cfg.DDNS.Domain), err)
		}
		saveStatus(st)
		return st
	}
	if log != nil && ip != st.IP {
		log.Printf("DDNS %s -> %s", Hostname(cfg.DDNS.Domain), ip)
	}
	st.IP, st.Updated, st.Result = ip, now.Unix(), "updated"
	saveStatus(st)
	return st
}

// Run keeps DuckDNS current until ctx is cancelled (called by the service).
func Run(ctx context.Context, log *logx.Logger) {
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	for {
		if cfg, err := config.LoadServer(); err == nil {
			Sync(cfg, false, log)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
