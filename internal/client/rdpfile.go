package client

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"securdp/internal/config"
)

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._ -]`)

// writeRDPFile writes a per-profile .rdp file pointing at the tunnel. Windows
// keeps the saved login (Credential Manager "TERMSRV/<address>") per address,
// and every profile has its own loopback address, so ticking "Remember me"
// in Remote Desktop works separately for each remote PC.
func (t *Tunnel) writeRDPFile() (string, error) {
	p := t.profile
	screen := "1"
	if p.RDPFullscreen {
		screen = "2"
	}
	lines := []string{
		"full address:s:" + t.LocalAddr,
		"screen mode id:i:" + screen,
		"prompt for credentials:i:0",
		"promptcredentialonce:i:1",
		"authentication level:i:2",
		"enablecredsspsupport:i:1",
		"autoreconnection enabled:i:1",
	}
	if p.RDPUsername != "" {
		lines = append(lines, "username:s:"+p.RDPUsername)
	}
	dir := config.ClientDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, unsafeName.ReplaceAllString(p.Name, "_")+".rdp")
	// mstsc reads .rdp files as UTF-16 LE with BOM most reliably.
	return path, os.WriteFile(path, utf16le(strings.Join(lines, "\r\n")+"\r\n"), 0o600)
}

func utf16le(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, r := range s {
		if r > 0xFFFF {
			r = '?'
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
