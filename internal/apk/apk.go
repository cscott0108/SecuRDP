// Package apk holds the Android app bundled into the exe at build time
// (see build.ps1), which a hub hands to phones as an update.
package apk

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
)

//go:embed bundle
var bundle embed.FS

// Bundled is the embedded app: its bytes, SHA-256 and Android version.
type Bundled struct {
	Data        []byte
	SHA256      string
	VersionCode int
	VersionName string
}

var (
	once   sync.Once
	cached *Bundled
)

// Get returns the bundled app, or nil if this exe was built without one.
func Get() *Bundled {
	once.Do(func() { cached = load(bundle) })
	return cached
}

func load(fsys embed.FS) *Bundled {
	data, err := fsys.ReadFile("bundle/SecuRDP.apk")
	if err != nil || len(data) == 0 {
		return nil
	}
	v, err := fsys.ReadFile("bundle/version.txt")
	if err != nil {
		return nil
	}
	f := strings.Fields(strings.TrimPrefix(string(v), "\uFEFF")) // "8 1.7.0"
	if len(f) != 2 {
		return nil
	}
	code, err := strconv.Atoi(f[0])
	if err != nil || code <= 0 {
		return nil
	}
	sum := sha256.Sum256(data)
	return &Bundled{Data: data, SHA256: hex.EncodeToString(sum[:]), VersionCode: code, VersionName: f[1]}
}
