package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"

	"securdp/internal/apk"
	"securdp/internal/version"
)

// updateHost serves the hub's own securdp.exe to logged-in users, so the
// Windows app can update itself from the hub it trusts (the pinned host key
// and a password + code login stand behind every byte). Reply:
//
//	ok \t size \t sha256-hex \t version \n   then exactly size bytes
//	err \t message \n
const updateHost = "update.securdp"

// apkHost serves the Android app bundled into this exe (see package apk),
// same reply format, the version being the Android versionName.
const apkHost = "apk.securdp"

// bundledAPK is the app served; tests replace it.
var bundledAPK = apk.Get

func (s *Server) serveAPK(nc ssh.NewChannel, user, ip string) {
	a := bundledAPK()
	if a == nil {
		nc.Reject(ssh.ConnectionFailed, "this hub has no Android app to offer")
		return
	}
	ch, ok := accept(nc)
	if !ok {
		return
	}
	defer ch.Close()
	fmt.Fprintf(ch, "ok\t%d\t%s\t%s\n", len(a.Data), a.SHA256, a.VersionName)
	if _, err := ch.Write(a.Data); err != nil {
		s.log.Printf("UPDATE %s user=%s: Android app download stopped: %v", ip, user, err)
		return
	}
	ch.CloseWrite()
	s.log.Printf("UPDATE %s user=%s downloaded SecuRDP for Android %s", ip, user, a.VersionName)
}

// exePath is the file served; tests point it elsewhere.
var exePath = os.Executable

var exeHash struct {
	sync.Mutex
	path, sum string
	size      int64
	mod       int64
}

// selfHash returns the size and SHA-256 of the running exe, cached until it changes.
func selfHash(path string) (int64, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, "", err
	}
	exeHash.Lock()
	defer exeHash.Unlock()
	if exeHash.path == path && exeHash.mod == st.ModTime().UnixNano() && exeHash.size == st.Size() {
		return exeHash.size, exeHash.sum, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	exeHash.path, exeHash.size, exeHash.mod, exeHash.sum = path, n, st.ModTime().UnixNano(), hex.EncodeToString(h.Sum(nil))
	return n, exeHash.sum, nil
}

func (s *Server) serveUpdate(nc ssh.NewChannel, user, ip string) {
	ch, ok := accept(nc)
	if !ok {
		return
	}
	defer ch.Close()
	path, err := exePath()
	var size int64
	var sum string
	if err == nil {
		size, sum, err = selfHash(path)
	}
	var f *os.File
	if err == nil {
		f, err = os.Open(path)
	}
	if err != nil {
		fmt.Fprintf(ch, "err\tthe hub couldn't read its program file\n")
		s.log.Printf("UPDATE %s user=%s: %v", ip, user, err)
		return
	}
	defer f.Close()
	fmt.Fprintf(ch, "ok\t%d\t%s\t%s\n", size, sum, version.Version)
	n, err := io.CopyN(ch, f, size)
	if err != nil {
		s.log.Printf("UPDATE %s user=%s: stopped after %d of %d bytes", ip, user, n, size)
		return
	}
	ch.CloseWrite()
	s.log.Printf("UPDATE %s user=%s downloaded SecuRDP %s", ip, user, version.Version)
}
