package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EnsureServerDir creates %ProgramData%\SecuRDP and restricts it to
// SYSTEM and Administrators only (inheritance removed, so normal users
// cannot read the password hashes or TOTP secrets).
func EnsureServerDir() error {
	dir := ServerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Lock the folder only; files inherit from it. (Applying the (OI)(CI)
	// grants to files with /T strips them to an empty, unreadable ACL.)
	// Well-known SIDs keep this working on non-English Windows.
	if err := icacls(dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", // SYSTEM
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F"); err != nil { // Administrators
		return err
	}
	// Make existing files take the folder's permissions (also repairs files
	// damaged by the old /T behaviour).
	if entries, _ := os.ReadDir(dir); len(entries) > 0 {
		return icacls(dir+`\*`, "/reset")
	}
	return nil
}

func icacls(args ...string) error {
	cmd := exec.Command("icacls", append(args, "/Q")...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %v: %s", err, out)
	}
	return nil
}

// ProtectSecret encrypts with DPAPI bound to this machine, so a copied
// server.json is useless on another computer.
func ProtectSecret(plain string) (string, error) {
	in := windows.DataBlob{Size: uint32(len(plain)), Data: unsafe.SliceData([]byte(plain))}
	var out windows.DataBlob
	err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return base64.StdEncoding.EncodeToString(unsafe.Slice(out.Data, out.Size)), nil
}

func UnprotectSecret(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", nil
	}
	in := windows.DataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return string(unsafe.Slice(out.Data, out.Size)), nil
}
