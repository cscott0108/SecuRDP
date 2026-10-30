// Package winutil wraps the Windows-specific bits: elevation, firewall,
// RDP settings and the console.
package winutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	fwRuleAllow = "SecuRDP Gatekeeper (inbound)"
	fwRuleBlock = "SecuRDP - block direct RDP from internet"
	rdpKey      = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	rdpTcpKey   = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
)

func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RelaunchElevated restarts this exe with the given args via UAC.
func RelaunchElevated(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	a, _ := windows.UTF16PtrFromString(strings.Join(args, " "))
	return windows.ShellExecute(0, verb, file, a, nil, windows.SW_SHOWNORMAL)
}

// HideOwnConsole frees the console if this process created it (double-clicked
// from Explorer), so the GUI does not leave a black window behind. When run
// from an existing terminal the console is shared and left alone.
func HideOwnConsole() {
	k := windows.NewLazySystemDLL("kernel32.dll")
	getList := k.NewProc("GetConsoleProcessList")
	var pids [4]uint32
	n, _, _ := getList.Call(uintptr(unsafePtr(&pids[0])), 4)
	if n == 1 {
		k.NewProc("FreeConsole").Call()
	}
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// RDPInfo describes the local Remote Desktop configuration.
type RDPInfo struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
	NLA     bool `json:"nla"`
}

func GetRDPInfo() RDPInfo {
	info := RDPInfo{Port: 3389}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, rdpKey, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("fDenyTSConnections"); err == nil {
			info.Enabled = v == 0
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, rdpTcpKey, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("PortNumber"); err == nil && v > 0 {
			info.Port = int(v)
		}
		if v, _, err := k.GetIntegerValue("UserAuthentication"); err == nil {
			info.NLA = v == 1
		}
		k.Close()
	}
	return info
}

// EnableRDP turns on Remote Desktop with Network Level Authentication.
// NLA needs the TLS security layer (SecurityLayer=2); the legacy RDP layer
// (0) can't do NLA, so that is switched too.
func EnableRDP() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, rdpKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	if err := k.SetDWordValue("fDenyTSConnections", 0); err != nil {
		k.Close()
		return err
	}
	k.Close()
	k, err = registry.OpenKey(registry.LOCAL_MACHINE, rdpTcpKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("SecurityLayer", 2); err != nil {
		return fmt.Errorf("setting TLS security layer: %w", err)
	}
	if err := k.SetDWordValue("UserAuthentication", 1); err != nil {
		return fmt.Errorf("enabling NLA: %w", err)
	}
	if info := GetRDPInfo(); !info.NLA {
		return errors.New("NLA setting did not stick - a Group Policy may be overriding it (gpedit: Remote Desktop Session Host > Security)")
	}
	return nil
}

// internetRanges is every address except private/home-network ones, so the
// RDP block rule only stops internet traffic. A Windows block rule can't have
// exceptions, so the allowed ranges are carved out instead. Left reachable:
// 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT / Tailscale), 169.254/16,
// 127/8, IPv6 ULA fc00::/7 and link-local fe80::/10.
const internetRanges = "0.0.0.0-9.255.255.255,11.0.0.0-100.63.255.255,100.128.0.0-126.255.255.255," +
	"128.0.0.0-169.253.255.255,169.255.0.0-172.15.255.255,172.32.0.0-192.167.255.255,192.169.0.0-255.255.255.255," +
	"::-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,fe00::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff,fec0::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

// ApplyFirewall opens the gatekeeper port and optionally blocks the real RDP
// port from the network. Tunnelled RDP arrives on loopback, which the Windows
// firewall does not filter, so blocking 3389 does not affect SecuRDP.
func ApplyFirewall(exePath string, port int, blockRDP bool, rdpPort int) error {
	RemoveFirewall()
	if _, err := run("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+fwRuleAllow, "dir=in", "action=allow", "protocol=TCP",
		fmt.Sprintf("localport=%d", port), "program="+exePath, "profile=any"); err != nil {
		return fmt.Errorf("adding firewall allow rule: %w", err)
	}
	if blockRDP {
		if _, err := run("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+fwRuleBlock, "dir=in", "action=block", "protocol=TCP",
			fmt.Sprintf("localport=%d", rdpPort), "remoteip="+internetRanges, "profile=any"); err != nil {
			return fmt.Errorf("adding RDP block rule: %w", err)
		}
	}
	return nil
}

func RemoveFirewall() {
	run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwRuleAllow)
	run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwRuleBlock)
	// Rules created by earlier versions (before the SecuRDP rename).
	for _, n := range []string{"SecureRDP Gatekeeper (inbound)", "SecureRDP - block direct RDP from internet",
		"SecureRDP - block direct RDP from network"} {
		run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n)
	}
}
