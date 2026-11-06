package gui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"securdp/internal/client"
	"securdp/internal/service"
	"securdp/internal/version"
)

// Updating from the hub: a 1.8+ hub reports its version when you log in. If
// it is newer than this app, the UI offers to download the hub's own
// securdp.exe through the tunnel (size + SHA-256 checked, then test-run),
// swap it in for this exe and restart.

// noteHubVersion remembers a newer version offered by the hub behind profile name.
func (a *app) noteHubVersion(name string, info *client.HubInfo) {
	if info == nil || info.Version == "" || version.Compare(info.Version, version.Version) <= 0 {
		return
	}
	a.mu.Lock()
	a.updates[name] = info.Version
	a.mu.Unlock()
}

// updateOffer is the newest update any hub offered, for the UI (nil if none).
// Called with a.mu held.
func (a *app) updateOffer() map[string]any {
	var best map[string]any
	for name, v := range a.updates {
		if best == nil || version.Compare(v, best["version"].(string)) > 0 {
			_, connected := a.tunnels[name]
			best = map[string]any{"hub": name, "version": v, "connected": connected,
				"installed_copy": service.RunningInstalledCopy()}
		}
	}
	return best
}

func (a *app) applyUpdate(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	t := a.tunnels[in.Name]
	a.mu.Unlock()
	if t == nil {
		return nil, fmt.Errorf("connect to %s first, then update", in.Name)
	}
	select {
	case <-t.Done():
		return nil, fmt.Errorf("the connection to %s closed - connect again, then update", in.Name)
	default:
	}

	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Replace this exe in place, unless it is the installed (service) copy:
	// that one is updated with Install / update from the new exe instead.
	inPlace := !service.RunningInstalledCopy()
	staging := filepath.Join(filepath.Dir(exe), "securdp-update.exe")
	f, err := os.Create(staging)
	if !inPlace || err != nil {
		inPlace = false
		dl, derr := windows.KnownFolderPath(windows.FOLDERID_Downloads, 0)
		if derr != nil {
			return nil, derr
		}
		staging = filepath.Join(dl, "securdp-new.exe")
		if f, err = os.Create(staging); err != nil {
			return nil, err
		}
	}
	got, err := t.DownloadUpdate(f)
	f.Close()
	if err == nil {
		err = checkRuns(staging, got)
	}
	if err != nil {
		os.Remove(staging)
		return nil, err
	}

	target := staging
	if inPlace {
		// Windows lets a running exe be renamed (not overwritten): move this
		// one aside, put the new one in its place, and clean up on next start.
		old := exe + ".old"
		os.Remove(old)
		if err := os.Rename(exe, old); err == nil {
			if err := os.Rename(staging, exe); err == nil {
				target = exe
			} else {
				os.Rename(old, exe)
			}
		}
	}
	if target != exe {
		// Couldn't swap: keep the new exe under a clear name instead.
		named := filepath.Join(filepath.Dir(target), "securdp-"+got+".exe")
		os.Remove(named)
		if os.Rename(target, named) == nil {
			target = named
		}
	}

	cmd := exec.Command(target, "gui", "--wait-pid", strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("updated, but couldn't start it: %w (start %s yourself)", err, target)
	}
	go func() { time.Sleep(300 * time.Millisecond); close(a.quit) }()
	return map[string]any{"version": got, "path": target, "replaced": target == exe}, nil
}

// checkRuns test-runs a downloaded exe: it must start and report want.
func checkRuns(path, want string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("the downloaded update didn't run: %w", err)
	}
	if v := strings.TrimSpace(string(out)); v != want {
		return fmt.Errorf("the downloaded update reports version %q, expected %q", v, want)
	}
	return nil
}

// AfterUpdate runs at start-up: with "--wait-pid N" (a restart after an
// update) it waits for the old process to exit, and it removes the old exe
// left behind by an in-place update.
func AfterUpdate(args []string) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--wait-pid" {
			if pid, err := strconv.Atoi(args[i+1]); err == nil {
				if h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)); err == nil {
					windows.WaitForSingleObject(h, 15_000)
					windows.CloseHandle(h)
				}
			}
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	old := exe + ".old"
	if _, err := os.Stat(old); errors.Is(err, os.ErrNotExist) {
		return
	}
	go func() {
		for i := 0; i < 20; i++ { // the old process may take a moment to let go
			if os.Remove(old) == nil || errors.Is(os.Remove(old), os.ErrNotExist) {
				return
			}
			time.Sleep(time.Second)
		}
	}()
}
