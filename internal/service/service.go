// Package service installs and runs SecuRDP as a Windows service.
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"securdp/internal/config"
	"securdp/internal/logx"
	"securdp/internal/server"
	"securdp/internal/winutil"
)

const (
	Name        = "SecuRDP"
	displayName = "SecuRDP Gatekeeper"
	description = "SSH gate (password + authenticator code) that tunnels Remote Desktop to this PC."
)

// InstalledExe is where the service binary lives once installed.
func InstalledExe() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, config.AppName, "securdp.exe")
}

// MigrateLegacy upgrades an install made under the old "SecureRDP" name:
// removes the old service, firewall rules and program folder, moves the
// config folder, and installs the SecuRDP service if the old one existed.
// Requires admin; a no-op when there is nothing to migrate.
func MigrateLegacy() error {
	if !winutil.IsElevated() {
		return nil
	}
	hadService := false
	if m, err := mgr.Connect(); err == nil {
		if s, err := m.OpenService(config.LegacyAppName); err == nil {
			hadService = true
			stopAndWait(s)
			s.Delete()
			s.Close()
		}
		m.Disconnect()
	}
	moved := config.MigrateServerDir()
	if !hadService && !moved {
		return nil
	}
	winutil.RemoveFirewall()
	pf := filepath.Dir(filepath.Dir(InstalledExe()))
	os.RemoveAll(filepath.Join(pf, config.LegacyAppName))
	if hadService {
		return Install()
	}
	return nil
}

func IsServiceProcess() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// RunService is the entry point when started by the Service Control Manager.
func RunService() error { return svc.Run(Name, &handler{}) }

type handler struct{}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	config.EnsureServerDir()
	log, err := logx.Open(config.LogPath(), nil)
	if err != nil {
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- server.Run(ctx, log) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Printf("service started")
	for {
		select {
		case err := <-errc:
			log.Printf("server stopped: %v", err)
			cancel()
			return true, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				log.Printf("service stopping")
				return false, 0
			}
		}
	}
}

// RunForeground runs the gatekeeper in the console (for testing).
func RunForeground() error {
	if err := config.EnsureServerDir(); err != nil {
		return err
	}
	log, err := logx.Open(config.LogPath(), os.Stdout)
	if err != nil {
		return err
	}
	return server.Run(context.Background(), log)
}

func copyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	// Rename over a running exe fails, so move the old one aside first.
	os.Remove(dst + ".old")
	os.Rename(dst, dst+".old")
	return os.Rename(tmp, dst)
}

// Install copies this exe to Program Files, registers the service (auto
// start, restart on failure), applies firewall rules and starts it.
func Install() error {
	if !winutil.IsElevated() {
		return errors.New("administrator rights required")
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if len(cfg.Users) == 0 {
		return errors.New("add at least one user before installing")
	}
	if _, err := server.LoadOrCreateHostKey(); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		stopAndWait(s)
		s.Close()
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := InstalledExe()
	if err := copyFile(self, dst); err != nil {
		return fmt.Errorf("copying to %s: %w", dst, err)
	}

	s, err := m.OpenService(Name)
	if err != nil {
		s, err = m.CreateService(Name, dst, mgr.Config{
			DisplayName:      displayName,
			Description:      description,
			StartType:        mgr.StartAutomatic,
			DelayedAutoStart: true,
		}, "service")
		if err != nil {
			return fmt.Errorf("creating service: %w", err)
		}
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, 86400)

	if err := winutil.ApplyFirewall(dst, cfg.ListenPort, cfg.BlockDirectRDP, winutil.GetRDPInfo().Port); err != nil {
		return err
	}
	return s.Start()
}

func Uninstall() error {
	if !winutil.IsElevated() {
		return errors.New("administrator rights required")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err == nil {
		stopAndWait(s)
		if err := s.Delete(); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	winutil.RemoveFirewall()
	return nil
}

// Restart applies new settings (e.g. port change) by restarting the service
// and refreshing firewall rules.
func Restart() error {
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return errors.New("service is not installed")
	}
	defer s.Close()
	stopAndWait(s)
	if err := winutil.ApplyFirewall(InstalledExe(), cfg.ListenPort, cfg.BlockDirectRDP, winutil.GetRDPInfo().Port); err != nil {
		return err
	}
	return s.Start()
}

func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return errors.New("service is not installed")
	}
	defer s.Close()
	stopAndWait(s)
	return nil
}

func stopAndWait(s *mgr.Service) {
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	s.Control(svc.Stop)
	for i := 0; i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
	}
}

// Status returns "not installed", "running", "stopped", etc. It works
// without admin rights.
func Status() string {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseServiceHandle(h)
	n, _ := windows.UTF16PtrFromString(Name)
	sh, err := windows.OpenService(h, n, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "not installed"
	}
	defer windows.CloseServiceHandle(sh)
	var ss windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(sh, &ss); err != nil {
		return "unknown"
	}
	switch ss.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "starting"
	case windows.SERVICE_STOP_PENDING:
		return "stopping"
	}
	return "unknown"
}
