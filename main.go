// SecuRDP: one executable that is both the gatekeeper service (on the PC
// you RDP into) and the client (on the PC you connect from).
package main

import (
	"fmt"
	"os"
	"strconv"

	"securdp/internal/client"
	"securdp/internal/config"
	"securdp/internal/gui"
	"securdp/internal/service"
	"securdp/internal/tray"
	ver "securdp/internal/version"
	"securdp/internal/winutil"
)

const version = ver.Version

const usage = `SecuRDP ` + version + `

  securdp                      open the SecuRDP window (setup + connect)
  securdp gui --browser        open the UI in your web browser instead
  securdp tray                 show the notification-area icon (server PCs)
  securdp connect <profile>    connect a saved profile from the terminal
  securdp connect <host> <port> <username>
  securdp install              install/update the gatekeeper service (admin)
  securdp uninstall            remove the service and firewall rules (admin)
  securdp serve                run the gatekeeper in this console (testing)
  securdp status               show service status
`

func main() {
	if service.IsServiceProcess() {
		if err := service.RunService(); err != nil {
			os.Exit(1)
		}
		return
	}
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"gui"}
	}
	cmd := args[0]
	var err error
	switch cmd {
	case "gui":
		opt := gui.Options{}
		for _, a := range args[1:] {
			opt.Browser = opt.Browser || a == "--browser"
			opt.NoOpen = opt.NoOpen || a == "--no-open"
		}
		if !opt.Browser && !opt.NoOpen {
			winutil.HideOwnConsole()
			// One window per user: focus the open one instead. (Skipped when
			// elevated, so "Restart as administrator" isn't swallowed by the
			// window it is replacing.)
			if !winutil.IsElevated() && tray.FocusExistingWindow() {
				return
			}
		}
		if !winutil.IsElevated() {
			tray.StartIfNeeded()
		}
		err = gui.Run(opt)
	case "tray":
		winutil.HideOwnConsole()
		err = tray.Run()
	case "connect":
		config.MigrateClientDir()
		err = connect(args[1:])
	case "install":
		if err = service.MigrateLegacy(); err != nil {
			break
		}
		if err = service.Install(); err == nil {
			fmt.Println("SecuRDP service installed and started.")
		}
	case "uninstall":
		if err = service.Uninstall(); err == nil {
			fmt.Println("SecuRDP service removed.")
		}
	case "serve":
		err = service.RunForeground()
	case "status":
		fmt.Println("Service:", service.Status())
		r := winutil.GetRDPInfo()
		fmt.Printf("Remote Desktop enabled: %v  port: %d  NLA: %v\n", r.Enabled, r.Port, r.NLA)
	case "version":
		fmt.Println(version)
	default:
		fmt.Print(usage)
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func connect(args []string) error {
	cc, err := config.LoadClient()
	if err != nil {
		return err
	}
	var p config.Profile
	switch len(args) {
	case 1:
		found := cc.Find(args[0])
		if found == nil {
			return fmt.Errorf("no saved profile named %q", args[0])
		}
		p = *found
	case 3:
		port, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("bad port %q", args[1])
		}
		name := fmt.Sprintf("%s:%d", args[0], port)
		if found := cc.Find(name); found != nil {
			p = *found
		} else {
			p = config.Profile{Name: name, Host: args[0], Port: port, Username: args[2]}
		}
	default:
		fmt.Print(usage)
		return nil
	}
	save := func(np config.Profile) {
		if ex := cc.Find(np.Name); ex != nil {
			*ex = np
		} else {
			cc.AssignLocalIP(&np)
			cc.Profiles = append(cc.Profiles, np)
		}
		config.SaveClient(cc)
	}
	if p.LocalIP == "" {
		cc.AssignLocalIP(&p)
	}
	return client.ConnectCLI(p, save)
}
