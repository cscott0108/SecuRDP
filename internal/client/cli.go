package client

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"securdp/internal/config"
)

// ConnectCLI connects a saved profile (or an ad-hoc one) from the terminal.
func ConnectCLI(p config.Profile, save func(config.Profile)) error {
	in := bufio.NewReader(os.Stdin)
	fmt.Printf("Connecting to %s:%d as %s\n", p.Host, p.Port, p.Username)
	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Print("Authenticator code: ")
	code, _ := in.ReadString('\n')
	code = strings.TrimSpace(code)

	t, err := Connect(p, string(pw), code)
	var uh *UnknownHostError
	if errors.As(err, &uh) {
		fmt.Printf("\nFirst connection to this server. Its fingerprint is:\n  %s\n", uh.Fingerprint)
		fmt.Println("Compare it with the fingerprint shown in SecuRDP on the server.")
		fmt.Print("Do they match? (yes/no): ")
		a, _ := in.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(a)) != "yes" {
			return errors.New("aborted")
		}
		p.HostFingerprint = uh.Fingerprint
		save(p)
		t, err = Connect(p, string(pw), code)
	}
	if err != nil {
		return err
	}
	computer := ""
	if list, _ := t.Computers(); len(list) > 1 {
		computer = p.Computer
		found := false
		for _, c := range list {
			found = found || c.Name == computer
		}
		if !found {
			fmt.Println("\nComputers on this hub:")
			for i, c := range list {
				state := "not answering"
				if c.Online {
					state = "online"
				}
				fmt.Printf("  %d) %-16s %s\n", i+1, c.Name, state)
			}
			fmt.Print("Connect to which number? ")
			a, _ := in.ReadString('\n')
			n, err := strconv.Atoi(strings.TrimSpace(a))
			if err != nil || n < 1 || n > len(list) {
				t.Close()
				return errors.New("no computer chosen")
			}
			computer = list[n-1].Name
		}
	}
	if err := t.Listen(computer, p.LocalIP); err != nil {
		t.Close()
		return err
	}
	fmt.Printf("Tunnel open on %s - starting Remote Desktop...\n", t.LocalAddr)
	if err := t.LaunchRDP(); err != nil {
		t.Close()
		return err
	}
	<-t.Done()
	fmt.Println("Remote Desktop closed - tunnel shut down.")
	return nil
}
