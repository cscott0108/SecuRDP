package client

import (
	"bufio"
	"errors"
	"fmt"
	"os"
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

	t, err := Dial(p, string(pw), code)
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
		t, err = Dial(p, string(pw), code)
	}
	if err != nil {
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
