package gui

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"securdp/internal/config"
)

// Trusted home login (the Local button): while logged in with password +
// code, this PC creates a key (kept DPAPI-protected for this Windows user) and
// the hub trusts it for login without password or code, from the home
// network only.

func (a *app) homeRoutes(mux *http.ServeMux) {
	a.api(mux, "/api/hub/trust", false, a.trustHome)
	a.api(mux, "/api/hub/untrust", false, a.untrustHome)
}

func (a *app) trustHome(r *http.Request) (any, error) {
	in, err := decode[struct {
		Name     string `json:"name"`
		Device   string `json:"device"`
		HomeHost string `json:"home_host"`
	}](r)
	if err != nil {
		return nil, err
	}
	s, err := a.session(in.Name)
	if err != nil {
		return nil, err
	}
	device := strings.TrimSpace(in.Device)
	if device == "" {
		device, _ = os.Hostname()
	}
	if err := config.ValidateDeviceName(device); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	blk, err := ssh.MarshalPrivateKey(priv, "SecuRDP home login")
	if err != nil {
		return nil, err
	}
	enc, err := config.ProtectUserSecret(string(pem.EncodeToMemory(blk)))
	if err != nil {
		return nil, err
	}
	if err := s.t.Trust(device, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))); err != nil {
		return nil, err
	}
	cc, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	p := cc.Find(in.Name)
	if p == nil {
		return nil, errors.New("profile not found")
	}
	p.HomeKey, p.HomeDevice, p.HomeHost = enc, device, strings.TrimSpace(in.HomeHost)
	return map[string]string{"device": device}, config.SaveClient(cc)
}

// untrustHome forgets this PC's home login, and removes it on the hub too
// when logged in there.
func (a *app) untrustHome(r *http.Request) (any, error) {
	in, err := decode[struct{ Name string }](r)
	if err != nil {
		return nil, err
	}
	cc, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	p := cc.Find(in.Name)
	if p == nil {
		return nil, errors.New("profile not found")
	}
	removedOnHub := false
	if s, err := a.session(in.Name); err == nil && p.HomeDevice != "" {
		removedOnHub = s.t.Untrust(p.HomeDevice) == nil
	}
	p.HomeKey, p.HomeDevice, p.HomeHost = "", "", ""
	return map[string]bool{"removed_on_hub": removedOnHub}, config.SaveClient(cc)
}

// homeSigner unlocks a profile's home key.
func homeSigner(p *config.Profile) (ssh.Signer, error) {
	if p.HomeKey == "" {
		return nil, errors.New("this PC isn't trusted for home login on " + p.Name + " yet")
	}
	pemText, err := config.UnprotectSecret(p.HomeKey)
	if err != nil {
		return nil, errors.New("couldn't unlock this PC's home key (was it copied from another Windows account?) - trust this PC again")
	}
	return ssh.ParsePrivateKey([]byte(pemText))
}
