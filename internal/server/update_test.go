package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"securdp/internal/version"
)

func TestUpdateServesTheHubsOwnExe(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "securdp.exe")
	body := bytes.Repeat([]byte("MZ fake exe "), 50_000)
	os.WriteFile(fake, body, 0o644)
	exePath = func() (string, error) { return fake, nil }
	t.Cleanup(func() { exePath = os.Executable })

	fx := startFilesHub(t)
	info, err := fx.tun.Info()
	if err != nil || info.Version != version.Version {
		t.Fatalf("hub version %q, %v", info.Version, err)
	}
	var got bytes.Buffer
	v, err := fx.tun.DownloadUpdate(&got)
	if err != nil || v != version.Version || !bytes.Equal(got.Bytes(), body) {
		t.Fatalf("download: %q %v (%d bytes)", v, err, got.Len())
	}
	// A change on disk is picked up (the checksum isn't stale).
	os.WriteFile(fake, append(body, '!'), 0o644)
	got.Reset()
	if _, err := fx.tun.DownloadUpdate(&got); err != nil || got.Len() != len(body)+1 {
		t.Fatalf("after change: %v (%d bytes)", err, got.Len())
	}
}

func TestAppLinkCantDownloadUpdates(t *testing.T) {
	h := startLinkHub(t, false)
	full := h.loginCode(t, 0)
	signer, pub := newDeviceKey(t)
	if r, _ := request(full, pairHost, "pair\tphone\trouter\t"+pub); r != "ok\n" {
		t.Fatalf("pair: %q", r)
	}
	link, err := h.loginKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()
	if c, err := link.Dial("tcp", updateHost+":0"); err == nil {
		c.Close()
		t.Fatal("app link opened the update channel")
	}
	if r, _ := request(full, hubHost, ""); !strings.HasPrefix(r, "V\t"+version.Version+"\n") {
		t.Fatalf("hub info: %q", r)
	}
}
