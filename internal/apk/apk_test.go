package apk

import (
	"os"
	"testing"
)

// A build that bundled the app (build.ps1) must be able to read it back.
func TestBundledAppLoads(t *testing.T) {
	if _, err := os.Stat("bundle/SecuRDP.apk"); err != nil {
		t.Skip("built without the Android app")
	}
	a := Get()
	if a == nil || a.VersionCode <= 0 || a.VersionName == "" || len(a.Data) < 1000 || len(a.SHA256) != 64 {
		t.Fatalf("bundled app didn't load: %+v", a != nil)
	}
	t.Logf("bundled Android app %s (code %d), %d bytes", a.VersionName, a.VersionCode, len(a.Data))
}
