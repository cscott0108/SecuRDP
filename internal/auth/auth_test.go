package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vectors(t *testing.T) {
	// RFC 6238 appendix B, SHA1 key "12345678901234567890", truncated to 6 digits.
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		if got := CurrentTOTP(secret, time.Unix(ts, 0)); got != want {
			t.Errorf("t=%d: got %s want %s", ts, got, want)
		}
		if _, ok := VerifyTOTP(secret, want, time.Unix(ts, 0)); !ok {
			t.Errorf("t=%d: verify failed", ts)
		}
	}
}

func TestTOTPDriftAndReject(t *testing.T) {
	s, _ := NewTOTPSecret()
	now := time.Now()
	if _, ok := VerifyTOTP(s, CurrentTOTP(s, now.Add(-30*time.Second)), now); !ok {
		t.Error("previous step should be accepted")
	}
	if _, ok := VerifyTOTP(s, CurrentTOTP(s, now.Add(-120*time.Second)), now); ok {
		t.Error("old code should be rejected")
	}
	if _, ok := VerifyTOTP(s, "12345", now); ok {
		t.Error("short code accepted")
	}
}

func TestTOTPURI(t *testing.T) {
	u := TOTPURI("ABC", "SecuRDP", "me@pc")
	if !strings.HasPrefix(u, "otpauth://totp/SecuRDP:me@pc?") || !strings.Contains(u, "secret=ABC") {
		t.Fatal(u)
	}
}

func TestPassword(t *testing.T) {
	h, err := HashPassword("Correct horse battery 9")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("Correct horse battery 9", h) || VerifyPassword("Correct horse battery 8", h) {
		t.Fatal("verify mismatch")
	}
	if ValidatePassword("short", "") == nil || ValidatePassword("alllowercaseletters", "") == nil {
		t.Error("weak password accepted")
	}
	if ValidatePassword("Correct horse battery 9", "") != nil {
		t.Error("strong password rejected")
	}
	if ValidateUsername("admin") == nil || ValidateUsername("Administrator") == nil || ValidateUsername("ab") == nil {
		t.Error("bad username accepted")
	}
	if ValidateUsername("blue.falcon77") != nil {
		t.Error("good username rejected")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Minute, time.Minute, 2)
	for i := 0; i < 2; i++ {
		if l.Fail("1.2.3.4") {
			t.Fatal("banned too early")
		}
	}
	if !l.Fail("1.2.3.4") {
		t.Fatal("expected ban")
	}
	if b, _ := l.Banned("1.2.3.4"); !b {
		t.Fatal("should be banned")
	}
	if b, _ := l.Banned("5.6.7.8"); b {
		t.Fatal("other IP banned")
	}
	if !l.Acquire("9.9.9.9") || !l.Acquire("9.9.9.9") || l.Acquire("9.9.9.9") {
		t.Fatal("pending cap not enforced")
	}
}
