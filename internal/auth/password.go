// Package auth implements password hashing, TOTP and brute-force protection.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. 64 MiB / 3 passes is the OWASP-recommended baseline.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns an encoded Argon2id hash: $argon2id$v=19$m=..,t=..,p=..$salt$hash
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks password against an encoded Argon2id hash in constant time.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when a username does not exist, so a wrong
// username costs the same time as a wrong password (no username enumeration).
var dummyHash, _ = HashPassword("securdp-dummy-password-never-valid")

// BurnTime performs a throwaway hash verification.
func BurnTime(password string) { VerifyPassword(password, dummyHash) }

var commonUsernames = map[string]bool{
	"admin": true, "administrator": true, "root": true, "user": true, "guest": true, "test": true,
	"rdp": true, "remote": true, "support": true, "owner": true, "pi": true, "ubuntu": true, "default": true,
}

// ValidateUsername rejects short or commonly brute-forced usernames.
func ValidateUsername(u string) error {
	if len(u) < 5 || len(u) > 32 {
		return errors.New("username must be 5-32 characters")
	}
	for _, r := range u {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			return errors.New("username may contain only letters, digits, '.', '_' and '-'")
		}
	}
	if commonUsernames[strings.ToLower(u)] {
		return errors.New("that username is one of the first ones attackers try - pick something unique")
	}
	return nil
}

// ValidatePassword enforces a strong password: 14+ chars and 3 of 4 character classes.
func ValidatePassword(pw, username string) error {
	if len(pw) < 14 {
		return errors.New("password must be at least 14 characters")
	}
	var lower, upper, digit, other bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	if n < 3 {
		return errors.New("password needs at least 3 of: lowercase, uppercase, digits, symbols")
	}
	if username != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(username)) {
		return errors.New("password must not contain the username")
	}
	return nil
}
