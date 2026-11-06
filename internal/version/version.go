// Package version is the single source of the SecuRDP version (used by the
// app, the service log and tools/mkres for the exe's version info).
package version

import (
	"strconv"
	"strings"
)

const Version = "1.9.1"

// Compare returns -1, 0 or 1 comparing dotted versions a and b ("1.4.0").
func Compare(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
