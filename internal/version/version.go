// Package version provides the small version comparison partout needs
// (fleet update drift, "newer release" decisions). It is intentionally not
// a full semver implementation: dot-separated numeric segments, a leading
// "v" and non-numeric tails are tolerated.
package version

import "strings"

// Compare returns -1, 0, or 1 when a is older than, equal to, or newer
// than b. Numeric segments compare numerically (0.10 > 0.9); a shorter
// version is older when all shared segments are equal (0.9 < 0.9.1); an
// unknown/empty version sorts oldest.
func Compare(a, b string) int {
	as, bs := normalize(a), normalize(b)
	if len(as) == len(bs) {
		for i := range as {
			if as[i] != bs[i] {
				if as[i] < bs[i] {
					return -1
				}
				return 1
			}
		}
		return 0
	}
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	// All shared segments equal: the longer version is newer.
	if len(as) > len(bs) {
		return 1
	}
	return -1
}

func normalize(v string) []int {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	var out []int
	for _, part := range strings.Split(v, ".") {
		var n, digits int
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
			digits++
		}
		if digits == 0 {
			return out // trailing tag (e.g. "0.9.0-beta"): compare as prefix
		}
		out = append(out, n)
	}
	return out
}

// IsNewer reports whether release version a is newer than the host's
// current version b.
func IsNewer(a, b string) bool { return Compare(a, b) > 0 }
