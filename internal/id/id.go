// Package id generates opaque TEXT keys for Partout entities (PRD §8:
// ag_..., exec_..., run_..., grp_...).
package id

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns prefix + "-" + 12 random hex chars (e.g. "exec_a1b2c3d4e5f6").
func New(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback; rand.Read should not fail.
		b = [6]byte{0, 1, 2, 3, 4, 5}
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
