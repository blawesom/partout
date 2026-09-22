// Package hsauth is the shared Ed25519 challenge-response helper used by the
// agent (sign) and the server (verify). The signature is over:
//
//	nonce || uuid || ts_be64
//
// where nonce is the server's random challenge (32 bytes), uuid is the agent
// uuid, and ts_be64 is the agent epoch-seconds as 8 big-endian bytes
// (architecture §3.1, PRD R3).
package hsauth

import (
	"encoding/binary"
	"fmt"
	"time"
)

// SkewTolerance is the maximum allowed clock skew in seconds (PRD R3: ±300s).
const SkewTolerance int64 = 300

// BuildMsg returns the exact byte sequence signed/verified by both sides.
func BuildMsg(nonce []byte, uuid string, ts int64) []byte {
	buf := make([]byte, 0, len(nonce)+len(uuid)+8)
	buf = append(buf, nonce...)
	buf = append(buf, uuid...)
	var tsB [8]byte
	binary.BigEndian.PutUint64(tsB[:], uint64(ts))
	buf = append(buf, tsB[:]...)
	return buf
}

// CheckSkew returns nil if ts is within SkewTolerance of now, else an error.
func CheckSkew(ts int64, now time.Time) error {
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > SkewTolerance {
		return fmt.Errorf("hsauth: clock skew %ds exceeds ±%ds", diff, SkewTolerance)
	}
	return nil
}
