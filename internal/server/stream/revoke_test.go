package stream

import (
	"io"
	"log"
	"testing"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
)

// TestRevokeAgent pins the removal revocation loop: a live session gets the
// REVOKE envelope (agent stops itself; its client-side close ends the
// stream), and queued offline work for the agent is dropped so it cannot
// outlive the deletion in memory.
func TestRevokeAgent(t *testing.T) {
	h := NewHandler(nil, nil, log.New(io.Discard, "", 0))

	const ag = "ag_r"
	// Queued offline work that must not survive the deletion.
	h.offlineQueue[ag] = []*queuedEnvelope{{
		env:       &pb.Envelope{Kind: pb.EnvelopeKind_COMMAND},
		expiresAt: time.Now().Add(time.Hour),
	}}

	var got *pb.Envelope
	sess := &Session{AgentID: ag}
	sess.send = func(env *pb.Envelope) error { got = env; return nil }
	h.sessions[ag] = sess

	h.RevokeAgent(ag, "host deleted")

	if got == nil {
		t.Fatal("RevokeAgent did not send to the live session")
	}
	if got.Kind != pb.EnvelopeKind_REVOKE {
		t.Errorf("envelope kind = %v, want REVOKE", got.Kind)
	}
	if r := got.GetRevoke(); r == nil || r.Reason != "host deleted" {
		t.Errorf("revoke payload = %+v, want reason %q", r, "host deleted")
	}
	if n := len(h.offlineQueue[ag]); n != 0 {
		t.Errorf("offline queue still holds %d entries after revoke, want 0", n)
	}

	// No session (agent offline at deletion time): a no-op, no panic.
	h.RevokeAgent("ag_nobody", "host deleted")
}
