package stream

// Whitebox tests for the durable pending-update queue (M8.1 #4): the
// in-memory offline queue is the fast path; pending_updates is what makes
// a dispatch survive a server restart.

import (
	"io"
	"log"
	"testing"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/store"
)

func seedUpdateRelease(t *testing.T, st *store.Store, id, version string) {
	t.Helper()
	rel := store.Release{ID: id, Version: version, Arch: "linux-amd64", Kind: "agent",
		SHA256: "aa", Signature: "sig", Artifact: []byte("artifact")}
	if err := st.InsertRelease(rel); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}
}

func TestUpdateDirectivePersistsAcrossRestart(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	seedUpdateRelease(t, st, "rel_1", "v1.0.0")

	// Dispatch to an offline agent on the "old" server instance.
	h1 := NewHandler(st, nil, log.New(io.Discard, "", 0))
	dir := &pb.UpdateDirective{ReleaseId: "rel_1", Version: "v1.0.0", Arch: "linux-amd64", Kind: "agent", Grant: "dispatch-grant"}
	if err := h1.QueueUpdateDirective("ag_1", dir); err != nil {
		t.Fatalf("queue: %v", err)
	}
	p, err := st.GetPendingUpdate("ag_1")
	if err != nil || p == nil || p.ReleaseID != "rel_1" {
		t.Fatalf("pending row = (%v, %v), want rel_1", p, err)
	}

	// "Restart": a new handler on the same store (in-memory state gone).
	h2 := NewHandler(st, nil, log.New(io.Discard, "", 0))
	var delivered []*pb.Envelope
	h2.drainOffline("ag_1", func(env *pb.Envelope) error { delivered = append(delivered, env); return nil })

	if len(delivered) != 1 {
		t.Fatalf("delivered %d envelopes on reconnect, want 1", len(delivered))
	}
	u := delivered[0].GetUpdateDirective()
	if u == nil || u.ReleaseId != "rel_1" || u.Grant == "" || u.Grant == dir.Grant {
		t.Fatalf("delivered directive = %+v; want rel_1 with a FRESH grant", u)
	}
	// The fresh grant must actually redeem to the right binding.
	agentID, releaseID, ok := h2.RedeemUpdateGrant(u.Grant)
	if !ok || agentID != "ag_1" || releaseID != "rel_1" {
		t.Fatalf("fresh grant redeem = (%q, %q, %v), want (ag_1, rel_1, true)", agentID, releaseID, ok)
	}
	// Row retired after delivery.
	if p, _ := st.GetPendingUpdate("ag_1"); p != nil {
		t.Error("pending row still present after delivery")
	}
	// A second reconnect delivers nothing.
	var second []*pb.Envelope
	h2.drainOffline("ag_1", func(env *pb.Envelope) error { second = append(second, env); return nil })
	if len(second) != 0 {
		t.Errorf("second reconnect delivered %d envelopes, want 0", len(second))
	}
}

func TestPendingUpdateMemoryCopyRetiresRow(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	seedUpdateRelease(t, st, "rel_1", "v1.0.0")

	h := NewHandler(st, nil, log.New(io.Discard, "", 0))
	if err := h.QueueUpdateDirective("ag_1", &pb.UpdateDirective{ReleaseId: "rel_1", Version: "v1.0.0", Arch: "linux-amd64", Kind: "agent", Grant: "dispatch-grant"}); err != nil {
		t.Fatalf("queue: %v", err)
	}

	// Reconnect on the SAME instance: the in-memory copy is delivered and
	// the durable row for the same release is retired — no second copy.
	var delivered []*pb.Envelope
	h.drainOffline("ag_1", func(env *pb.Envelope) error { delivered = append(delivered, env); return nil })
	if len(delivered) != 1 || delivered[0].GetUpdateDirective() == nil {
		t.Fatalf("delivered = %d envelope(s), want the in-memory directive", len(delivered))
	}
	if p, _ := st.GetPendingUpdate("ag_1"); p != nil {
		t.Error("pending row not retired after in-memory delivery")
	}
}

func TestPendingUpdateNewerReleaseKeptForNextReconnect(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	seedUpdateRelease(t, st, "rel_old", "v1.0.0")
	seedUpdateRelease(t, st, "rel_new", "v2.0.0")

	h := NewHandler(st, nil, log.New(io.Discard, "", 0))
	// First directive (v1) queued offline...
	if err := h.QueueUpdateDirective("ag_1", &pb.UpdateDirective{ReleaseId: "rel_old", Version: "v1.0.0", Arch: "linux-amd64", Kind: "agent", Grant: "dispatch-grant"}); err != nil {
		t.Fatalf("queue old: %v", err)
	}
	// ...then a newer run supersedes it while the host is still offline.
	if err := h.QueueUpdateDirective("ag_1", &pb.UpdateDirective{ReleaseId: "rel_new", Version: "v2.0.0", Arch: "linux-amd64", Kind: "agent", Grant: "dispatch-grant"}); err != nil {
		t.Fatalf("queue new: %v", err)
	}

	var delivered []*pb.Envelope
	h.drainOffline("ag_1", func(env *pb.Envelope) error { delivered = append(delivered, env); return nil })

	// The in-memory queue holds both (v1 then v2); the durable row (v2)
	// matches the last in-memory delivery -> retired, not re-sent.
	if len(delivered) != 2 {
		t.Fatalf("delivered %d envelopes, want 2", len(delivered))
	}
	if u := delivered[1].GetUpdateDirective(); u == nil || u.ReleaseId != "rel_new" {
		t.Fatalf("second delivery = %+v, want rel_new", u)
	}
	if p, _ := st.GetPendingUpdate("ag_1"); p != nil {
		t.Errorf("pending row not retired (would double-deliver on next reconnect): %+v", p)
	}
}

func TestPendingUpdateDeletedReleaseDropped(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	seedUpdateRelease(t, st, "rel_1", "v1.0.0")

	h := NewHandler(st, nil, log.New(io.Discard, "", 0))
	if err := h.QueueUpdateDirective("ag_1", &pb.UpdateDirective{ReleaseId: "rel_1", Version: "v1.0.0", Arch: "linux-amd64", Kind: "agent", Grant: "dispatch-grant"}); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if _, err := st.DeleteRelease("rel_1"); err != nil {
		t.Fatalf("DeleteRelease: %v", err)
	}

	var delivered []*pb.Envelope
	h.drainOffline("ag_1", func(env *pb.Envelope) error { delivered = append(delivered, env); return nil })
	// The in-memory copy is still delivered (bounded, in-flight), but the
	// durable row must be dropped — its release no longer exists.
	if p, _ := st.GetPendingUpdate("ag_1"); p != nil {
		t.Errorf("pending row for a deleted release not dropped: %+v", p)
	}
}
