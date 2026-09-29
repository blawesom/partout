package stream_test

import (
	"io"
	"log"
	"testing"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/store"
)

func TestUpdateGrantLifecycle(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	h := stream.NewHandler(st, nil, log.New(io.Discard, "", 0))

	// Minting requires both an agent and a release.
	if _, err := h.IssueUpdateGrant("", "rel_1"); err == nil {
		t.Error("mint without agent: want error")
	}
	if _, err := h.IssueUpdateGrant("ag_1", ""); err == nil {
		t.Error("mint without release: want error")
	}

	tok, err := h.IssueUpdateGrant("ag_1", "rel_1")
	if err != nil || tok == "" {
		t.Fatalf("mint: tok=%q err=%v", tok, err)
	}

	// Unknown token → invalid.
	if _, _, ok := h.RedeemUpdateGrant("bogus"); ok {
		t.Error("unknown grant redeemed")
	}

	// First redeem succeeds and returns the binding.
	agentID, releaseID, ok := h.RedeemUpdateGrant(tok)
	if !ok || agentID != "ag_1" || releaseID != "rel_1" {
		t.Fatalf("redeem = (%q, %q, %v), want (ag_1, rel_1, true)", agentID, releaseID, ok)
	}

	// Single-use: a second redeem fails.
	if _, _, ok := h.RedeemUpdateGrant(tok); ok {
		t.Error("grant redeemed twice (must be single-use)")
	}
}

func TestSendUpdateDirectiveOffline(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	h := stream.NewHandler(st, nil, log.New(io.Discard, "", 0))

	// No connected session → ErrAgentOffline (queued delivery is step 3).
	dir := &pb.UpdateDirective{ReleaseId: "rel_1", Version: "v1", Arch: "linux-amd64", Kind: "agent"}
	if err := h.SendUpdateDirective("ag_nobody", dir); err != stream.ErrAgentOffline {
		t.Fatalf("offline dispatch = %v, want ErrAgentOffline", err)
	}
}
