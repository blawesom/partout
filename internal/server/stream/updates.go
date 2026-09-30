package stream

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/store"
)

// Update artifact download grants (M8.1, step 2).
//
// An UpdateDirective carries a one-time, TTL-bound grant instead of the
// artifact bytes: the binary transfer stays off the control stream (no
// head-of-line blocking), and the grant only grants ACCESS — trust is
// established by the agent verifying the release signature against its
// locally provisioned key before executing anything.
const updateGrantTTL = 10 * time.Minute

type updateGrant struct {
	agentID   string
	releaseID string
	expiresAt time.Time
}

func (h *Handler) initUpdateGrants() {
	if h.updateGrants == nil {
		h.updateGrants = map[string]updateGrant{}
	}
}

// IssueUpdateGrant mints a one-time grant binding agentID to releaseID.
func (h *Handler) IssueUpdateGrant(agentID, releaseID string) (string, error) {
	if agentID == "" || releaseID == "" {
		return "", fmt.Errorf("stream: update grant requires agent + release")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("stream: grant random: %w", err)
	}
	tok := hex.EncodeToString(buf)
	h.initUpdateGrants()
	h.updateMu.Lock()
	// Reap expired grants opportunistically.
	now := time.Now()
	for k, g := range h.updateGrants {
		if now.After(g.expiresAt) {
			delete(h.updateGrants, k)
		}
	}
	h.updateGrants[tok] = updateGrant{agentID: agentID, releaseID: releaseID, expiresAt: now.Add(updateGrantTTL)}
	h.updateMu.Unlock()
	return tok, nil
}

// RedeemUpdateGrant validates and atomically consumes a grant, returning the
// binding it was minted for. Single-use: a second call with the same token
// fails.
func (h *Handler) RedeemUpdateGrant(tok string) (agentID, releaseID string, ok bool) {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	g, found := h.updateGrants[tok]
	if !found || time.Now().After(g.expiresAt) {
		return "", "", false
	}
	delete(h.updateGrants, tok)
	return g.agentID, g.releaseID, true
}

// SendUpdateDirective delivers a signed update directive to a connected
// agent. Offline agents get an error (queued delivery is the M8.1 step-3
// rollout machinery, not the canary path).
func (h *Handler) SendUpdateDirective(agentID string, dir *pb.UpdateDirective) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return ErrAgentOffline
	}
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_UPDATE_DIRECTIVE,
		Payload: &pb.Envelope_UpdateDirective{UpdateDirective: dir},
	}
	return sess.send(env)
}

// QueueUpdateDirective delivers a signed update directive to a connected
// agent, or queues it for an offline one (delivered on reconnect, like
// commands). This is the M8.1 step-3 rollout path: fleet hosts may be
// unreachable at dispatch time and must not be dropped.
//
// Offline delivery is two-layered: the in-memory queue (fast, lost on
// restart) AND a durable row in pending_updates (survives a server restart).
// On reconnect the drain reconciles the two (see drainOffline); the durable
// row stores only (agent, release) so delivery can always mint a fresh
// grant — a directive queued across a long outage never expires.
func (h *Handler) QueueUpdateDirective(agentID string, dir *pb.UpdateDirective) error {
	if err := h.SendUpdateDirective(agentID, dir); err == nil {
		return nil
	}
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_UPDATE_DIRECTIVE,
		Payload: &pb.Envelope_UpdateDirective{UpdateDirective: dir},
	}
	h.queueOffline(agentID, env)
	if h.st != nil {
		if err := h.st.UpsertPendingUpdate(agentID, dir.ReleaseId); err != nil {
			h.log.Printf("stream: persist pending update for %s: %v (in-memory copy still queued)", agentID, err)
		}
	}
	h.log.Printf("stream: update directive for %s queued (agent offline)", agentID)
	return nil
}

// deliverPendingUpdate sends the durable pending-update directive for
// agentID, rebuilding it from the release row with a FRESH one-time grant
// (the grant minted at dispatch may be long expired). Returns true when the
// directive was sent. The pending row is deleted on success; on send failure
// it is kept for the next reconnect.
func (h *Handler) deliverPendingUpdate(agentID string, send func(*pb.Envelope) error) bool {
	if h.st == nil {
		return false
	}
	p, err := h.st.GetPendingUpdate(agentID)
	if err != nil {
		h.log.Printf("stream: pending update lookup %s: %v", agentID, err)
		return false
	}
	if p == nil {
		return false
	}
	rel, err := h.st.GetRelease(p.ReleaseID)
	if err != nil {
		if errors.Is(err, store.ErrNoRelease) {
			h.log.Printf("stream: pending update %s: release %s deleted; dropping", agentID, p.ReleaseID)
			_ = h.st.DeletePendingUpdate(agentID)
		} else {
			h.log.Printf("stream: pending update %s: release %s: %v; kept for next reconnect", agentID, p.ReleaseID, err)
		}
		return false
	}
	tok, err := h.IssueUpdateGrant(agentID, p.ReleaseID)
	if err != nil {
		h.log.Printf("stream: pending update %s: grant: %v; kept for next reconnect", agentID, err)
		return false
	}
	dir := &pb.UpdateDirective{
		ReleaseId: rel.ID, Version: rel.Version, Arch: rel.Arch,
		Kind: rel.Kind, Sha256: rel.SHA256, Signature: rel.Signature, Grant: tok,
		Unsigned: rel.Signature == "",
	}
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_UPDATE_DIRECTIVE,
		Payload: &pb.Envelope_UpdateDirective{UpdateDirective: dir},
	}
	if err := send(env); err != nil {
		h.log.Printf("stream: pending update %s: send: %v; kept for next reconnect", agentID, err)
		return false
	}
	if err := h.st.DeletePendingUpdate(agentID); err != nil {
		h.log.Printf("stream: pending update %s: delete after send: %v", agentID, err)
	}
	h.log.Printf("stream: delivered pending update %s (release %s) to reconnected %s", dir.Version, rel.ID, agentID)
	return true
}
