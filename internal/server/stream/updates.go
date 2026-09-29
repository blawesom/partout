package stream

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
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
func (h *Handler) QueueUpdateDirective(agentID string, dir *pb.UpdateDirective) error {
	if err := h.SendUpdateDirective(agentID, dir); err == nil {
		return nil
	}
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_UPDATE_DIRECTIVE,
		Payload: &pb.Envelope_UpdateDirective{UpdateDirective: dir},
	}
	h.queueOffline(agentID, env)
	h.log.Printf("stream: update directive for %s queued (agent offline)", agentID)
	return nil
}
