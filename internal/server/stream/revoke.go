package stream

import (
	pb "github.com/blawesom/partout/internal/proto"
)

// RevokeAgent tells a live agent that it has been removed from the fleet.
//
// The server never force-closes the gRPC stream: it sends the REVOKE
// envelope and the agent stops itself (its client-side close is what ends
// the Stream() goroutine and frees the session). Any offline work queued
// for the agent is dropped so it cannot outlive the deletion in memory.
// For a disconnected agent there is nothing to tell — its store row is
// gone, so the next handshake is rejected and removal already doubles as
// revocation.
func (h *Handler) RevokeAgent(agentID, reason string) {
	h.offlineMu.Lock()
	delete(h.offlineQueue, agentID)
	h.offlineMu.Unlock()

	h.mu.Lock()
	sess := h.sessions[agentID]
	h.mu.Unlock()
	if sess == nil {
		return
	}
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_REVOKE,
		Payload: &pb.Envelope_Revoke{Revoke: &pb.Revoke{Reason: reason}},
	}
	if err := sess.send(env); err != nil {
		h.log.Printf("stream: revoke %s: send: %v", agentID, err)
		return
	}
	h.log.Printf("stream: agent %s revoked (%s)", agentID, reason)
}
