package stream

import (
	"errors"
	"testing"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/store"
)

// newTestHandlerStore builds a store + handler with a registered (offline) agent
// and a queued-state execution run.
func newTestHandlerStore(t *testing.T) (*store.Store, *Handler, string) {
	t.Helper()
	st, err := store.New("sqlite:" + t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := NewHandler(st, nil, nil)
	agentID := "ag_offline_dispatch"
	if err := st.UpsertAgent(store.Agent{ID: agentID, UUID: "uuid-off", ED25519Pub: "e", X25519Pub: "x", State: "disconnected"}); err != nil {
		t.Fatal(err)
	}
	// Parent execution so the FK on execution_runs is satisfied.
	if err := st.CreateExecution(store.Execution{ID: "exec_x", Selector: "all", Cmd: "hostname", CreatedBy: "test", State: "dispatching"}); err != nil {
		t.Fatal(err)
	}
	return st, h, agentID
}

func makeCommand(runID string) *pb.Command {
	return &pb.Command{RunId: runID, ExecutionId: "exec_x", Cmd: "hostname"}
}

func runState(t *testing.T, st *store.Store, runID string) string {
	t.Helper()
	r, err := st.GetExecutionRun(runID)
	if err != nil {
		t.Fatalf("ExecutionRun: %v", err)
	}
	return r.State
}

// TestDispatchToOfflineAgent verifies a command for an offline agent is queued
// (not lost), and delivered + marked delivered when the agent reconnects.
func TestDispatchToOfflineAgent(t *testing.T) {
	st, h, agentID := newTestHandlerStore(t)
	runID := "run_off1"
	// Start in queued_offline (the real dispatch-to-offline state) so this also
	// regression-tests that UpdateRunState allows queued_offline -> delivered.
	if err := st.CreateExecutionRun(store.ExecutionRun{ID: runID, ExecutionID: "exec_x", AgentID: agentID, State: "queued_offline"}); err != nil {
		t.Fatal(err)
	}

	// Agent is offline: SendCommand queues and returns ErrAgentOffline.
	err := h.SendCommand(agentID, makeCommand(runID))
	if !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("expected ErrAgentOffline, got %v", err)
	}
	if h.QueueCount(agentID) != 1 {
		t.Fatalf("QueueCount = %d, want 1", h.QueueCount(agentID))
	}

	// Simulate reconnect: drain delivers the envelope and marks the run delivered.
	var delivered []*pb.Envelope
	h.drainOffline(agentID, func(env *pb.Envelope) error { delivered = append(delivered, env); return nil })
	if len(delivered) != 1 || delivered[0].GetCommand() == nil || delivered[0].GetCommand().RunId != runID {
		t.Fatalf("drain delivered %d envelope(s), want the queued command", len(delivered))
	}
	if h.QueueCount(agentID) != 0 {
		t.Errorf("queue not drained: %d", h.QueueCount(agentID))
	}
	if got := runState(t, st, runID); got != "delivered" {
		t.Errorf("run state after drain = %q, want delivered", got)
	}
}

// TestOfflineQueueExpiry verifies a queued envelope that passes its TTL is
// dropped on drain and the run marked expired.
func TestOfflineQueueExpiry(t *testing.T) {
	st, h, agentID := newTestHandlerStore(t)
	runID := "run_off2"
	if err := st.CreateExecutionRun(store.ExecutionRun{ID: runID, ExecutionID: "exec_x", AgentID: agentID, State: "queued"}); err != nil {
		t.Fatal(err)
	}

	// Inject an already-expired queued envelope directly (deterministic).
	h.offlineMu.Lock()
	h.offlineQueue[agentID] = append(h.offlineQueue[agentID],
		&queuedEnvelope{env: &pb.Envelope{Kind: pb.EnvelopeKind_COMMAND, Payload: &pb.Envelope_Command{Command: makeCommand(runID)}}, expiresAt: time.Now().Add(-time.Second)})
	h.offlineMu.Unlock()

	var delivered []*pb.Envelope
	h.drainOffline(agentID, func(env *pb.Envelope) error { delivered = append(delivered, env); return nil })
	if len(delivered) != 0 {
		t.Errorf("expired envelope was delivered (%d)", len(delivered))
	}
	if got := runState(t, st, runID); got != "expired" {
		t.Errorf("run state after expiry = %q, want expired", got)
	}
}

// TestOfflineQueueConnectedAgent verifies a command for a connected agent is
// sent immediately (not queued).
func TestOfflineQueueConnectedAgent(t *testing.T) {
	st, h, agentID := newTestHandlerStore(t)
	var sent []*pb.Envelope
	sess := &Session{AgentID: agentID, send: func(env *pb.Envelope) error { sent = append(sent, env); return nil }}
	h.mu.Lock()
	h.sessions[agentID] = sess
	h.mu.Unlock()
	t.Cleanup(func() { h.mu.Lock(); delete(h.sessions, agentID); h.mu.Unlock() })

	runID := "run_off3"
	_ = st.CreateExecutionRun(store.ExecutionRun{ID: runID, ExecutionID: "exec_x", AgentID: agentID, State: "queued"})
	if err := h.SendCommand(agentID, makeCommand(runID)); err != nil {
		t.Fatalf("SendCommand to connected agent: %v", err)
	}
	if h.QueueCount(agentID) != 0 {
		t.Errorf("connected agent should not queue: %d", h.QueueCount(agentID))
	}
	if len(sent) != 1 {
		t.Errorf("expected immediate send, got %d", len(sent))
	}
}
