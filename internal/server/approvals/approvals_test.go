package approvals

import (
	"log"
	"testing"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func newTestController(t *testing.T) (*Controller, *store.Store, *certutil.ServerIdentity) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(testWriter{}, "srv: ", 0))
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c := New(st, h, sseB, nil)
	c.SetIdentity(ident)
	return c, st, ident
}

type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestNewRequest stores a pending request scoped to the exact payload.
func TestNewRequest(t *testing.T) {
	c, st, _ := newTestController(t)

	req, err := c.NewRequest(NewRequestParams{
		ActionClass: "exec", AgentID: "ag_1", ExecutionID: "exec_1", RunID: "run_1",
		Actor: "alice", ActorRole: "operator",
		MatchedRules: []string{"no-rm"},
		Payload:      map[string]any{"cmd": "rm", "args": []string{"-rf", "/"}},
	})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if req.State != "pending" || req.ID == "" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.ExpiresUnix <= req.CreatedUnix {
		t.Fatal("expiry must be after creation")
	}

	got, err := st.GetApprovalRequest(req.ID)
	if err != nil || got == nil {
		t.Fatalf("stored request: %v %v", got, err)
	}
	if got.PayloadJSON == "" {
		t.Fatal("payload must be stored")
	}
}

// TestApproveNonAdmin: only admins can approve.
func TestApproveNonAdmin(t *testing.T) {
	c, _, _ := newTestController(t)
	req, _ := c.NewRequest(NewRequestParams{ActionClass: "exec", AgentID: "ag_1", RunID: "run_1",
		Actor: "alice", ActorRole: "operator", Payload: map[string]any{"cmd": "rm"}})

	_, err := c.Approve(req.ID, Actor{Principal: "alice", Role: "operator"})
	if err == nil {
		t.Fatal("operator must not be able to approve")
	}
	stored, _ := c.Get(req.ID)
	if stored.State != "pending" {
		t.Fatalf("request should stay pending, got %s", stored.State)
	}
}

// TestApproveDispatches: admin approval re-dispatches through the registered
// dispatcher with a freshly signed EffectAllow decision carrying the
// approval id, and the signature verifies against the server key.
func TestApproveDispatches(t *testing.T) {
	c, st, ident := newTestController(t)

	var dispatched *store.ApprovalRequest
	var dec *pb.Decision
	c.RegisterDispatcher("exec", func(req *store.ApprovalRequest, d *pb.Decision) error {
		dispatched, dec = req, d
		return nil
	})
	req, _ := c.NewRequest(NewRequestParams{
		ActionClass: "exec", AgentID: "ag_1", ExecutionID: "exec_1", RunID: "run_1",
		Actor: "alice", ActorRole: "operator", MatchedRules: []string{"r1"},
		Payload: map[string]any{"cmd": "rm"},
	})

	got, err := c.Approve(req.ID, Actor{Principal: "bob", Role: "admin"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.State != "approved" || got.DecidedBy != "bob" {
		t.Fatalf("after approve: %+v", got)
	}
	if dispatched == nil || dec == nil {
		t.Fatal("dispatcher was not called")
	}
	if dec.Effect != policy.EffectAllow || dec.ApprovalId != req.ID {
		t.Fatalf("bad decision: %+v", dec)
	}
	if dec.RunId != "run_1" {
		t.Fatalf("decision run id = %q, want run_1", dec.RunId)
	}
	version, _ := st.PolicyBundleVersion()
	if !policy.VerifyDecision(ident.Pub, dec.RunId, version, dec.Effect,
		dec.MatchedRules, dec.ActorRole, dec.ApprovalId, dec.Sig) {
		t.Fatal("decision signature failed to verify")
	}
}

// TestApproveNoDispatcher: approval succeeds but reports the missing
// dispatcher (the row stays approved; operator re-runs the action).
func TestApproveNoDispatcher(t *testing.T) {
	c, _, _ := newTestController(t)
	req, _ := c.NewRequest(NewRequestParams{ActionClass: "custom", AgentID: "ag_1",
		Payload: map[string]any{"x": 1}})

	_, err := c.Approve(req.ID, Actor{Principal: "bob", Role: "admin"})
	if err == nil {
		t.Fatal("expected error: no dispatcher registered")
	}
	stored, _ := c.Get(req.ID)
	if stored.State != "approved" {
		t.Fatalf("row should stay approved, got %s", stored.State)
	}
}

// TestDeny records the denial with reason.
func TestDeny(t *testing.T) {
	c, _, _ := newTestController(t)
	req, _ := c.NewRequest(NewRequestParams{ActionClass: "exec", AgentID: "ag_1",
		Payload: map[string]any{"cmd": "rm"}})

	got, err := c.Deny(req.ID, "too risky", Actor{Principal: "bob", Role: "admin"})
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if got.State != "denied" || got.DecisionReason != "too risky" {
		t.Fatalf("after deny: %+v", got)
	}
	// Denying again fails.
	if _, err := c.Deny(req.ID, "again", Actor{Principal: "bob", Role: "admin"}); err == nil {
		t.Fatal("expected error on second deny")
	}
}

// TestApproveRejectedWhenRunFinalized: if the parked run was cancelled or
// otherwise finalized before the admin acts, the approval is rejected.
func TestApproveRejectedWhenRunFinalized(t *testing.T) {
	c, st, _ := newTestController(t)
	if err := st.UpsertAgent(store.Agent{ID: "ag_1", UUID: "u1", ED25519Pub: "k", X25519Pub: "x"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	req, _ := c.NewRequest(NewRequestParams{
		ActionClass: "exec", AgentID: "ag_1", ExecutionID: "exec_1", RunID: "run_1",
		Actor: "alice", ActorRole: "operator", Payload: map[string]any{"cmd": "rm"},
	})
	if err := st.CreateExecution(store.Execution{ID: "exec_1", Selector: "all", Cmd: "rm", CreatedBy: "alice", State: "dispatching"}); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := st.CreateExecutionRun(store.ExecutionRun{ID: "run_1", ExecutionID: "exec_1", AgentID: "ag_1", State: "awaiting_approval"}); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}

	// Simulate the execution being cancelled (run finalized).
	if err := st.UpdateRunState("run_1", "cancelled", -1, 0); err != nil {
		t.Fatalf("UpdateRunState: %v", err)
	}

	if _, err := c.Approve(req.ID, Actor{Principal: "bob", Role: "admin"}); err == nil {
		t.Fatal("approving a cancelled run must fail")
	}
}

// TestExpiredCannotApprove: a request that expires cannot be retroactively
// honored; the parked exec run is finalized as failed.
func TestExpiredCannotApprove(t *testing.T) {
	c, st, _ := newTestController(t)

	// Seed the agent (runs FK to agents).
	if err := st.UpsertAgent(store.Agent{ID: "ag_1", UUID: "u1", ED25519Pub: "k", X25519Pub: "x"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	expiredExecs := []string{}
	c.OnExecExpired = func(execID string) { expiredExecs = append(expiredExecs, execID) }

	// Create a request with a short TTL, then fast-forward it past expiry.
	req, err := c.NewRequest(NewRequestParams{
		ActionClass: "exec", AgentID: "ag_1", ExecutionID: "exec_1", RunID: "run_1",
		Actor: "alice", ActorRole: "operator", Payload: map[string]any{"cmd": "rm"},
	})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Force the row into the past (tests don't want to sleep).
	if err := st.SetApprovalExpiryForTest(req.ID, 0); err != nil {
		t.Fatalf("SetApprovalExpiryForTest: %v", err)
	}
	// Seed the parked execution + run (run has an FK to the execution).
	if err := st.CreateExecution(store.Execution{ID: "exec_1", Selector: "all", Cmd: "rm", CreatedBy: "alice", State: "dispatching"}); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := st.CreateExecutionRun(store.ExecutionRun{ID: "run_1", ExecutionID: "exec_1", AgentID: "ag_1", State: "awaiting_approval"}); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}

	if _, err := c.List("", 50); err != nil {
		t.Fatalf("List: %v", err)
	}
	stored, _ := c.Get(req.ID)
	if stored.State != "expired" {
		t.Fatalf("expected expired, got %s", stored.State)
	}
	// The parked run must be finalized failed and the execution re-finalized.
	runs, err := st.ListRunsForExecution("exec_1")
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListRunsForExecution: %v %v", runs, err)
	}
	if runs[0].State != "failed" {
		t.Fatalf("run should be failed, got %s", runs[0].State)
	}
	if len(expiredExecs) != 1 || expiredExecs[0] != "exec_1" {
		t.Fatalf("OnExecExpired not called properly: %v", expiredExecs)
	}

	// Approve must now fail.
	if _, err := c.Approve(req.ID, Actor{Principal: "bob", Role: "admin"}); err == nil {
		t.Fatal("expired request must not be approvable")
	}
}
