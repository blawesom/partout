package control_test

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// newSweeperCtl builds a control + store pair for aggregate-state tests.
func newSweeperCtl(t *testing.T) (*control.Control, *store.Store) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	return control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0)), st
}

func seedExecution(t *testing.T, st *store.Store, execID string, runs ...store.ExecutionRun) {
	t.Helper()
	if err := st.UpsertAgent(store.Agent{ID: "ag_x", UUID: "uuid-x", ED25519Pub: "e", X25519Pub: "x"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.CreateExecution(store.Execution{ID: execID, Selector: "all", Cmd: "true", State: "dispatching"}); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	for _, r := range runs {
		if err := st.CreateExecutionRun(r); err != nil {
			t.Fatalf("CreateExecutionRun %s: %v", r.ID, err)
		}
	}
}

func execState(t *testing.T, st *store.Store, execID string) string {
	t.Helper()
	ex, err := st.GetExecution(execID)
	if err != nil {
		t.Fatalf("GetExecution: %v", err)
	}
	return ex.State
}

// TestFinalizeExecutionInterruptedAggregate is the 1.0-gate fix (roadmap
// item 20): a disconnect-momentary "interrupted" run must NOT finalize the
// execution as failed/partial — a failure policy watching the transient
// state would wrongly retry. The aggregate reads "interrupted" until the
// run resolves.
func TestFinalizeExecutionInterruptedAggregate(t *testing.T) {
	ctl, st := newSweeperCtl(t)
	seedExecution(t, st, "exec_i1",
		store.ExecutionRun{ID: "r1", ExecutionID: "exec_i1", AgentID: "ag_x", State: "succeeded"},
		store.ExecutionRun{ID: "r2", ExecutionID: "exec_i1", AgentID: "ag_x", State: "failed"},
		store.ExecutionRun{ID: "r3", ExecutionID: "exec_i1", AgentID: "ag_x", State: "interrupted"},
	)
	if err := ctl.FinalizeExecution("exec_i1"); err != nil {
		t.Fatalf("FinalizeExecution: %v", err)
	}
	if s := execState(t, st, "exec_i1"); s != "interrupted" {
		t.Fatalf("execution state = %q, want interrupted (transient, not partial)", s)
	}

	// The agent replays its spooled result: interrupted -> succeeded. The
	// aggregate converges to the true outcome (partial).
	if err := st.UpdateRunState("r3", "succeeded", 0, 10); err != nil {
		t.Fatalf("UpdateRunState replay: %v", err)
	}
	if err := ctl.FinalizeExecution("exec_i1"); err != nil {
		t.Fatalf("FinalizeExecution replay: %v", err)
	}
	if s := execState(t, st, "exec_i1"); s != "partial" {
		t.Fatalf("execution state after replay = %q, want partial", s)
	}
}

// TestFinalizeExecutionAllInterrupted verifies the all-interrupted case
// (every host dropped): the aggregate is interrupted, not failed.
func TestFinalizeExecutionAllInterrupted(t *testing.T) {
	ctl, st := newSweeperCtl(t)
	seedExecution(t, st, "exec_i2",
		store.ExecutionRun{ID: "r1", ExecutionID: "exec_i2", AgentID: "ag_x", State: "interrupted"},
	)
	if err := ctl.FinalizeExecution("exec_i2"); err != nil {
		t.Fatalf("FinalizeExecution: %v", err)
	}
	if s := execState(t, st, "exec_i2"); s != "interrupted" {
		t.Fatalf("execution state = %q, want interrupted", s)
	}
}

// TestFinalizeExecutionInterruptedStillRunningWhileInFlight verifies an
// execution with both in-flight and interrupted runs stays "running"
// (in-flight dominates until everything is terminal-ish).
func TestFinalizeExecutionInterruptedStillRunningWhileInFlight(t *testing.T) {
	ctl, st := newSweeperCtl(t)
	seedExecution(t, st, "exec_i3",
		store.ExecutionRun{ID: "r1", ExecutionID: "exec_i3", AgentID: "ag_x", State: "interrupted"},
		store.ExecutionRun{ID: "r2", ExecutionID: "exec_i3", AgentID: "ag_x", State: "delivered"},
	)
	if err := ctl.FinalizeExecution("exec_i3"); err != nil {
		t.Fatalf("FinalizeExecution: %v", err)
	}
	if s := execState(t, st, "exec_i3"); s != "running" {
		t.Fatalf("execution state = %q, want running (a run is still in flight)", s)
	}
}

// TestSweepInterruptedResolvesStranded verifies the bound: an interrupted
// run that outlives the spool window resolves to not_delivered and the
// aggregate converges to a terminal state.
func TestSweepInterruptedResolvesStranded(t *testing.T) {
	ctl, st := newSweeperCtl(t)
	seedExecution(t, st, "exec_s",
		store.ExecutionRun{ID: "r1", ExecutionID: "exec_s", AgentID: "ag_x", State: "interrupted"},
	)

	// Not stranded yet: within the window, nothing resolves.
	if err := ctl.SweepInterrupted(time.Hour); err != nil {
		t.Fatalf("SweepInterrupted (young run): %v", err)
	}
	runs, _ := st.ListRunsForExecution("exec_s")
	if runs[0].State != "interrupted" {
		t.Fatalf("young run state = %q, want interrupted (no premature resolution)", runs[0].State)
	}

	// Outlived the window: resolves to not_delivered, aggregate failed.
	if err := ctl.SweepInterrupted(0); err != nil {
		t.Fatalf("SweepInterrupted (stranded): %v", err)
	}
	runs, _ = st.ListRunsForExecution("exec_s")
	if runs[0].State != "not_delivered" {
		t.Fatalf("stranded run state = %q, want not_delivered", runs[0].State)
	}
	if s := execState(t, st, "exec_s"); s != "failed" {
		t.Fatalf("execution state = %q, want failed (not_delivered is terminal)", s)
	}

	// The resolution is auditable.
	ev, err := st.ListAudit("", 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	found := false
	for _, a := range ev {
		if a.Kind == "exec.stranded" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no exec.stranded audit row after sweep (got %d rows)", len(ev))
	}
}
