package store

import (
	"testing"
)

// setupExecFixture creates an agent, execution, and run in state "delivered".
func setupExecFixture(t *testing.T, db *Store, runState string) (runID string) {
	t.Helper()
	if err := db.UpsertAgent(Agent{ID: "ag_sp", UUID: "u-sp", ED25519Pub: "kp1", X25519Pub: "kp2"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := db.CreateExecution(Execution{ID: "exec_sp", Selector: "role:web", Cmd: "echo", State: "running"}); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := db.CreateExecutionRun(ExecutionRun{ID: "run_sp", ExecutionID: "exec_sp", AgentID: "ag_sp", State: runState}); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}
	return "run_sp"
}

func TestAppendOutputIdempotent(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	setupExecFixture(t, db, "running")

	ch := OutputChunk{RunID: "run_sp", ChunkSeq: 0, Stream: "stdout", Data: []byte("hello ")}
	if err := db.AppendOutput(ch); err != nil {
		t.Fatalf("AppendOutput: %v", err)
	}
	// Replay the same chunk (as a spool drain would).
	if err := db.AppendOutput(ch); err != nil {
		t.Fatalf("AppendOutput replay: %v", err)
	}
	chunks, err := db.ListOutput("run_sp")
	if err != nil {
		t.Fatalf("ListOutput: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("chunks = %d, want 1 (replay should be a no-op)", len(chunks))
	}
}

func TestUpdateRunStateGuarded(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	// delivered -> running (normal transition)
	setupExecFixture(t, db, "delivered")
	if err := db.UpdateRunState("run_sp", "running", -1, 0); err != nil {
		t.Fatalf("UpdateRunState: %v", err)
	}
	runs, _ := db.ListRunsForExecution("exec_sp")
	if runs[0].State != "running" {
		t.Fatalf("state = %q, want running", runs[0].State)
	}

	// running -> succeeded (normal terminal)
	if err := db.UpdateRunState("run_sp", "succeeded", 0, 42); err != nil {
		t.Fatalf("UpdateRunState: %v", err)
	}
	runs, _ = db.ListRunsForExecution("exec_sp")
	if runs[0].State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", runs[0].State)
	}

	// succeeded -> failed (stale replay must NOT overwrite a terminal state)
	if err := db.UpdateRunState("run_sp", "failed", 1, 99); err != nil {
		t.Fatalf("UpdateRunState: %v", err)
	}
	runs, _ = db.ListRunsForExecution("exec_sp")
	if runs[0].State != "succeeded" {
		t.Fatalf("state = %q, want succeeded (guarded)", runs[0].State)
	}

	// succeeded -> succeeded (duplicate is a no-op, allowed)
	if err := db.UpdateRunState("run_sp", "succeeded", 0, 42); err != nil {
		t.Fatalf("UpdateRunState dup: %v", err)
	}
}

func TestInterruptedCanReFinalize(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	setupExecFixture(t, db, "delivered")

	// Simulate a disconnect: the server marks the run interrupted.
	if _, err := db.InterruptAgentRuns("ag_sp"); err != nil {
		t.Fatalf("InterruptAgentRuns: %v", err)
	}
	runs, _ := db.ListRunsForExecution("exec_sp")
	if runs[0].State != "interrupted" {
		t.Fatalf("state = %q, want interrupted", runs[0].State)
	}

	// The agent replays the spooled result: interrupted -> succeeded.
	if err := db.UpdateRunState("run_sp", "succeeded", 0, 100); err != nil {
		t.Fatalf("UpdateRunState replay: %v", err)
	}
	runs, _ = db.ListRunsForExecution("exec_sp")
	if runs[0].State != "succeeded" {
		t.Fatalf("state = %q, want succeeded (re-finalized)", runs[0].State)
	}
}

func TestInterruptAgentRuns(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	// Two runs on the same agent: one in flight, one queued.
	if err := db.UpsertAgent(Agent{ID: "ag_sp", UUID: "u-sp", ED25519Pub: "kp1", X25519Pub: "kp2"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := db.CreateExecution(Execution{ID: "exec_a", Selector: "all", Cmd: "a", State: "running"}); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := db.CreateExecution(Execution{ID: "exec_b", Selector: "all", Cmd: "b", State: "running"}); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := db.CreateExecutionRun(ExecutionRun{ID: "run_a", ExecutionID: "exec_a", AgentID: "ag_sp", State: "running"}); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}
	if err := db.CreateExecutionRun(ExecutionRun{ID: "run_b", ExecutionID: "exec_b", AgentID: "ag_sp", State: "queued"}); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}
	// A run on a different agent (must be untouched).
	if err := db.UpsertAgent(Agent{ID: "ag_other", UUID: "u-other", ED25519Pub: "kp3", X25519Pub: "kp4"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := db.CreateExecutionRun(ExecutionRun{ID: "run_c", ExecutionID: "exec_b", AgentID: "ag_other", State: "running"}); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}

	execs, err := db.InterruptAgentRuns("ag_sp")
	if err != nil {
		t.Fatalf("InterruptAgentRuns: %v", err)
	}
	if len(execs) != 1 || execs[0] != "exec_a" {
		t.Fatalf("execs = %v, want [exec_a]", execs)
	}

	runs, err := db.ListRunsForExecution("exec_a")
	if err != nil {
		t.Fatalf("ListRunsForExecution: %v", err)
	}
	if runs[0].State != "interrupted" {
		t.Fatalf("run_a state = %q, want interrupted", runs[0].State)
	}
	runs, _ = db.ListRunsForExecution("exec_b")
	// run_b (queued) untouched; run_c (other agent) untouched.
	for _, r := range runs {
		switch r.ID {
		case "run_b":
			if r.State != "queued" {
				t.Fatalf("run_b state = %q, want queued", r.State)
			}
		case "run_c":
			if r.State != "running" {
				t.Fatalf("run_c state = %q, want running", r.State)
			}
		}
	}
}

func TestInterruptAgentRunsNoop(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	setupExecFixture(t, db, "succeeded")

	execs, err := db.InterruptAgentRuns("ag_sp")
	if err != nil {
		t.Fatalf("InterruptAgentRuns: %v", err)
	}
	if len(execs) != 0 {
		t.Fatalf("execs = %v, want none", execs)
	}
}
