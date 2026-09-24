package task

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/blawesom/partout/internal/proto"
)

func TestStepFile(t *testing.T) {
	e := NewExecutor(nil)
	dir := t.TempDir()
	p := filepath.Join(dir, "test.txt")

	// First write → changed.
	sr := e.Step(context.Background(), 0, &pb.TaskStep{Kind: "file", Name: "write", Path: p, Content: "hello"})
	if sr.State != StateChanged {
		t.Fatalf("first write: %s (%s)", sr.State, sr.Detail)
	}
	// Second write same content → ok (idempotent).
	sr = e.Step(context.Background(), 0, &pb.TaskStep{Kind: "file", Name: "write", Path: p, Content: "hello"})
	if sr.State != StateOK {
		t.Fatalf("second write: %s (%s)", sr.State, sr.Detail)
	}
	// Different content → changed.
	sr = e.Step(context.Background(), 0, &pb.TaskStep{Kind: "file", Name: "write", Path: p, Content: "world"})
	if sr.State != StateChanged {
		t.Fatalf("change content: %s (%s)", sr.State, sr.Detail)
	}
	if got, _ := os.ReadFile(p); string(got) != "world" {
		t.Fatalf("file content = %q, want world", got)
	}
}

func TestStepCommand(t *testing.T) {
	e := NewExecutor(nil)
	// Successful command.
	sr := e.Step(context.Background(), 0, &pb.TaskStep{Kind: "command", Name: "true", Command: "true"})
	if sr.State != StateOK {
		t.Fatalf("true: %s (%s)", sr.State, sr.Detail)
	}
	// Failing command.
	sr = e.Step(context.Background(), 0, &pb.TaskStep{Kind: "command", Name: "false", Command: "false"})
	if sr.State != StateFailed {
		t.Fatalf("false: %s (%s)", sr.State, sr.Detail)
	}
	// Unknown command.
	sr = e.Step(context.Background(), 0, &pb.TaskStep{Kind: "command", Name: "nope", Command: "definitely-not-a-real-cmd-xyz"})
	if sr.State != StateFailed {
		t.Fatalf("unknown cmd: %s", sr.State)
	}
}

func TestStepGuardSkipped(t *testing.T) {
	e := NewExecutor(nil)
	e.SetFacts(map[string]string{"host.distro": "ubuntu"})

	// Guard false → skipped.
	sr := e.Step(context.Background(), 0, &pb.TaskStep{
		Kind: "command", Name: "guarded", Command: "true",
		When: "host.distro == 'debian'",
	})
	if sr.State != StateSkipped {
		t.Fatalf("guard false: %s (%s)", sr.State, sr.Detail)
	}

	// Guard true → runs.
	sr = e.Step(context.Background(), 0, &pb.TaskStep{
		Kind: "command", Name: "guarded", Command: "true",
		When: "host.distro == 'ubuntu'",
	})
	if sr.State != StateOK {
		t.Fatalf("guard true: %s (%s)", sr.State, sr.Detail)
	}

	// Guard error → failed (fail-closed).
	sr = e.Step(context.Background(), 0, &pb.TaskStep{
		Kind: "command", Name: "guarded", Command: "true",
		When: "unknown_fact == 'x'",
	})
	if sr.State != StateFailed {
		t.Fatalf("guard error: %s (%s)", sr.State, sr.Detail)
	}
}

func TestStepAssert(t *testing.T) {
	e := NewExecutor(nil)
	e.SetFacts(map[string]string{"host.distro": "ubuntu"})
	sr := e.Step(context.Background(), 0, &pb.TaskStep{Kind: "assert", Expr: "host.distro == 'ubuntu'"})
	if sr.State != StateOK {
		t.Fatalf("assert true: %s", sr.State)
	}
	sr = e.Step(context.Background(), 0, &pb.TaskStep{Kind: "assert", Expr: "host.distro == 'rhel'"})
	if sr.State != StateFailed {
		t.Fatalf("assert false: %s", sr.State)
	}
}

func TestRunnerStopsOnFail(t *testing.T) {
	e := NewExecutor(nil)
	r := New(e)
	run := &pb.TaskRun{
		Steps: []*pb.TaskStep{
			{Kind: "command", Command: "true"},
			{Kind: "command", Command: "false"},
			{Kind: "command", Command: "true"},
		},
	}
	res := r.Run(context.Background(), run)
	if res.State != StateFailed {
		t.Fatalf("state = %s, want failed", res.State)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("steps = %d, want 2 (stops on fail)", len(res.Steps))
	}
	if res.Steps[1].State != StateFailed {
		t.Fatalf("step 1 = %s, want failed", res.Steps[1].State)
	}
}

func TestRunnerSkipped(t *testing.T) {
	e := NewExecutor(nil)
	e.SetFacts(map[string]string{"host.distro": "ubuntu"})
	r := New(e)
	run := &pb.TaskRun{
		Steps: []*pb.TaskStep{
			{Kind: "command", Command: "true", When: "host.distro == 'debian'"}, // skipped
			{Kind: "command", Command: "true"},                                  // runs
		},
	}
	res := r.Run(context.Background(), run)
	if res.State != StateSucceeded {
		t.Fatalf("state = %s", res.State)
	}
	if res.Steps[0].State != StateSkipped {
		t.Fatalf("step 0 = %s, want skipped", res.Steps[0].State)
	}
	if res.Steps[1].State != StateOK {
		t.Fatalf("step 1 = %s, want ok", res.Steps[1].State)
	}
}
