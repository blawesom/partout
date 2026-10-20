package task

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/agent/fs"
	pb "github.com/blawesom/partout/internal/proto"
)

func TestStepFile(t *testing.T) {
	e := NewExecutor(elevate.None, nil)
	dir := t.TempDir()
	root, err := prepareTestRoot(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	e.SetFileRoot(root)
	p := "test.txt"

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
	if got, _ := os.ReadFile(filepath.Join(root, p)); string(got) != "world" {
		t.Fatalf("file content = %q, want world", got)
	}

	// Path escape fails closed.
	sr = e.Step(context.Background(), 0, &pb.TaskStep{Kind: "file", Name: "write", Path: "../../outside.txt", Content: "x"})
	if sr.State != StateFailed {
		t.Fatalf("escape: %s (%s), want failed", sr.State, sr.Detail)
	}
}

func prepareTestRoot(t *testing.T, dir string) (string, error) {
	t.Helper()
	return fs.PrepareFileRoot(dir)
}

func TestStepCommand(t *testing.T) {
	e := NewExecutor(elevate.None, nil)
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
	e := NewExecutor(elevate.None, nil)
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
	e := NewExecutor(elevate.None, nil)
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
	e := NewExecutor(elevate.None, nil)
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
	e := NewExecutor(elevate.None, nil)
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

// TestStepSecretRefs: a step whose env/vars/content declare `secret:NAME`
// refs renders them through the executor's secrets lookup (the E2E cache
// in the real agent) — the written file contains the plaintext, never the
// bare ref. An unavailable ref fails the step closed.
func TestStepSecretRefs(t *testing.T) {
	secrets := func(ref string, _ int64) (string, error) {
		if ref == "db-pass" {
			return "s3cr3t-value", nil
		}
		return "", &secretLookupErr{ref}
	}
	e := NewExecutor(elevate.None, secrets)
	root, err := prepareTestRoot(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.SetFileRoot(root)

	// Template step whose var is the ref: the rendered file holds the
	// plaintext.
	sr := e.Step(context.Background(), 0, &pb.TaskStep{
		Kind: "template", Name: "render", Path: "app.conf",
		Template: "db_password={{.pw}}\n", Vars: map[string]string{"pw": "secret:db-pass"},
	})
	if sr.State != StateChanged {
		t.Fatalf("template step: %s (%s)", sr.State, sr.Detail)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "app.conf")); string(got) != "db_password=s3cr3t-value\n" {
		t.Fatalf("rendered file = %q, want the secret plaintext", got)
	}

	// File step whose content is the ref.
	sr = e.Step(context.Background(), 1, &pb.TaskStep{
		Kind: "file", Name: "raw", Path: "raw.txt", Content: "secret:db-pass",
	})
	if sr.State != StateChanged {
		t.Fatalf("file step: %s (%s)", sr.State, sr.Detail)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "raw.txt")); string(got) != "s3cr3t-value" {
		t.Fatalf("file content = %q, want the secret plaintext", got)
	}

	// Unavailable ref: fail closed, never run with the bare ref.
	sr = e.Step(context.Background(), 2, &pb.TaskStep{
		Kind: "command", Name: "uses missing", Command: "true",
		Env: map[string]string{"T": "secret:missing"},
	})
	if sr.State != StateFailed {
		t.Fatalf("missing secret: %s (%s), want failed", sr.State, sr.Detail)
	}
	if !strings.Contains(sr.Detail, "missing") {
		t.Fatalf("detail = %q, want the ref named", sr.Detail)
	}
}

type secretLookupErr struct{ ref string }

func (e *secretLookupErr) Error() string { return "secret \"" + e.ref + "\" unavailable" }
