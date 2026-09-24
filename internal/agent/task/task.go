// Package task implements the agent-side task runner (M3, PRD §5.5).
//
// A task is an ordered list of intent-based steps. The runner executes each
// step in order, evaluating an optional `when` guard (a constrained fact
// expression, not free-form code) first. A false guard reports `skipped`.
// Each step reports ok|changed|failed. A `failed` step stops the run.
//
// Steps are idempotent: each checks the current state before changing and
// reports `changed` only when it made a change, `ok` when the desired state
// already held.
package task

import (
	"context"
	"fmt"

	pb "github.com/blawesom/partout/internal/proto"
)

// State constants (shared with store).
const (
	StateOK        = "ok"
	StateChanged   = "changed"
	StateFailed    = "failed"
	StateSkipped   = "skipped"
	StateSucceeded = "succeeded"
)

// StepResult mirrors pb.TaskStepResult for internal use.
type StepResult struct {
	Index    int
	Name     string
	State    string
	Detail   string
	Started  int64
	Finished int64
}

// Result is the agent's final report for a task run.
type Result struct {
	State string
	Error string
	Steps []StepResult
}

// Runner executes a task run.
type Runner struct {
	// Exec is the per-kind step executor.
	exec *Executor
}

// New builds a Runner with the given executor (and its dependencies).
func New(exec *Executor) *Runner {
	return &Runner{exec: exec}
}

// Run executes the steps of a task run in order and returns the aggregate
// result. A `failed` step stops the run (remaining steps are not attempted).
func (r *Runner) Run(ctx context.Context, run *pb.TaskRun) *Result {
	res := &Result{State: StateSucceeded}
	for i, step := range run.GetSteps() {
		sr := r.exec.Step(ctx, i, step)
		res.Steps = append(res.Steps, sr)
		switch sr.State {
		case StateSkipped, StateOK, StateChanged:
			// continue
		case StateFailed:
			res.State = StateFailed
			res.Error = fmt.Sprintf("step %d (%s) failed: %s", i, step.GetKind(), sr.Detail)
			return res
		}
	}
	return res
}