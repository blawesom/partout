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
	"time"

	pb "github.com/blawesom/partout/internal/proto"
)

// State constants (shared with store).
const (
	StateOK        = "ok"
	StateChanged   = "changed"
	StateFailed    = "failed"
	StateSkipped   = "skipped"
	StateSucceeded = "succeeded"
	// StateRebooting marks a run that paused at a `reboot` step: the agent
	// persisted a resume marker and is rebooting. The remaining steps run
	// after the agent comes back (trigger "resume").
	StateRebooting = "rebooting"
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

// RebootCtx is handed to the Runner's reboot hook when a `reboot` step is
// reached. The hook persists the resume marker (remaining steps + results
// so far) BEFORE the host goes down.
type RebootCtx struct {
	Run         *pb.TaskRun
	JobID       string // non-empty when fired by the job scheduler
	JobTrigger  string // original trigger (cron | manual)
	MaxRunS     int32  // per-run deadline for the resumed remainder
	RebootIndex int    // index of the reboot step
	Done        []StepResult
}

// RebootHook persists the resume marker. A non-nil error aborts the run as
// failed (no marker, no reboot).
type RebootHook func(ctx context.Context, rc *RebootCtx) error

// RebootAbort is called when the reboot command itself fails (the host stays
// up), so the marker written by the hook can be discarded.
type RebootAbort func(runID string)

// Runner executes a task run.
type Runner struct {
	// Exec is the per-kind step executor.
	exec *Executor

	// Job context (set by the job scheduler before Run): present when the
	// run is a scheduled job instance, so a reboot resume knows how to
	// report back (JOB_RUN_RESULT vs TASK_RUN_RESULT).
	JobID      string
	JobTrigger string
	MaxRunS    int32

	rebootHook  RebootHook
	rebootAbort RebootAbort
}

// New builds a Runner with the given executor (and its dependencies).
func New(exec *Executor) *Runner {
	return &Runner{exec: exec}
}

// SetRebootHook installs the resume-marker hook (wired by the agent).
func (r *Runner) SetRebootHook(h RebootHook) { r.rebootHook = h }

// SetRebootAbort installs the marker-discard callback (wired by the agent).
func (r *Runner) SetRebootAbort(a RebootAbort) { r.rebootAbort = a }

// Run executes the steps of a task run in order and returns the aggregate
// result. A `failed` step stops the run (remaining steps are not attempted).
// A `reboot` step stops the run with state `rebooting` after the host is
// asked to reboot (PRD §5.5 continuation handshake).
func (r *Runner) Run(ctx context.Context, run *pb.TaskRun) *Result {
	res := &Result{State: StateSucceeded}
	for i, step := range run.GetSteps() {
		// Reboot steps are orchestrated here (marker first, then the reboot
		// command) so the run can be resumed after the host comes back.
		if step.GetKind() == "reboot" {
			r.runReboot(ctx, run, i, res, step)
			return res
		}
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

// runReboot executes the reboot-step handshake (PRD §5.5):
//  1. persist the resume marker via the hook (remaining steps + results);
//  2. ask the host to reboot (after a short flush grace for the report);
//  3. report `rebooting` and stop (the host goes down; the rest runs after
//     the reboot), or, if the reboot command failed, discard the marker and
//     report `failed` (no continuation will happen).
func (r *Runner) runReboot(ctx context.Context, run *pb.TaskRun, i int, res *Result, step *pb.TaskStep) {
	sr := StepResult{Index: i, Started: time.Now().Unix()}
	if step.GetName() != "" {
		sr.Name = step.GetName()
	} else {
		sr.Name = "reboot"
	}
	// 1. Marker first: without it the remaining steps are lost on reboot.
	if r.rebootHook != nil {
		if err := r.rebootHook(ctx, &RebootCtx{
			Run: run, JobID: r.JobID, JobTrigger: r.JobTrigger,
			MaxRunS: r.MaxRunS, RebootIndex: i, Done: res.Steps,
		}); err != nil {
			sr.Finished = time.Now().Unix()
			res.Steps = append(res.Steps, srWith(sr, StateFailed, "marker: "+err.Error()))
			res.State = StateFailed
			res.Error = fmt.Sprintf("step %d (reboot) failed: %s", i, err.Error())
			return
		}
	}
	// 2. Reboot (grace sleep + command happen inside DoReboot).
	state, detail := r.exec.DoReboot(ctx)
	sr.Finished = time.Now().Unix()
	switch state {
	case StateChanged, StateOK:
		sr.State = StateChanged
		sr.Detail = detail
		res.Steps = append(res.Steps, sr)
		res.State = StateRebooting
		res.Error = detail
		return
	default:
		sr.State = StateFailed
		sr.Detail = detail
		res.Steps = append(res.Steps, sr)
		res.State = StateFailed
		res.Error = fmt.Sprintf("step %d (reboot) failed: %s", i, detail)
		// 3. The host is still up: discard the marker (no resume needed).
		if r.rebootAbort != nil {
			r.rebootAbort(run.GetRunId())
		}
	}
}
