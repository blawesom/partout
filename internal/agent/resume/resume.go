// Package resume implements the post-reboot task continuation handshake
// (PRD §5.5, the `reboot` step kind).
//
// When a task run reaches a `reboot` step, the agent's task Runner persists
// a resume marker (remaining steps + results so far + the signed decision)
// under <data>/resume/<runID>.json, then the host reboots. When the agent
// starts back up and the first policy bundle has loaded, ResumePending:
//
//  1. verifies the host actually booted AFTER the marker was written
//     (uptime < age-of-marker); a marker on a host that never rebooted is
//     stale (the reboot command failed) and the run is reported failed;
//  2. re-checks the run's signed policy decision via the guardrail —
//     fail-closed on a missing/stale/denied decision;
//  3. executes the remaining steps;
//  4. reports the result (trigger "resume") — a JOB_RUN_RESULT for
//     scheduled-job runs, a TASK_RUN_RESULT for manual task runs;
//  5. deletes the marker.
package resume

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/blawesom/partout/internal/agent/guardrail"
	"github.com/blawesom/partout/internal/agent/jobs"
	"github.com/blawesom/partout/internal/agent/task"
	pb "github.com/blawesom/partout/internal/proto"
)

// Kind values.
const (
	KindTask = "task" // manual TASK_RUN dispatch
	KindJob  = "job"  // scheduled job run (JOB_ASSIGN)
)

// DoneStep is a completed step result carried in the marker.
type DoneStep struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Detail   string `json:"detail"`
	Started  int64  `json:"started"`
	Finished int64  `json:"finished"`
}

// Marker is one pending post-reboot continuation.
type Marker struct {
	RunID       string `json:"run_id"`
	Kind        string `json:"kind"` // "task" | "job"
	JobID       string `json:"job_id,omitempty"`
	TaskID      string `json:"task_id"`
	TaskVersion int32  `json:"task_version"`
	// StartIdx is the index of the reboot step; the remaining steps start
	// at StartIdx+1 (used to re-index step results in the resume report).
	StartIdx  int            `json:"start_idx"`
	Steps     []*pb.TaskStep `json:"steps"` // remaining steps after the reboot step
	DoneSteps []DoneStep     `json:"done_steps"`
	MaxRunS   int32          `json:"max_run_s"`
	Decision  *pb.Decision   `json:"decision,omitempty"`
	CreatedAt int64          `json:"created_at"`
}

// Store persists markers under <dir>/<runID>.json.
type Store struct{ dir string }

var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// NewStore creates (if needed) the marker directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("resume: mkdir %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Path returns the marker directory.
func (s *Store) Path() string { return s.dir }

// Save writes one marker (atomic tmp+rename, 0600).
func (s *Store) Save(m *Marker) error {
	if !safeID.MatchString(m.RunID) {
		return fmt.Errorf("resume: unsafe run id %q", m.RunID)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("resume: marshal: %w", err)
	}
	tmp := filepath.Join(s.dir, m.RunID+".json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("resume: write: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, m.RunID+".json")); err != nil {
		return fmt.Errorf("resume: rename: %w", err)
	}
	return nil
}

// List returns all pending markers.
func (s *Store) List() ([]*Marker, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("resume: list: %w", err)
	}
	var out []*Marker
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var m Marker
		if err := json.Unmarshal(data, &m); err != nil {
			continue // unreadable marker; left in place for inspection
		}
		out = append(out, &m)
	}
	return out, nil
}

// Delete removes one marker.
func (s *Store) Delete(runID string) error {
	if !safeID.MatchString(runID) {
		return fmt.Errorf("resume: unsafe run id %q", runID)
	}
	err := os.Remove(filepath.Join(s.dir, runID+".json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Resumer resumes pending continuations after a reboot.
type Resumer struct {
	store      *Store
	exec       *task.Executor
	guard      *guardrail.Guard
	log        *log.Logger
	hook       task.RebootHook // applied to resumed runners (chained reboots)
	abort      task.RebootAbort
	reportJob  func(*jobs.Report)
	reportTask func(runID, state, errMsg string, steps []*pb.TaskStepResult)
	bootAge    func() (time.Duration, bool)
}

// New builds a Resumer. reportJob/reportTask send the final result up the
// stream (wire the agent's sendJobResult/sendTaskResult).
func New(store *Store, exec *task.Executor, guard *guardrail.Guard,
	hook task.RebootHook, abort task.RebootAbort,
	reportJob func(*jobs.Report),
	reportTask func(runID, state, errMsg string, steps []*pb.TaskStepResult),
	lg *log.Logger) *Resumer {
	if lg == nil {
		lg = log.Default()
	}
	return &Resumer{
		store: store, exec: exec, guard: guard, log: lg,
		hook: hook, abort: abort,
		reportJob: reportJob, reportTask: reportTask,
		bootAge: BootAge,
	}
}

// SetBootAge overrides the uptime source (tests simulate a fresh boot).
func (r *Resumer) SetBootAge(fn func() (time.Duration, bool)) { r.bootAge = fn }

// BootAge reads the system boot age from /proc/uptime.
func BootAge() (time.Duration, bool) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	s := string(b)
	if i := indexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return time.Duration(v * float64(time.Second)), true
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// ResumePending processes every pending marker. It must run after the first
// policy bundle has loaded (the guardrail re-check is fail-closed until
// then). Safe to call more than once: processed markers are deleted.
func (r *Resumer) ResumePending() {
	markers, err := r.store.List()
	if err != nil {
		r.log.Printf("resume: list markers: %v", err)
		return
	}
	for _, m := range markers {
		r.resumeOne(m)
	}
}

func (r *Resumer) resumeOne(m *Marker) {
	// 1. Did the host actually boot after the marker was written?
	age, ok := r.bootAge()
	ageOfMarker := time.Since(time.Unix(m.CreatedAt, 0))
	if !ok {
		r.failMarker(m, "cannot verify reboot (system uptime unreadable)")
		return
	}
	if age >= ageOfMarker {
		// The host has been up longer than the marker is old: the reboot
		// never happened (the reboot command failed on the previous run,
		// or the marker is from a long-gone run).
		r.failMarker(m, "host did not reboot after the resume marker (reboot command failed?)")
		return
	}
	r.log.Printf("resume: %s: host booted %v ago, marker %v old — resuming",
		m.RunID, truncateDur(age), truncateDur(ageOfMarker))

	// 2. Policy re-check (fail closed).
	if !r.guard.Loaded() {
		// No bundle yet: keep the marker; the next bundle push re-triggers.
		r.log.Printf("resume: %s: policy bundle not loaded yet; deferring", m.RunID)
		return
	}
	tr := &pb.TaskRun{
		RunId: m.RunID, TaskId: m.TaskID, TaskVersion: m.TaskVersion,
		Steps: m.Steps, Decision: m.Decision,
	}
	if ok, reason := r.guard.RecheckTask(tr); !ok {
		r.failMarker(m, "resume denied by policy: "+reason)
		return
	}

	// 3. Execute the remaining steps.
	deadline := 30 * time.Minute
	if m.MaxRunS > 0 {
		deadline = time.Duration(m.MaxRunS) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	runner := task.New(r.exec)
	if r.hook != nil {
		runner.SetRebootHook(r.hook) // a chained reboot re-markers the run
	}
	if r.abort != nil {
		runner.SetRebootAbort(r.abort)
	}
	runner.JobID = m.JobID
	runner.MaxRunS = m.MaxRunS
	res := runner.Run(ctx, tr)

	state := res.State
	if ctx.Err() == context.DeadlineExceeded && res.State != task.StateSucceeded {
		state = "timeout"
	}

	// 4. Report (same run id; trigger "resume").
	now := time.Now().Unix()
	switch m.Kind {
	case KindJob:
		if r.reportJob != nil {
			r.reportJob(&jobs.Report{
				RunID: m.RunID, JobID: m.JobID, State: state, Error: res.Error,
				ScheduledAt: m.CreatedAt, StartedAt: now, FinishedAt: now,
				Trigger: "resume",
			})
		}
	default:
		if r.reportTask != nil {
			steps := make([]*pb.TaskStepResult, 0, len(m.DoneSteps)+len(res.Steps))
			for _, d := range m.DoneSteps {
				steps = append(steps, &pb.TaskStepResult{
					StepIndex: int32(d.Index), State: d.State, Detail: d.Detail,
					Started: d.Started, Finished: d.Finished,
				})
			}
			for i, s := range res.Steps {
				steps = append(steps, &pb.TaskStepResult{
					StepIndex: int32(m.StartIdx + 1 + i), State: s.State, Detail: s.Detail,
					Started: s.Started, Finished: s.Finished,
				})
			}
			r.reportTask(m.RunID, state, res.Error, steps)
		}
	}
	r.log.Printf("resume: %s finished: %s %s", m.RunID, state, res.Error)

	// 5. Done.
	_ = r.store.Delete(m.RunID)
}

// failMarker reports the run as failed and deletes the marker.
func (r *Resumer) failMarker(m *Marker, reason string) {
	r.log.Printf("resume: %s: %s", m.RunID, reason)
	now := time.Now().Unix()
	switch m.Kind {
	case KindJob:
		if r.reportJob != nil {
			r.reportJob(&jobs.Report{
				RunID: m.RunID, JobID: m.JobID, State: "failed", Error: reason,
				ScheduledAt: m.CreatedAt, StartedAt: now, FinishedAt: now,
				Trigger: "resume",
			})
		}
	default:
		if r.reportTask != nil {
			r.reportTask(m.RunID, "failed", reason, nil)
		}
	}
	_ = r.store.Delete(m.RunID)
}

func truncateDur(d time.Duration) string {
	if d > 30*24*time.Hour {
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	}
	return d.Round(time.Second).String()
}
