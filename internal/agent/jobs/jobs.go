// Package jobs implements the agent-side scheduled job scheduler (M3, PRD §5.4).
//
// The server resolves a job's selector to concrete hosts and pushes a
// JobAssignment (cron + task steps) to each. The agent runs each job on its
// own clock (robfig/cron), so a server outage or partition does not stop
// scheduled work. Each run reports a JobRunResult (up) that the server
// records as a job_run row (lineage) + audit event.
//
// Persisted: assignments are written to <data>/jobs.json (0600) so a restart
// resumes the same schedule (no server round-trip required).
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/blawesom/partout/internal/agent/task"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/robfig/cron/v3"
)

// Assignment is the persisted per-host job schedule.
type Assignment struct {
	JobID            string         `json:"job_id"`
	Name             string         `json:"name"`
	Cron             string         `json:"cron"`
	Timezone         string         `json:"timezone"`
	TaskID           string         `json:"task_id"`
	TaskVersion      int32          `json:"task_version"`
	Steps            []*pb.TaskStep `json:"steps"`
	MaxRunS          int32          `json:"max_run_s"`
	OverlapPolicy    string         `json:"overlap_policy"` // allow | skip | replace
	FailurePolicy    string         `json:"failure_policy"` // no_retry | retry
	RetryBackoffS    int32          `json:"retry_backoff_s"`
	SelectorSnapshot string         `json:"selector_snapshot"`
	Version          int64          `json:"version"`
}

// Report is a job run outcome sent up to the server.
type Report struct {
	RunID       string
	JobID       string
	State       string // succeeded | failed | timeout
	Error       string
	ScheduledAt int64
	StartedAt   int64
	FinishedAt  int64
	Trigger     string // cron | manual | resume
	RetryOf     int32
}

// runState tracks in-flight job runs for overlap policy.
type runState struct {
	running bool
	cancel  context.CancelFunc
}

// Scheduler runs assigned jobs on the agent's own clock.
type Scheduler struct {
	dataDir  string
	exec     *task.Executor
	log      *log.Logger
	cron     *cron.Cron
	reportFn func(*Report) // send JobRunResult up (wired by agent)

	mu        sync.Mutex
	assigns   map[string]*Assignment  // job_id -> assignment
	runStates map[string]*runState    // job_id -> in-flight state
	entries   map[string]cron.EntryID // job_id -> cron entry
}

// New builds a Scheduler. exec must be the shared task executor (so secrets
// + facts are available). reportFn is called with each job run outcome.
func New(dataDir string, exec *task.Executor, reportFn func(*Report), lg *log.Logger) *Scheduler {
	if lg == nil {
		lg = log.Default()
	}
	c := cron.New(cron.WithLocation(time.UTC))
	return &Scheduler{
		dataDir:   dataDir,
		exec:      exec,
		log:       lg,
		cron:      c,
		reportFn:  reportFn,
		assigns:   make(map[string]*Assignment),
		runStates: make(map[string]*runState),
		entries:   make(map[string]cron.EntryID),
	}
}

// SetFacts updates the executor's fact set (called on facts receipt).
func (s *Scheduler) SetFacts(f map[string]string) { s.exec.SetFacts(f) }

// PersistPath returns the on-disk assignments file.
func (s *Scheduler) PersistPath() string {
	return filepath.Join(s.dataDir, "jobs.json")
}

// Load restores persisted assignments and schedules them (called at startup).
func (s *Scheduler) Load() error {
	data, err := os.ReadFile(s.PersistPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no jobs yet
		}
		return fmt.Errorf("jobs: load: %w", err)
	}
	var list []*Assignment
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("jobs: unmarshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range list {
		s.assigns[a.JobID] = a
		_ = s.scheduleLocked(a)
	}
	s.log.Printf("jobs: restored %d assignments", len(list))
	return nil
}

// Apply installs/updates a job assignment (from JOB_ASSIGN down envelope).
func (s *Scheduler) Apply(a *Assignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Replace any existing entry.
	if old, ok := s.entries[a.JobID]; ok {
		s.cron.Remove(old)
		delete(s.entries, a.JobID)
	}
	s.assigns[a.JobID] = a
	if err := s.scheduleLocked(a); err != nil {
		delete(s.assigns, a.JobID)
		return err
	}
	return s.persistLocked()
}

// Remove deletes a job assignment (from JOB_UNASSIGN down envelope).
func (s *Scheduler) Remove(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.entries[jobID]; ok {
		s.cron.Remove(old)
		delete(s.entries, jobID)
	}
	delete(s.assigns, jobID)
	rs, ok := s.runStates[jobID]
	if ok && rs.cancel != nil {
		rs.cancel()
	}
	delete(s.runStates, jobID)
	_ = s.persistLocked()
}

// Start begins the cron loop.
func (s *Scheduler) Start() { s.cron.Start() }

// Stop halts the scheduler.
func (s *Scheduler) Stop() { s.cron.Stop() }

// List returns a copy of the current assignments.
func (s *Scheduler) List() []*Assignment {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Assignment, 0, len(s.assigns))
	for _, a := range s.assigns {
		out = append(out, a)
	}
	return out
}

// RunNow manually triggers a job (trigger="manual").
func (s *Scheduler) RunNow(jobID string) error {
	s.mu.Lock()
	a, ok := s.assigns[jobID]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("jobs: no assignment for %s", jobID)
	}
	go s.fire(a, time.Now(), "manual", 0)
	return nil
}

// scheduleLocked registers a cron entry for the assignment. Caller holds mu.
func (s *Scheduler) scheduleLocked(a *Assignment) error {
	loc := time.UTC
	if a.Timezone != "" {
		if l, err := time.LoadLocation(a.Timezone); err == nil {
			loc = l
		}
	}
	// Build a parser for the cron expression's location.
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	if _, err := parser.Parse(a.Cron); err != nil {
		return fmt.Errorf("jobs: bad cron %q: %w", a.Cron, err)
	}
	id, err := s.cron.AddFunc(a.Cron, func() {
		s.fire(a, time.Now(), "cron", 0)
	})
	if err != nil {
		return fmt.Errorf("jobs: add cron entry: %w", err)
	}
	s.entries[a.JobID] = id
	s.log.Printf("jobs: scheduled %s (%s %s)", a.JobID, a.Cron, loc)
	return nil
}

// fire runs one job instance. Overlap policy is honored; failure retry is
// applied per the failure policy.
func (s *Scheduler) fire(a *Assignment, schedAt time.Time, trigger string, retry int) {
	s.mu.Lock()
	rs := s.runStates[a.JobID]
	if rs == nil {
		rs = &runState{}
		s.runStates[a.JobID] = rs
	}
	// Overlap policy.
	switch a.OverlapPolicy {
	case "skip":
		if rs.running {
			s.mu.Unlock()
			s.log.Printf("jobs: %s skip (previous run in flight)", a.JobID)
			s.report(&Report{JobID: a.JobID, State: "skipped", ScheduledAt: schedAt.Unix(), Trigger: trigger, RetryOf: int32(retry)})
			return
		}
	case "replace":
		if rs.running && rs.cancel != nil {
			rs.cancel()
		}
	default: // "allow" — run regardless.
	}
	ctx, cancel := context.WithTimeout(context.Background(), runDeadline(a.MaxRunS))
	rs.running = true
	rs.cancel = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		rs.running = false
		rs.cancel = nil
		s.mu.Unlock()
	}()

	// Execute the task.
	runID := fmt.Sprintf("jr_%s_%d", a.JobID, schedAt.UnixNano())
	taskRun := &pb.TaskRun{
		RunId:       runID,
		TaskId:      a.TaskID,
		TaskVersion: a.TaskVersion,
		Steps:       a.Steps,
	}
	started := time.Now()
	runner := task.New(s.exec)
	res := runner.Run(ctx, taskRun)
	finished := time.Now()

	state := res.State
	if ctx.Err() == context.DeadlineExceeded && res.State != task.StateSucceeded {
		state = "timeout"
		if res.Error == "" {
			res.Error = "job run exceeded max_run_s"
		}
	}
	report := &Report{
		RunID:       runID,
		JobID:       a.JobID,
		State:       state,
		Error:       res.Error,
		ScheduledAt: schedAt.Unix(),
		StartedAt:   started.Unix(),
		FinishedAt:  finished.Unix(),
		Trigger:     trigger,
		RetryOf:     int32(retry),
	}
	s.report(report)

	// Failure retry.
	if state == "failed" && a.FailurePolicy == "retry" && a.RetryBackoffS > 0 && retry < 3 {
		s.log.Printf("jobs: %s failed, retry in %ds (attempt %d)", a.JobID, a.RetryBackoffS, retry+1)
		go func() {
			time.Sleep(time.Duration(a.RetryBackoffS) * time.Second)
			s.fire(a, time.Now(), "cron", retry+1)
		}()
	}
}

// report sends a job run outcome up (no-op if reportFn unset).
func (s *Scheduler) report(r *Report) {
	if s.reportFn != nil {
		s.reportFn(r)
	}
}

// runDeadline converts max_run_s to a duration (default 30 min).
func runDeadline(maxRunS int32) time.Duration {
	if maxRunS <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(maxRunS) * time.Second
}

// persistLocked writes the assignments to disk. Caller holds mu.
func (s *Scheduler) persistLocked() error {
	list := make([]*Assignment, 0, len(s.assigns))
	for _, a := range s.assigns {
		list = append(list, a)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("jobs: marshal: %w", err)
	}
	_ = os.MkdirAll(s.dataDir, 0o700)
	tmp := s.PersistPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("jobs: write: %w", err)
	}
	return os.Rename(tmp, s.PersistPath())
}
