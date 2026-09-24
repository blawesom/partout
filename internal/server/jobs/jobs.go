// Package jobs implements the server-side scheduled job controller (M3,
// PRD §5.4). Jobs are (selector, schedule, task). The server resolves the
// selector to concrete hosts at save/update time, pushes a per-host schedule
// (JobAssignment) to each, and records job runs (lineage) + audit when
// agents report them. Agents run the schedule on their own clock, so the
// server being down does not stop scheduled work.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/blawesom/partout/internal/id"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// Controller manages scheduled jobs.
type Controller struct {
	st  *store.Store
	h   *stream.Handler
	sse *sse.Broker
	log *log.Logger
}

// New builds a Controller.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{st: st, h: h, sse: sseB, log: lg}
}

// Job is the API-facing job spec (mirrors store.Job + selector).
type Job struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	TaskID        string `json:"task_id"`
	TaskVersion   int    `json:"task_version"` // 0 = latest
	Cron          string `json:"cron"`
	Timezone      string `json:"timezone"` // IANA tz (default UTC)
	Selector      string `json:"selector"`
	MaxRunS       int    `json:"max_run_s"`
	OverlapPolicy string `json:"overlap_policy"` // allow | skip | replace (default skip)
	FailurePolicy string `json:"failure_policy"` // no_retry | retry
	RetryBackoffS int    `json:"retry_backoff_s"`
	Enabled       bool   `json:"enabled"`
}

// create resolves the selector, saves the job, and pushes per-host schedules.
func (c *Controller) Create(ctx context.Context, spec Job) (*store.Job, error) {
	// Resolve the task version.
	taskVer := spec.TaskVersion
	if taskVer == 0 {
		v, err := c.st.LatestTaskVersion(spec.TaskID)
		if err != nil || v == nil {
			return nil, fmt.Errorf("jobs: no version for task %s", spec.TaskID)
		}
		taskVer = v.Version
	}
	// Load steps for the assignment.
	ver, err := c.st.TaskVersion(spec.TaskID, taskVer)
	if err != nil || ver == nil {
		return nil, fmt.Errorf("jobs: task %s v%d not found", spec.TaskID, taskVer)
	}
	steps, err := store.DecodeTaskSteps(ver.StepsJSON)
	if err != nil {
		return nil, fmt.Errorf("jobs: decode steps: %w", err)
	}
	pbSteps := make([]*pb.TaskStep, 0, len(steps))
	for _, s := range steps {
		pbSteps = append(pbSteps, &pb.TaskStep{
			Kind: s.Kind, Name: s.Name, When: s.When,
			Command: s.Command, Args: s.Args, Env: s.Env,
			Path: s.Path, Content: s.Content, Template: s.Template, Vars: s.Vars,
			Mode: s.Mode, Package: s.Package, State: s.State,
			Service: s.Service, User: s.User, Group: s.Group, Expr: s.Expr,
		})
	}

	jobID := id.New("job")
	job := &store.Job{
		ID:            jobID,
		Name:          spec.Name,
		TaskID:        spec.TaskID,
		TaskVersion:   taskVer,
		Cron:          spec.Cron,
		Selector:      spec.Selector,
		MaxRunSeconds: spec.MaxRunS,
		Enabled:       spec.Enabled,
	}
	if err := c.st.CreateJob(job); err != nil {
		return nil, fmt.Errorf("jobs: create: %w", err)
	}

	if err := c.resolveAndPush(job, spec, pbSteps); err != nil {
		// Leave the job row (operator can fix + re-save); report the error.
		c.log.Printf("jobs: resolve %s: %v", jobID, err)
		return job, fmt.Errorf("jobs: resolve selector: %w", err)
	}
	c.audit("create", jobID, spec.Selector, 0)
	return job, nil
}

// Update modifies a job and re-resolves + re-pushes (PRD §5.4 acceptance:
// editing a selector re-resolves and re-pushes per-host schedules).
func (c *Controller) Update(ctx context.Context, jobID string, spec Job) (*store.Job, error) {
	job, err := c.st.GetJob(jobID)
	if err != nil || job == nil {
		return nil, fmt.Errorf("jobs: %s not found", jobID)
	}
	// Preserve fields not in the spec.
	if spec.Name == "" {
		spec.Name = job.Name
	}
	if spec.TaskID == "" {
		spec.TaskID = job.TaskID
	}
	if spec.Cron == "" {
		spec.Cron = job.Cron
	}
	if spec.Selector == "" {
		spec.Selector = job.Selector
	}
	if spec.TaskVersion == 0 {
		spec.TaskVersion = job.TaskVersion
	}
	if spec.MaxRunS == 0 {
		spec.MaxRunS = job.MaxRunSeconds
	}
	if spec.OverlapPolicy == "" {
		spec.OverlapPolicy = "skip"
	}
	if spec.FailurePolicy == "" {
		spec.FailurePolicy = "no_retry"
	}
	if spec.Enabled == false {
		spec.Enabled = job.Enabled
	}

	taskVer := spec.TaskVersion
	if taskVer == 0 {
		v, _ := c.st.LatestTaskVersion(spec.TaskID)
		if v != nil {
			taskVer = v.Version
		}
	}
	ver, err := c.st.TaskVersion(spec.TaskID, taskVer)
	if err != nil || ver == nil {
		return nil, fmt.Errorf("jobs: task %s v%d not found", spec.TaskID, taskVer)
	}
	steps, err := store.DecodeTaskSteps(ver.StepsJSON)
	if err != nil {
		return nil, fmt.Errorf("jobs: decode steps: %w", err)
	}
	pbSteps := make([]*pb.TaskStep, 0, len(steps))
	for _, s := range steps {
		pbSteps = append(pbSteps, &pb.TaskStep{
			Kind: s.Kind, Name: s.Name, When: s.When,
			Command: s.Command, Args: s.Args, Env: s.Env,
			Path: s.Path, Content: s.Content, Template: s.Template, Vars: s.Vars,
			Mode: s.Mode, Package: s.Package, State: s.State,
			Service: s.Service, User: s.User, Group: s.Group, Expr: s.Expr,
		})
	}

	job.Name = spec.Name
	job.TaskID = spec.TaskID
	job.TaskVersion = taskVer
	job.Cron = spec.Cron
	job.Selector = spec.Selector
	job.MaxRunSeconds = spec.MaxRunS
	job.Enabled = spec.Enabled
	if err := c.st.UpdateJob(job); err != nil {
		return nil, fmt.Errorf("jobs: update: %w", err)
	}
	if err := c.resolveAndPush(job, spec, pbSteps); err != nil {
		return job, fmt.Errorf("jobs: resolve selector: %w", err)
	}
	c.audit("update", jobID, spec.Selector, 0)
	return job, nil
}

// Delete removes a job + unassigns from all hosts.
func (c *Controller) Delete(ctx context.Context, jobID string) error {
	assignments, _ := c.st.JobAssignmentsForJob(jobID)
	for _, a := range assignments {
		_ = c.st.UnassignJob(jobID, a.AgentID)
		if c.h != nil {
			_ = c.h.SendJobUnassign(a.AgentID, jobID)
		}
	}
	if err := c.st.DeleteJob(jobID); err != nil {
		return fmt.Errorf("jobs: delete: %w", err)
	}
	c.audit("delete", jobID, "", 0)
	return nil
}

// resolveAndPush resolves the selector to concrete agents and pushes a
// per-host schedule to each. Records the selector snapshot on each assignment.
func (c *Controller) resolveAndPush(job *store.Job, spec Job, pbSteps []*pb.TaskStep) error {
	// Resolve the selector to agent ids.
	r := store.NewResolver(c.st)
	agentsList, err := r.ResolveSelector(spec.Selector)
	if err != nil {
		return fmt.Errorf("resolve selector %q: %w", spec.Selector, err)
	}
	if len(agentsList) == 0 {
		c.log.Printf("jobs: %s: selector %q matched no hosts", job.ID, spec.Selector)
	}
	tz := spec.Timezone
	if tz == "" {
		tz = "UTC"
	}
	version := job.Updated // monotonic-ish version (bumps on edit)
	for _, agentInfo := range agentsList {
		agentID := agentInfo.ID
		a := &store.JobAssignment{JobID: job.ID, AgentID: agentID}
		if err := c.st.AssignJob(a); err != nil {
			c.log.Printf("jobs: assign %s -> %s: %v", job.ID, agentID, err)
			continue
		}
		ja := &pb.JobAssignment{
			JobId:            job.ID,
			Name:             job.Name,
			Cron:             job.Cron,
			Timezone:         tz,
			TaskId:           job.TaskID,
			TaskVersion:      int32(job.TaskVersion),
			Steps:            pbSteps,
			MaxRunS:          int32(job.MaxRunSeconds),
			OverlapPolicy:    spec.OverlapPolicy,
			FailurePolicy:    spec.FailurePolicy,
			RetryBackoffS:    int32(spec.RetryBackoffS),
			SelectorSnapshot: spec.Selector,
			Version:          version,
		}
		// Push to the agent (best-effort; offline agents get it on reconnect
		// via the server's down-queue in a later milestone).
		if c.h != nil {
			if err := c.h.SendJobAssign(agentID, ja); err != nil {
				c.log.Printf("jobs: push %s -> %s: %v", job.ID, agentID, err)
			}
		}
	}
	return nil
}

// OnRunResult records a job run + audit when an agent reports a scheduled
// job completion (wired as the stream JobRunResultHook).
func (c *Controller) OnRunResult(agentID string, r *pb.JobRunResult) {
	run := &store.JobRun{
		ID:          r.RunId,
		JobID:       r.JobId,
		AgentID:     agentID,
		TaskID:      "", // filled from job
		TaskVersion: 0,
		ScheduledAt: r.ScheduledAt,
		StartedAt:   r.StartedAt,
		FinishedAt:  r.FinishedAt,
		State:       r.State,
		Trigger:     r.Trigger,
		Error:       r.Error,
	}
	// Look up the job for task lineage.
	if job, err := c.st.GetJob(r.JobId); err == nil && job != nil {
		run.TaskID = job.TaskID
		run.TaskVersion = job.TaskVersion
	}
	if err := c.st.CreateJobRun(run); err != nil {
		c.log.Printf("jobs: create run %s: %v", r.RunId, err)
		return
	}
	// Update the assignment's last-run state.
	_ = c.st.UpdateJobAssignmentState(r.JobId, agentID, r.State, r.FinishedAt)
	c.audit("run", r.JobId, "", 0)
	// SSE event.
	if c.sse != nil {
		c.sse.Emit("job.run", map[string]any{
			"job_id": r.JobId, "agent_id": agentID,
			"state": r.State, "run_id": r.RunId,
		})
	}
}

// Get returns one job by ID.
func (c *Controller) Get(id string) (*store.Job, error) {
	return c.st.GetJob(id)
}

// List returns all jobs.
func (c *Controller) List() ([]*store.Job, error) {
	return c.st.ListJobs()
}

// RunsForJob returns the runs for one job.
func (c *Controller) RunsForJob(jobID string, limit int) ([]*store.JobRun, error) {
	return c.st.JobRunsForJob(jobID, limit)
}

// ListRuns returns recent runs across all jobs.
func (c *Controller) ListRuns(limit int) ([]*store.JobRun, error) {
	return c.st.ListJobRuns(limit)
}

// RunNow triggers an immediate run of a job on one host.
func (c *Controller) RunNow(ctx context.Context, jobID, agentID string) error {
	job, err := c.st.GetJob(jobID)
	if err != nil || job == nil {
		return fmt.Errorf("jobs: %s not found", jobID)
	}
	ver, err := c.st.TaskVersion(job.TaskID, job.TaskVersion)
	if err != nil || ver == nil {
		return fmt.Errorf("jobs: task version not found")
	}
	steps, err := store.DecodeTaskSteps(ver.StepsJSON)
	if err != nil {
		return fmt.Errorf("jobs: decode steps: %w", err)
	}
	// Dispatch a one-off task run to the agent (triggered by the job).
	runID := id.New("jr")
	pbSteps := make([]*pb.TaskStep, 0, len(steps))
	for _, s := range steps {
		pbSteps = append(pbSteps, &pb.TaskStep{
			Kind: s.Kind, Name: s.Name, When: s.When,
			Command: s.Command, Args: s.Args, Env: s.Env,
			Path: s.Path, Content: s.Content, Template: s.Template, Vars: s.Vars,
			Mode: s.Mode, Package: s.Package, State: s.State,
			Service: s.Service, User: s.User, Group: s.Group, Expr: s.Expr,
		})
	}
	// Record the manual run.
	run := &store.JobRun{
		ID: runID, JobID: jobID, AgentID: agentID,
		TaskID: job.TaskID, TaskVersion: job.TaskVersion,
		ScheduledAt: time.Now().Unix(), Trigger: "manual", State: "running",
	}
	_ = c.st.CreateJobRun(run)
	_ = c.h.SendTaskRun(agentID, &pb.TaskRun{
		RunId:       runID,
		TaskId:      job.TaskID,
		TaskVersion: int32(job.TaskVersion),
		Steps:       pbSteps,
	})
	_ = c.st.FinalizeJobRun(runID, "dispatched", "")
	c.audit("run", jobID, "", 0)
	return nil
}

// audit records a job audit event + SSE.
func (c *Controller) audit(kind, jobID, selectorText string, n int) {
	payload, _ := json.Marshal(map[string]any{
		"kind":     kind,
		"job_id":   jobID,
		"selector": selectorText,
		"hosts":    n,
	})
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: "job", Payload: string(payload),
	})
	if c.sse != nil {
		c.sse.Emit("job."+kind, map[string]any{"job_id": jobID})
	}
}
