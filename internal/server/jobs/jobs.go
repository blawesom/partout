// Package jobs implements the server-side scheduled job controller (M3,
// PRD §5.4). Jobs are (selector, schedule, task). The server resolves the
// selector to concrete hosts at save/update time, pushes a per-host schedule
// (JobAssignment) to each, and records job runs (lineage) + audit when
// agents report them. Agents run the schedule on their own clock, so the
// server being down does not stop scheduled work.
//
// Policy: job create/update/RunNow are gated under the task.run action
// class (PRD §5.5, arch §5.3). Each per-host assignment carries a signed
// Decision (run_id = job id, a standing authorization bound to the job +
// bundle version); the agent re-checks it via the guardrail before every
// fire and fails closed on mismatch. Denied jobs are rejected before any
// state is persisted.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// Controller manages scheduled jobs.
type Controller struct {
	st    *store.Store
	h     *stream.Handler
	sse   *sse.Broker
	log   *log.Logger
	ident *certutil.ServerIdentity
}

// New builds a Controller.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{st: st, h: h, sse: sseB, log: lg}
}

// SetIdentity installs the server's Ed25519 signing key (signs job
// Decisions, like tasks/packages/files/sessions).
func (c *Controller) SetIdentity(ident *certutil.ServerIdentity) { c.ident = ident }

// Actor carries the requester identity for audit + policy.
type Actor struct {
	Principal string
	Role      string
}

// PolicyError is returned when a job write is rejected by the policy
// deny-list (the task.run action class). The API layer maps it to 403.
type PolicyError struct {
	Reason string
}

func (e *PolicyError) Error() string { return "job denied by policy: " + e.Reason }

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
func (c *Controller) Create(ctx context.Context, spec Job, actor Actor) (*store.Job, error) {
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

	jobID := id.New("job")
	// Policy gate BEFORE persisting: every host the selector matches must
	// be allowed to run task.run. A denied host rejects the whole write
	// (fail closed; no orphan job row, nothing assigned).
	decisions, err := c.gatePolicy(jobID, spec.Selector, actor.Role)
	if err != nil {
		return nil, err
	}

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

	if _, err := c.resolveAndPush(job, spec, steps, decisions); err != nil {
		// Leave the job row (operator can fix + re-save); report the error.
		c.log.Printf("jobs: resolve %s: %v", jobID, err)
		return job, fmt.Errorf("jobs: resolve selector: %w", err)
	}
	c.audit("create", jobID, spec.Selector, 0)
	return job, nil
}

// Update modifies a job and re-resolves + re-pushes (PRD §5.4 acceptance:
// editing a selector re-resolves and re-pushes per-host schedules).
func (c *Controller) Update(ctx context.Context, jobID string, spec Job, actor Actor) (*store.Job, error) {
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

	// Policy gate BEFORE mutating: re-authorization is required on every
	// save (a fresh signed Decision per host, bound to the current bundle
	// version). Denied → no change is persisted.
	decisions, err := c.gatePolicy(jobID, spec.Selector, actor.Role)
	if err != nil {
		return nil, err
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
	current, err := c.resolveAndPush(job, spec, steps, decisions)
	if err != nil {
		return job, fmt.Errorf("jobs: resolve selector: %w", err)
	}
	// Editing a selector can drop hosts: unassign them so they stop firing
	// (PRD §5.4 acceptance) and discard their signed decision.
	c.reconcileAssignments(jobID, current)
	c.audit("update", jobID, spec.Selector, len(current))
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
// per-host schedule to each (with the pre-gated signed Decision per host).
// Records the selector snapshot on each assignment and returns the set of
// agent ids that currently belong to the job.
func (c *Controller) resolveAndPush(job *store.Job, spec Job, steps []store.TaskStep, decisions map[string]*pb.Decision) (map[string]bool, error) {
	// Resolve the selector to agent ids.
	r := store.NewResolver(c.st)
	agentsList, err := r.ResolveSelector(spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("resolve selector %q: %w", spec.Selector, err)
	}
	if len(agentsList) == 0 {
		c.log.Printf("jobs: %s: selector %q matched no hosts", job.ID, spec.Selector)
	}
	current := make(map[string]bool, len(agentsList))
	tz := spec.Timezone
	if tz == "" {
		tz = "UTC"
	}
	version := job.Updated // monotonic-ish version (bumps on edit)
	for _, agentInfo := range agentsList {
		agentID := agentInfo.ID
		current[agentID] = true
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
			Steps:            toPBSteps(steps),
			MaxRunS:          int32(job.MaxRunSeconds),
			OverlapPolicy:    spec.OverlapPolicy,
			FailurePolicy:    spec.FailurePolicy,
			RetryBackoffS:    int32(spec.RetryBackoffS),
			SelectorSnapshot: spec.Selector,
			Version:          version,
			Decision:         decisions[agentID],
		}
		// Push to the agent (best-effort; offline agents get it on reconnect
		// via the server's down-queue in a later milestone).
		if c.h != nil {
			if err := c.h.SendJobAssign(agentID, ja); err != nil {
				c.log.Printf("jobs: push %s -> %s: %v", job.ID, agentID, err)
			}
		}
	}
	return current, nil
}

// reconcileAssignments drops and unassigns hosts that no longer match the
// job's selector (PRD §5.4: editing a selector re-resolves the fleet). It
// must run before/with the push so a host removed from the selector stops
// firing — and, once the agent removes the assignment, discards its signed
// decision. Hosts that remain keep their freshly pushed assignment.
func (c *Controller) reconcileAssignments(jobID string, current map[string]bool) {
	assigned, err := c.st.JobAssignmentsForJob(jobID)
	if err != nil {
		c.log.Printf("jobs: reconcile %s: assignments: %v", jobID, err)
		return
	}
	for _, a := range assigned {
		if current[a.AgentID] {
			continue
		}
		if err := c.st.UnassignJob(jobID, a.AgentID); err != nil {
			c.log.Printf("jobs: unassign %s -> %s: %v", jobID, a.AgentID, err)
			continue
		}
		if c.h != nil {
			if err := c.h.SendJobUnassign(a.AgentID, jobID); err != nil {
				c.log.Printf("jobs: push unassign %s -> %s: %v", jobID, a.AgentID, err)
			}
		}
		c.log.Printf("jobs: %s unassigned from %s (no longer matches the selector)", jobID, a.AgentID)
	}
}

// gatePolicy resolves the selector and evaluates the task.run action class
// for every matched host. Returns a per-host signed Decision map (run_id =
// job id: a standing authorization bound to this job + the current bundle
// version). If any host is denied, returns a *PolicyError naming the hosts.
// Evaluation happens BEFORE any job state is persisted, so a denied write
// leaves the store untouched.
func (c *Controller) gatePolicy(jobID, selector, actorRole string) (map[string]*pb.Decision, error) {
	// Fail closed without a signing identity: a job that cannot carry a
	// verifiable Decision would be denied by the agent at fire time, so
	// reject the write with a clear misconfiguration error instead.
	if c.ident == nil {
		return nil, fmt.Errorf("jobs: server signing identity not configured; cannot authorize task.run")
	}
	r := store.NewResolver(c.st)
	agents, err := r.ResolveSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("resolve selector %q: %w", selector, err)
	}
	d := make(map[string]*pb.Decision, len(agents))
	var denied []string
	for _, a := range agents {
		host, _ := c.st.Agent(a.ID)
		act := policy.Action{
			ActorRole:   actorRole,
			ActionClass: policy.ActionTaskRun,
		}
		if host != nil {
			act.HostID = host.ID
			if tags, _ := c.st.Tags(a.ID); len(tags) > 0 {
				act.HostTags = tags
			}
			if roles, _ := c.st.Roles(a.ID); len(roles) > 0 {
				act.HostRoles = roles
			}
		}
		decision, reason, ok := c.signTaskRunDecision(jobID, actorRole, act)
		if !ok {
			denied = append(denied, fmt.Sprintf("%s (%s)", a.ID, reason))
			continue
		}
		d[a.ID] = decision
	}
	if len(denied) > 0 {
		return nil, &PolicyError{Reason: "task.run denied for host(s) " + strings.Join(denied, ", ")}
	}
	return d, nil
}

// signTaskRunDecision evaluates the task.run action class and, when allowed,
// signs a Decision bound to runID. ok=false means the policy denied it
// (reason carries the denial reason).
func (c *Controller) signTaskRunDecision(runID, actorRole string, act policy.Action) (*pb.Decision, string, bool) {
	if c.ident == nil {
		// Callers gate on this up front; keep the failure closed.
		return nil, "server signing identity not configured", false
	}
	rules, _ := c.st.GetPolicyRules()
	decision := policy.Evaluate(rules, act)
	if decision.Effect != policy.EffectAllow {
		return nil, decision.Reason, false
	}
	version, _ := c.st.PolicyBundleVersion()
	sig := policy.SignDecision(c.ident.Priv, runID, version,
		decision.Effect, decision.MatchedRules, actorRole)
	return &pb.Decision{
		RunId:         runID,
		BundleVersion: version,
		Effect:        decision.Effect,
		MatchedRules:  decision.MatchedRules,
		Sig:           sig,
		ActorRole:     actorRole,
	}, "", true
}

// toPBSteps converts store task steps to the wire format.
func toPBSteps(steps []store.TaskStep) []*pb.TaskStep {
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
	return pbSteps
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

// RunNow triggers an immediate run of a job on one host. Like manual
// task.run, it is gated under the task.run action class: a denied host
// records a 'denied' run and the dispatch never happens.
func (c *Controller) RunNow(ctx context.Context, jobID, agentID string, actor Actor) error {
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
	runID := id.New("jr")

	// Fail closed without a signing identity (see gatePolicy).
	if c.ident == nil {
		return fmt.Errorf("jobs: server signing identity not configured; cannot authorize task.run")
	}

	// Policy gate: sign a fresh per-run decision for this host.
	host, _ := c.st.Agent(agentID)
	act := policy.Action{
		ActorRole:   actor.Role,
		ActionClass: policy.ActionTaskRun,
	}
	if host != nil {
		act.HostID = host.ID
		if tags, _ := c.st.Tags(agentID); len(tags) > 0 {
			act.HostTags = tags
		}
		if roles, _ := c.st.Roles(agentID); len(roles) > 0 {
			act.HostRoles = roles
		}
	}
	decision, _, ok := c.signTaskRunDecision(runID, actor.Role, act)
	if !ok {
		_ = c.st.CreateJobRun(&store.JobRun{
			ID: runID, JobID: jobID, AgentID: agentID,
			TaskID: job.TaskID, TaskVersion: job.TaskVersion,
			ScheduledAt: time.Now().Unix(), Trigger: "manual", State: "denied",
			Error: "denied by policy",
		})
		_ = c.st.FinalizeJobRun(runID, "denied", "denied by policy")
		c.audit("run-denied", jobID, "", 0)
		return &PolicyError{Reason: "task.run denied for host " + agentID}
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
		Steps:       toPBSteps(steps),
		Decision:    decision,
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
