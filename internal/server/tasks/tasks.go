// Package tasks implements the server-side task orchestration (M3, PRD §5.5).
// It dispatches task runs to agents over the stream, records results in
// the task_runs/task_run_steps tables, and emits SSE audit events.
package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// Controller dispatches task runs to agents.
type Controller struct {
	st    *store.Store
	h     *stream.Handler
	sse   *sse.Broker
	log   *log.Logger
	ident *certutil.ServerIdentity
	// approvals is the M4 approvals engine (require_approval parking).
	approvals *approvals.Controller
	// opTimeout bounds one task run over the stream.
	opTimeout time.Duration
}

// New builds a Controller.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{st: st, h: h, sse: sseB, log: lg, opTimeout: 10 * time.Minute}
}

// SetIdentity installs the server's Ed25519 signing key (signs Decisions).
func (c *Controller) SetIdentity(ident *certutil.ServerIdentity) { c.ident = ident }

// SetApprovals installs the M4 approvals engine (require_approval parking).
func (c *Controller) SetApprovals(ac *approvals.Controller) { c.approvals = ac }

// ApprovalRequiredError is returned when a task run is parked on an approval
// request (M4). The API layer maps it to 202 with the request id.
type ApprovalRequiredError struct {
	ApprovalID string
	RunID      string
}

func (e *ApprovalRequiredError) Error() string {
	return "tasks: approval required (" + e.ApprovalID + ")"
}

// Actor carries the requester identity for audit + policy.
type Actor struct {
	Principal string
	Role      string
}

// Run dispatches a task run to the specified agent (host).
// Steps are sent as proto pb.TaskStep; they must have been converted from
// the store's TaskStep type by the API layer.
func (c *Controller) Run(ctx context.Context, agentID, taskID string, version int,
	steps []*pb.TaskStep, actor Actor) (*store.TaskRun, error) {

	runID := id.New("tr")
	action := &store.TaskRun{
		ID:          runID,
		TaskID:      taskID,
		TaskVersion: version,
		AgentID:     agentID,
	}
	if err := c.st.CreateTaskRun(action); err != nil {
		return nil, fmt.Errorf("tasks: create run %s: %w", runID, err)
	}

	// Policy gate: evaluate the task.run action and, when allowed, sign a
	// Decision. A require_approval match parks the run (M4).
	var pbDecision *pb.Decision
	if c.ident != nil {
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
		rules, _ := c.st.GetPolicyRules()
		// Step-level gating (F13): command-like steps are evaluated as
		// exec-class actions too, so cmd-regex rules (e.g. the preset
		// require-approval reboot rule) apply to task steps, not just exec.
		decision := EvaluateRunSteps(rules, act, steps)
		switch decision.Effect {
		case policy.EffectDeny:
			_ = c.st.FinalizeTaskRun(runID, "failed", "denied by policy: "+decision.Reason, 0)
			c.audit(agentID, runID, actor, "denied", 0, decision.Reason)
			if final, err := c.st.TaskRun(runID); err == nil && final != nil {
				return final, nil
			}
			return action, nil
		case policy.EffectRequireApproval:
			if c.approvals == nil {
				// Fail closed without the approvals engine.
				_ = c.st.FinalizeTaskRun(runID, "failed", "denied by policy: "+decision.Reason, 0)
				c.audit(agentID, runID, actor, "denied", 0, "require_approval without approvals engine; failing closed")
				return action, fmt.Errorf("tasks: %s requires approval but the approvals engine is not wired; failing closed", taskID)
			}
			_ = c.st.MarkTaskRunAwaiting(runID)
			areq, err := c.approvals.NewRequest(approvals.NewRequestParams{
				ActionClass:  policy.ActionTaskRun,
				AgentID:      agentID,
				RunID:        runID,
				Actor:        actor.Principal,
				ActorRole:    actor.Role,
				MatchedRules: decision.MatchedRules,
				Payload: map[string]any{
					"task_id": taskID, "task_version": version,
				},
			})
			if err != nil {
				_ = c.st.FinalizeTaskRun(runID, "failed", "approval request: "+err.Error(), 0)
				return action, fmt.Errorf("tasks: approval request: %w", err)
			}
			c.audit(agentID, runID, actor, "awaiting_approval", 0, decision.Reason)
			return action, &ApprovalRequiredError{ApprovalID: areq.ID, RunID: runID}
		case policy.EffectAllow:
			bundleVersion, _ := c.st.PolicyBundleVersion()
			sig := policy.SignDecision(c.ident.Priv, runID, bundleVersion,
				decision.Effect, decision.MatchedRules, actor.Role, "")
			pbDecision = &pb.Decision{
				RunId:         runID,
				BundleVersion: bundleVersion,
				Effect:        decision.Effect,
				MatchedRules:  decision.MatchedRules,
				Sig:           sig,
				ActorRole:     actor.Role,
			}
		}
	}

	return c.dispatchRun(ctx, runID, taskID, version, steps, agentID, pbDecision, actor)
}

// dispatchRun sends a task run down the stream, waits for the result,
// records per-step results, and finalizes the row. Shared by the direct
// path (Run) and the approval re-dispatch (DispatchApprovedTaskRun).
func (c *Controller) dispatchRun(ctx context.Context, runID, taskID string, version int,
	steps []*pb.TaskStep, agentID string, pbDecision *pb.Decision, actor Actor) (*store.TaskRun, error) {
	pbRun := &pb.TaskRun{
		RunId:       runID,
		TaskId:      taskID,
		TaskVersion: int32(version),
		Steps:       steps,
		Decision:    pbDecision,
	}
	if err := c.h.SendTaskRun(agentID, pbRun); err != nil {
		_ = c.st.FinalizeTaskRun(runID, "failed", "dispatch: "+err.Error(), 0)
		c.audit(agentID, runID, actor, "error", 0, err.Error())
		return nil, err
	}

	// Wait for result.
	opCtx, cancel := context.WithTimeout(ctx, c.opTimeout)
	defer cancel()
	result, err := c.h.WaitTaskResult(opCtx, runID)
	if err != nil {
		_ = c.st.FinalizeTaskRun(runID, "failed", "timeout: "+err.Error(), 0)
		c.audit(agentID, runID, actor, "error", 0, err.Error())
		return nil, err
	}

	// Record per-step results.
	for _, sr := range result.GetSteps() {
		step := &store.TaskRunStep{
			RunID: runID, StepIdx: int(sr.GetStepIndex()),
			Kind: "unknown", State: sr.GetState(), Detail: sr.GetDetail(),
			Started: sr.GetStarted(), Finished: sr.GetFinished(),
		}
		if len(steps) > int(sr.GetStepIndex()) {
			step.Kind = steps[sr.GetStepIndex()].GetKind()
		}
		_ = c.st.RecordTaskRunStep(step)
	}

	// Finalize the run.
	status := "succeeded"
	errMsg := ""
	if result.GetState() != "succeeded" {
		status = result.GetState()
		errMsg = result.GetError()
	}
	_ = c.st.FinalizeTaskRun(runID, status, errMsg, 0)
	c.audit(agentID, runID, actor, status, 0, "")
	// Re-read the finalized run so the caller sees the terminal state.
	if final, err := c.st.TaskRun(runID); err == nil && final != nil {
		return final, nil
	}
	return nil, nil
}

// DispatchApprovedTaskRun re-dispatches a parked task run after its
// approval was granted (the approvals engine's task.run dispatcher). The
// signed decision (bound to the approval id) rides the run down; the agent
// guardrail's approval path honors it.
func (c *Controller) DispatchApprovedTaskRun(req *store.ApprovalRequest, dec *pb.Decision) error {
	var p struct {
		TaskID      string `json:"task_id"`
		TaskVersion int    `json:"task_version"`
	}
	if err := json.Unmarshal([]byte(req.PayloadJSON), &p); err != nil {
		return fmt.Errorf("tasks: approval %s: bad payload: %w", req.ID, err)
	}
	run, err := c.st.TaskRun(req.RunID)
	if err != nil || run == nil {
		return fmt.Errorf("tasks: approval %s: run %s not found", req.ID, req.RunID)
	}
	if run.State != "awaiting_approval" {
		return fmt.Errorf("tasks: approval %s: run %s is %s, not awaiting_approval", req.ID, req.RunID, run.State)
	}
	ver, err := c.st.TaskVersion(p.TaskID, p.TaskVersion)
	if err != nil || ver == nil {
		return fmt.Errorf("tasks: approval %s: task %s v%d not found", req.ID, p.TaskID, p.TaskVersion)
	}
	storeSteps, err := store.DecodeTaskSteps(ver.StepsJSON)
	if err != nil {
		return fmt.Errorf("tasks: approval %s: decode steps: %w", req.ID, err)
	}
	pbSteps := make([]*pb.TaskStep, 0, len(storeSteps))
	for _, s := range storeSteps {
		pbSteps = append(pbSteps, &pb.TaskStep{
			Kind: s.Kind, Name: s.Name, When: s.When,
			Command: s.Command, Args: s.Args, Env: s.Env,
			Path: s.Path, Content: s.Content, Template: s.Template, Vars: s.Vars,
			Mode: s.Mode, Package: s.Package, State: s.State,
			Service: s.Service, User: s.User, Group: s.Group, Expr: s.Expr,
		})
	}
	actor := Actor{Principal: req.Actor, Role: req.ActorRole}
	_, err = c.dispatchRun(context.Background(), req.RunID, p.TaskID, p.TaskVersion, pbSteps, req.AgentID, dec, actor)
	return err
}

// RunPlaybook runs a playbook's pinned task version on every host its
// selector matches (fan-out; per-host outcomes are the returned runs —
// succeeded/failed/awaiting_approval). Policy gates apply per host: a
// parked host's run is returned in awaiting_approval state with its
// approval request surfaced via the error list.
func (c *Controller) RunPlaybook(ctx context.Context, playbookID string, actor Actor) ([]*store.TaskRun, []string, error) {
	pbRow, err := c.st.Playbook(playbookID)
	if err != nil || pbRow == nil {
		return nil, nil, fmt.Errorf("tasks: playbook %s not found", playbookID)
	}
	ver, err := c.st.TaskVersion(pbRow.TaskID, pbRow.TaskVersion)
	if err != nil || ver == nil {
		return nil, nil, fmt.Errorf("tasks: playbook %s: task %s v%d not found", playbookID, pbRow.TaskID, pbRow.TaskVersion)
	}
	storeSteps, err := store.DecodeTaskSteps(ver.StepsJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("tasks: playbook %s: decode steps: %w", playbookID, err)
	}
	pbSteps := make([]*pb.TaskStep, 0, len(storeSteps))
	for _, s := range storeSteps {
		pbSteps = append(pbSteps, &pb.TaskStep{
			Kind: s.Kind, Name: s.Name, When: s.When,
			Command: s.Command, Args: s.Args, Env: s.Env,
			Path: s.Path, Content: s.Content, Template: s.Template, Vars: s.Vars,
			Mode: s.Mode, Package: s.Package, State: s.State,
			Service: s.Service, User: s.User, Group: s.Group, Expr: s.Expr,
		})
	}
	agents, err := store.NewResolver(c.st).ResolveSelector(pbRow.Selector)
	if err != nil {
		return nil, nil, fmt.Errorf("tasks: playbook %s: resolve selector %q: %w", playbookID, pbRow.Selector, err)
	}
	runs := make([]*store.TaskRun, 0, len(agents))
	var errs []string
	for _, a := range agents {
		run, rerr := c.Run(ctx, a.ID, pbRow.TaskID, pbRow.TaskVersion, pbSteps, actor)
		if rerr != nil {
			var apprErr *ApprovalRequiredError
			if !errors.As(rerr, &apprErr) {
				errs = append(errs, fmt.Sprintf("%s: %s", a.ID, rerr.Error()))
				continue
			}
		}
		if run != nil {
			runs = append(runs, run)
		}
	}
	return runs, errs, nil
}

// OnLateResult records a task run result that arrived without a live
// waiter: typically a post-reboot resume of a run whose original dispatch
// already timed out (PRD §5.5). It finalizes the existing row in place and
// records the reported steps. A no-op when the run id is unknown.
// It reports whether the run id was a known task run (false = the caller
// may route the result elsewhere, e.g. to manual job runs).
func (c *Controller) OnLateResult(agentID, runID string, tr *pb.TaskRunResult) bool {
	run, err := c.st.TaskRun(runID)
	if err != nil || run == nil {
		return false // unknown run: nothing to finalize
	}
	for _, sr := range tr.GetSteps() {
		_ = c.st.RecordTaskRunStep(&store.TaskRunStep{
			RunID: runID, StepIdx: int(sr.GetStepIndex()),
			Kind: "unknown", State: sr.GetState(), Detail: sr.GetDetail(),
			Started: sr.GetStarted(), Finished: sr.GetFinished(),
		})
	}
	status := "succeeded"
	errMsg := ""
	if tr.GetState() != "succeeded" {
		status = tr.GetState()
		errMsg = tr.GetError()
	}
	_ = c.st.FinalizeTaskRun(runID, status, errMsg, 0)
	c.log.Printf("tasks: late result for %s (agent %s): %s %s", runID, agentID, status, errMsg)
	c.audit(agentID, runID, Actor{Principal: "agent", Role: "agent"}, status, 0, "")
	return true
}

// GetRun returns one task run by ID.
func (c *Controller) GetRun(id string) (*store.TaskRun, error) {
	return c.st.TaskRun(id)
}

// ListRunsForHost lists recent runs for one host.
func (c *Controller) ListRunsForHost(agentID string, limit int) ([]*store.TaskRun, error) {
	return c.st.TaskRunsForHost(agentID, limit)
}

// ListRuns lists all runs (most recent first).
func (c *Controller) ListRuns(limit int) ([]*store.TaskRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// We don't have a direct ListRuns; use list of tasks then aggregate.
	// For now, just return the task_runs rows.
	rows, err := c.st.ListTaskRuns(limit)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// ListSteps returns all steps for a run.
func (c *Controller) ListSteps(runID string) ([]*store.TaskRunStep, error) {
	return c.st.TaskRunSteps(runID)
}

// audit records a package audit event + SSE event.
func (c *Controller) audit(agentID, runID string, actor Actor, state string, applied int64, errMsg string) {
	payload, _ := json.Marshal(map[string]any{
		"run_id": runID,
		"state":  state,
		"error":  errMsg,
	})
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: "task", Actor: actor.Principal,
		AgentID: agentID, Payload: string(payload),
	})
	if c.sse != nil {
		c.sse.Emit("task.run", map[string]any{
			"agent_id": agentID, "run_id": runID,
			"state": state, "actor": actor.Principal,
		})
	}
}

// ---- step-level policy gating (field feedback F13) -------------------------
//
// The cmd-regex policy rules (including the preset
// default-require-approval-reboot) used to match only dispatched exec
// commands: a task `reboot` step ran straight to execution and was stopped
// solely by the privilege wall. Task steps are now evaluated as exec-class
// actions at dispatch time (and re-checked by the agent guardrail), so a
// rule that gates `reboot` gates it everywhere.

// stepCommandLine renders the command line a step would execute, for
// cmd-regex policy matching. Returns ("", false) for non-command steps.
func stepCommandLine(s *pb.TaskStep) (string, bool) {
	switch s.GetKind() {
	case "command":
		if s.GetCommand() == "" {
			return "", false
		}
		return strings.TrimSpace(strings.Join(append([]string{s.GetCommand()}, s.GetArgs()...), " ")), true
	case "reboot":
		// The reboot step's execution surface: the reboot command itself
		// (defaultReboot tries `systemctl reboot`, `shutdown -r now`, then
		// `reboot`). Match the conservative literal the preset rules use.
		return "reboot", true
	default:
		return "", false
	}
}

// StepActions builds one exec-class policy action per command-like step,
// from the same host/actor context as the task.run-class action.
func StepActions(base policy.Action, steps []*pb.TaskStep) []policy.Action {
	var out []policy.Action
	for _, s := range steps {
		cl, ok := stepCommandLine(s)
		if !ok {
			continue
		}
		a := base
		a.ActionClass = policy.ActionExec
		a.CommandLine = cl
		fields := strings.Fields(cl)
		if len(fields) > 0 {
			a.Cmd = fields[0]
			if len(fields) > 1 {
				a.Args = fields[1:]
			} else {
				a.Args = nil
			}
		}
		out = append(out, a)
	}
	return out
}

// EvaluateRunSteps evaluates the task.run action class AND every
// command-like step (as exec-class actions); the worst effect wins
// (deny > require_approval > allow). This is what tasks.Run and the jobs
// controller gate on before signing a dispatch Decision.
func EvaluateRunSteps(rules []policy.Rule, act policy.Action, steps []*pb.TaskStep) policy.Decision {
	combined := policy.Evaluate(rules, act)
	rank := func(effect string) int {
		switch effect {
		case policy.EffectDeny:
			return 3
		case policy.EffectRequireApproval:
			return 2
		default:
			return 1
		}
	}
	for _, sa := range StepActions(act, steps) {
		d := policy.Evaluate(rules, sa)
		if rank(d.Effect) > rank(combined.Effect) {
			combined = d
		}
		// Merge matched-rule attribution so the audit shows why.
		combined.MatchedRules = append(combined.MatchedRules, d.MatchedRules...)
	}
	return combined
}
