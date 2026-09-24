// Package tasks implements the server-side task orchestration (M3, PRD §5.5).
// It dispatches task runs to agents over the stream, records results in
// the task_runs/task_run_steps tables, and emits SSE audit events.
package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
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

	// Policy gate: create a signed Decision for the task.run action.
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
		decision := policy.Evaluate(rules, act)
		if decision.Effect == policy.EffectDeny {
			_ = c.st.FinalizeTaskRun(runID, "failed", "denied by policy: "+decision.Reason, 0)
			c.audit(agentID, runID, actor, "denied", 0, decision.Reason)
			if final, err := c.st.TaskRun(runID); err == nil && final != nil {
				return final, nil
			}
			return action, nil
		}
		if decision.Effect == policy.EffectAllow {
			version, _ := c.st.PolicyBundleVersion()
			sig := policy.SignDecision(c.ident.Priv, runID, version,
				decision.Effect, decision.MatchedRules, actor.Role)
			pbDecision = &pb.Decision{
				RunId:         runID,
				BundleVersion: version,
				Effect:        decision.Effect,
				MatchedRules:  decision.MatchedRules,
				Sig:           sig,
				ActorRole:     actor.Role,
			}
		}
	}

	// Dispatch the task run.
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
		return action, err
	}

	// Wait for result.
	opCtx, cancel := context.WithTimeout(ctx, c.opTimeout)
	defer cancel()
	result, err := c.h.WaitTaskResult(opCtx, runID)
	if err != nil {
		_ = c.st.FinalizeTaskRun(runID, "failed", "timeout: "+err.Error(), 0)
		c.audit(agentID, runID, actor, "error", 0, err.Error())
		return action, err
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
	return action, nil
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
