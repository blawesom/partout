// Package control is the orchestration engine (arch §4.1): it resolves
// selectors, creates execution + runs, dispatches command envelopes down the
// stream, and records audit rows. It sits in front of the transport so every
// mutation is policy-gated and audited before it reaches a host.
package control

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

// Control dispatches work to hosts.
type Control struct {
	st  *store.Store
	h   *stream.Handler
	sse *sse.Broker
	log *log.Logger
}

// New builds a Control. It also wires the stream handler's result hook so
// executions finalize their aggregate state as runs finish.
func New(st *store.Store, h *stream.Handler, sse *sse.Broker, lg *log.Logger) *Control {
	if lg == nil {
		lg = log.Default()
	}
	c := &Control{st: st, h: h, sse: sse, log: lg}
	h.ResultHook = c.onRunFinished
	return c
}

// DispatchRequest is a command to run across a selector.
type DispatchRequest struct {
	Selector  string            `json:"selector"`
	Cmd       string            `json:"cmd"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	TimeoutS  int32             `json:"timeout_s,omitempty"`
	CreatedBy string            `json:"created_by,omitempty"`
}

// DispatchResult reports what was dispatched.
type DispatchResult struct {
	ExecutionID string   `json:"execution_id"`
	Runs        []RunRef `json:"runs"`
	Errors      []string `json:"errors,omitempty"`
}

// RunRef is one dispatched run.
type RunRef struct {
	RunID     string `json:"run_id"`
	AgentID   string `json:"agent_id"`
	Delivered bool   `json:"delivered"`
}

// Dispatch resolves the selector, creates an execution + a run per host, and
// sends a Command envelope to each host. Hosts with no active session get a
// `not_delivered` run (M0: no offline queue yet).
func (c *Control) Dispatch(ctx context.Context, req DispatchRequest) (*DispatchResult, error) {
	// 1. Resolve selector (empty → error, never a silent no-op).
	r := store.NewResolver(c.st)
	hosts, err := r.ResolveSelector(req.Selector)
	if err != nil {
		return nil, fmt.Errorf("control: resolve selector: %w", err)
	}

	// 2. Create execution.
	execID := id.New("exec")
	argsJSON := ""
	if req.Args != nil {
		b, err := json.Marshal(req.Args)
		if err != nil {
			return nil, fmt.Errorf("control: marshal args: %w", err)
		}
		argsJSON = string(b)
	}
	exec := store.Execution{
		ID:        execID,
		Selector:  req.Selector,
		Cmd:       req.Cmd,
		ArgsJSON:  argsJSON,
		CreatedBy: req.CreatedBy,
		State:     "dispatching",
	}
	if err := c.st.CreateExecution(exec); err != nil {
		return nil, fmt.Errorf("control: create execution: %w", err)
	}

	// 3. Create a run per host and dispatch.
	res := &DispatchResult{ExecutionID: execID}
	for _, host := range hosts {
		runID := id.New("run")
		run := store.ExecutionRun{
			ID:          runID,
			ExecutionID: execID,
			AgentID:     host.ID,
			State:       "queued",
		}
		if err := c.st.CreateExecutionRun(run); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", host.ID, err))
			continue
		}

		cmd := &pb.Command{
			RunId:       runID,
			ExecutionId: execID,
			Cmd:         req.Cmd,
			Args:        req.Args,
			Env:         req.Env,
			TimeoutS:    req.TimeoutS,
		}
		// Dispatch down the stream.
		if err := c.h.SendCommand(host.ID, cmd); err != nil {
			c.st.UpdateRunState(runID, "not_delivered", -1, 0)
			res.Runs = append(res.Runs, RunRef{RunID: runID, AgentID: host.ID, Delivered: false})
			res.Errors = append(res.Errors, fmt.Sprintf("%s: not delivered: %v", host.ID, err))
			continue
		}
		c.st.UpdateRunState(runID, "delivered", -1, 0)
		res.Runs = append(res.Runs, RunRef{RunID: runID, AgentID: host.ID, Delivered: true})
	}

	// 4. Audit.
	c.audit("exec.dispatch", req.CreatedBy, map[string]string{
		"execution_id": execID,
		"selector":     req.Selector,
		"cmd":          req.Cmd,
		"hosts":        fmt.Sprint(len(hosts)),
	})

	// 5. SSE.
	if c.sse != nil {
		c.sse.Emit("execution.state", map[string]string{
			"execution_id": execID,
			"state":        "dispatching",
		})
	}

	return res, nil
}

// CancelResult reports the outcome of a cancel request.
type CancelResult struct {
	ExecutionID string   `json:"execution_id"`
	Cancelled   []string `json:"cancelled"`
	AlreadyDone []string `json:"already_done"`
	Errors      []string `json:"errors,omitempty"`
}

// CancelExecution stops an execution: in-flight runs get a CANCEL envelope
// sent to their agent (which kills the process and reports state=cancelled),
// and all non-terminal runs are marked cancelled in the store.
func (c *Control) CancelExecution(execID string, actor string) (*CancelResult, error) {
	exec, err := c.st.GetExecution(execID)
	if err != nil {
		return nil, fmt.Errorf("control: get execution: %w", err)
	}
	switch exec.State {
	case "succeeded", "failed", "partial", "cancelled":
		return nil, fmt.Errorf("control: execution %s already %s", execID, exec.State)
	}

	runs, err := c.st.ListRunsForExecution(execID)
	if err != nil {
		return nil, fmt.Errorf("control: list runs: %w", err)
	}

	res := &CancelResult{ExecutionID: execID}
	for _, r := range runs {
		if store.IsTerminalRun(r.State) {
			res.AlreadyDone = append(res.AlreadyDone, r.ID)
			continue
		}
		// Ask the agent to stop the process (best-effort; offline agent → ignore).
		if r.State == "delivered" || r.State == "running" {
			if err := c.h.SendCancel(r.AgentID, r.ID); err != nil {
				c.log.Printf("control: send cancel %s/%s: %v", r.AgentID, r.ID, err)
			}
		}
		res.Cancelled = append(res.Cancelled, r.ID)
	}

	if _, err := c.st.CancelNonTerminalRuns(execID); err != nil {
		return nil, fmt.Errorf("control: cancel runs: %w", err)
	}
	if err := c.st.UpdateExecutionState(execID, "cancelled"); err != nil {
		return nil, fmt.Errorf("control: update state: %w", err)
	}

	c.audit("exec.cancel", actor, map[string]string{
		"execution_id": execID,
		"runs":         fmt.Sprint(len(res.Cancelled)),
	})
	if c.sse != nil {
		c.sse.Emit("execution.state", map[string]string{
			"execution_id": execID,
			"state":        "cancelled",
		})
	}
	return res, nil
}

// FinalizeExecution recomputes the execution's aggregate state from its runs
// and updates it. Called after all runs reach a terminal state.
func (c *Control) FinalizeExecution(execID string) error {
	runs, err := c.st.ListRunsForExecution(execID)
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		return c.st.UpdateExecutionState(execID, "pending")
	}

	// If the execution was explicitly cancelled, don't overwrite the state.
	// CancelExecution sets this; FinalizeExecution only recomputes natural
	// terminal states (succeeded/failed/partial).
	for _, r := range runs {
		if r.State == "cancelled" {
			// Already done — no further computation needed.
			return nil
		}
	}

	var succeeded, failed, other int
	for _, r := range runs {
		switch r.State {
		case "succeeded":
			succeeded++
		case "failed", "timed_out", "interrupted", "not_delivered", "cancelled":
			failed++
		default:
			other++
		}
	}
	state := "running" // still in-flight
	if other == 0 {
		switch {
		case failed == 0:
			state = "succeeded"
		case succeeded == 0:
			state = "failed"
		default:
			state = "partial"
		}
	}
	if err := c.st.UpdateExecutionState(execID, state); err != nil {
		return err
	}
	if c.sse != nil {
		c.sse.Emit("execution.state", map[string]string{"execution_id": execID, "state": state})
	}
	return nil
}

// onRunFinished is the stream handler result hook: called from the gRPC stream
// goroutine whenever a CommandResult is recorded. It triggers execution
// finalization and emits an SSE event for the execution state transition.
func (c *Control) onRunFinished(execID string) {
	if err := c.FinalizeExecution(execID); err != nil {
		c.log.Printf("control: finalize %s: %v", execID, err)
	}
}

// Audit appends an audit event.
func (c *Control) audit(kind, actor string, payload map[string]string) {
	b, _ := json.Marshal(payload)
	c.st.AppendAudit(store.AuditEvent{
		TS:      time.Now().Unix(),
		Kind:    kind,
		Actor:   actor,
		Payload: string(b),
	})
}
