// Package approvals implements the M4 approvals engine (PRD §5.8).
//
// A policy rule with effect `require_approval` parks the action: the
// surface (command dispatch, package apply) creates an approval request
// carrying the EXACT payload (approvals are scoped to the payload, not a
// blanket allow), and the action is not dispatched. An admin approves or
// denies via API/UI; on approval the controller signs a fresh EffectAllow
// decision carrying the approval id and re-dispatches the stored payload
// through the surface's registered dispatcher. Every transition is
// audit-logged and SSE-broadcast.
//
// Requests carry a TTL (PARTOUT_APPROVAL_TTL_S, default 1 h); expired
// requests can never be retroactively honored (lazy expiry on list/read).
package approvals

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
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

// Controller manages approval requests.
type Controller struct {
	st    *store.Store
	h     *stream.Handler
	sse   *sse.Broker
	log   *log.Logger
	ident *certutil.ServerIdentity
	ttl   time.Duration

	// Dispatchers re-dispatches a stored payload on approval, keyed by
	// action class ("exec", "pkg.apply", …). Each dispatcher receives the
	// request and the signed approval decision. Wired by the server
	// assembly (each surface keeps its own dispatch/finalize logic).
	Dispatchers map[string]func(req *store.ApprovalRequest, dec *pb.Decision) error

	// OnExecExpired finalizes an execution whose parked run just expired
	// (wired to control.FinalizeExecution so the aggregate recomputes).
	OnExecExpired func(executionID string)
}

// New builds a Controller.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	ttl := time.Hour
	if v := os.Getenv("PARTOUT_APPROVAL_TTL_S"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = time.Duration(n) * time.Second
		}
	}
	return &Controller{
		st: st, h: h, sse: sseB, log: lg, ttl: ttl,
		Dispatchers: make(map[string]func(*store.ApprovalRequest, *pb.Decision) error),
	}
}

// SetIdentity installs the server's Ed25519 signing key (signs the
// approval-allow decision).
func (c *Controller) SetIdentity(ident *certutil.ServerIdentity) { c.ident = ident }

// RegisterDispatcher installs the re-dispatch function for one action class.
func (c *Controller) RegisterDispatcher(actionClass string, fn func(req *store.ApprovalRequest, dec *pb.Decision) error) {
	c.Dispatchers[actionClass] = fn
}

// Actor carries the approver identity.
type Actor struct {
	Principal string
	Role      string
}

// NewRequestParams describes the action to approve.
type NewRequestParams struct {
	ActionClass  string // "exec" | "pkg.apply" | …
	AgentID      string
	ExecutionID  string // command executions (optional)
	RunID        string // created run row (optional)
	Actor        string // requesting principal
	ActorRole    string
	MatchedRules []string       // rules that required approval
	Payload      map[string]any // exact action payload
}

// NewRequest creates a pending approval request + audit + SSE event.
func (c *Controller) NewRequest(p NewRequestParams) (*store.ApprovalRequest, error) {
	payload, err := json.Marshal(p.Payload)
	if err != nil {
		return nil, fmt.Errorf("approvals: marshal payload: %w", err)
	}
	now := time.Now().Unix()
	req := &store.ApprovalRequest{
		ID:           id.New("apr"),
		ActionClass:  p.ActionClass,
		PayloadJSON:  string(payload),
		AgentID:      p.AgentID,
		ExecutionID:  p.ExecutionID,
		RunID:        p.RunID,
		Actor:        p.Actor,
		ActorRole:    p.ActorRole,
		MatchedRules: strings.Join(p.MatchedRules, ","),
		State:        "pending",
		CreatedUnix:  now,
		ExpiresUnix:  now + int64(c.ttl.Seconds()),
	}
	if err := c.st.CreateApprovalRequest(req); err != nil {
		return nil, err
	}
	c.audit(req, "requested", "", "")
	c.emit(req, "approval.requested")
	return req, nil
}

// Approve transitions a pending request to approved and re-dispatches the
// stored payload through the surface's dispatcher. The approver must be an
// admin. Returns the request (with the dispatch error, if any, in the
// returned error — the approval row itself stays approved; the operator
// can re-run the action).
func (c *Controller) Approve(requestID string, actor Actor) (*store.ApprovalRequest, error) {
	if actor.Role != "admin" {
		return nil, fmt.Errorf("approvals: approve requires the admin role (got %q)", actor.Role)
	}
	req, err := c.st.GetApprovalRequest(requestID)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("approvals: request %s not found", requestID)
	}
	if req.State == "pending" && req.ExpiresUnix <= time.Now().Unix() {
		_ = c.st.DecideApprovalRequest(req.ID, "expired", "system", "expired before decision")
		req.State = "expired"
	}
	if req.State != "pending" {
		return req, fmt.Errorf("approvals: request %s is %s, not pending", req.ID, req.State)
	}
	// The parked run may have been finalized meanwhile (execution cancelled,
	// agent disconnect, …): approving it would dispatch into the void.
	if req.RunID != "" {
		if run, err := c.st.GetExecutionRun(req.RunID); err == nil && run != nil && store.IsTerminalRun(run.State) {
			return req, fmt.Errorf("approvals: request %s: run %s is already %s", req.ID, req.RunID, run.State)
		}
	}
	if c.ident == nil {
		return nil, fmt.Errorf("approvals: server signing identity not configured")
	}

	if err := c.st.DecideApprovalRequest(req.ID, "approved", actor.Principal, ""); err != nil {
		return nil, err
	}
	req.State = "approved"
	req.DecidedBy = actor.Principal
	req.DecidedUnix = time.Now().Unix()
	c.audit(req, "approved", actor.Principal, "")
	c.emit(req, "approval.approved")

	// Sign the approval-allow decision and re-dispatch the exact payload.
	version, _ := c.st.PolicyBundleVersion()
	var rules []string
	if req.MatchedRules != "" {
		rules = strings.Split(req.MatchedRules, ",")
	}
	sig := policy.SignDecision(c.ident.Priv, decisionRunID(req), version,
		policy.EffectAllow, rules, req.ActorRole, req.ID)
	dec := &pb.Decision{
		RunId:         decisionRunID(req),
		BundleVersion: version,
		Effect:        policy.EffectAllow,
		MatchedRules:  rules,
		Sig:           sig,
		ActorRole:     req.ActorRole,
		ApprovalId:    req.ID,
	}
	fn, ok := c.Dispatchers[req.ActionClass]
	if !ok {
		c.log.Printf("approvals: %s approved but no dispatcher for class %q (re-run the action)", req.ID, req.ActionClass)
		return req, fmt.Errorf("approvals: no dispatcher registered for %q", req.ActionClass)
	}
	if err := fn(req, dec); err != nil {
		c.log.Printf("approvals: %s dispatch: %v", req.ID, err)
		c.audit(req, "dispatch_error", "", err.Error())
		return req, err
	}
	return req, nil
}

// Deny transitions a pending request to denied (with reason) + audit.
func (c *Controller) Deny(requestID, reason string, actor Actor) (*store.ApprovalRequest, error) {
	if actor.Role != "admin" {
		return nil, fmt.Errorf("approvals: deny requires the admin role (got %q)", actor.Role)
	}
	req, err := c.st.GetApprovalRequest(requestID)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("approvals: request %s not found", requestID)
	}
	if req.State != "pending" {
		return req, fmt.Errorf("approvals: request %s is %s, not pending", req.ID, req.State)
	}
	if err := c.st.DecideApprovalRequest(req.ID, "denied", actor.Principal, reason); err != nil {
		return nil, err
	}
	req.State = "denied"
	req.DecidedBy = actor.Principal
	req.DecidedUnix = time.Now().Unix()
	req.DecisionReason = reason
	c.audit(req, "denied", actor.Principal, reason)
	c.emit(req, "approval.denied")
	return req, nil
}

// List returns requests (optionally filtered by state). Expired pending
// requests are finalized first: parked exec runs are marked failed and
// their executions re-finalized.
func (c *Controller) List(state string, limit int) ([]*store.ApprovalRequest, error) {
	if expired, err := c.st.ExpireApprovalRequests(); err == nil {
		for _, r := range expired {
			switch r.ActionClass {
			case "exec":
				if r.RunID != "" {
					_ = c.st.UpdateRunState(r.RunID, "failed", -1, 0)
					c.audit(r, "expired", "system", "")
					if r.ExecutionID != "" && c.OnExecExpired != nil {
						c.OnExecExpired(r.ExecutionID)
					}
				}
			case "session.open":
				// Finalize the parked session row (best-effort; the session
				// dispatcher would have opened it on approval).
				if r.RunID != "" {
					_ = c.st.UpdateSessionState(r.RunID, "failed", -1, "approval expired")
					c.audit(r, "expired", "system", "")
				}
			case "task.run":
				if r.RunID != "" {
					_ = c.st.FinalizeTaskRun(r.RunID, "failed", "approval expired", 0)
					c.audit(r, "expired", "system", "")
				}
			case "job.run":
				if r.RunID != "" {
					_ = c.st.FinalizeJobRun(r.RunID, "failed", "approval expired")
					c.audit(r, "expired", "system", "")
				}
			}
		}
	}
	return c.st.ListApprovalRequests(state, limit)
}

// Get returns one request.
func (c *Controller) Get(requestID string) (*store.ApprovalRequest, error) {
	return c.st.GetApprovalRequest(requestID)
}

// decisionRunID is the run/op id the approval decision binds to (the run
// row when present, else the request id).
func decisionRunID(req *store.ApprovalRequest) string {
	if req.RunID != "" {
		return req.RunID
	}
	return req.ID
}

// audit records an approval audit event.
func (c *Controller) audit(req *store.ApprovalRequest, kind, decidedBy, reason string) {
	payload, _ := json.Marshal(map[string]any{
		"request_id":   req.ID,
		"kind":         kind,
		"action_class": req.ActionClass,
		"agent_id":     req.AgentID,
		"actor":        req.Actor,
		"decided_by":   decidedBy,
		"reason":       reason,
	})
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: "approval", Actor: decidedBy,
		AgentID: req.AgentID, Payload: string(payload),
	})
}

func (c *Controller) emit(req *store.ApprovalRequest, event string) {
	if c.sse != nil {
		c.sse.Emit(event, map[string]any{
			"request_id":   req.ID,
			"action_class": req.ActionClass,
			"agent_id":     req.AgentID,
			"state":        req.State,
		})
	}
}
