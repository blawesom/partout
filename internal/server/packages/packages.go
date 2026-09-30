// Package packages implements the server-side package management (M3,
// PRD §5.6): list-updates and apply-updates over the agent stream,
// policy-gated (pkg.list / pkg.apply action classes), with signed
// decisions for apply ops, before/after journal, and audit.
package packages

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/externaldata"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// Controller dispatches package operations to agents.
type Controller struct {
	st    *store.Store
	h     *stream.Handler
	sse   *sse.Broker
	log   *log.Logger
	ident *certutil.ServerIdentity
	// approvals is the M4 approvals engine; nil → require_approval fails
	// closed (deny) rather than silently allowing.
	approvals *approvals.Controller
	// extdata provides OSV CVE correlation for list-updates (PRD §6.3).
	// Nil → no correlation (updates returned unranked).
	extdata *externaldata.Refresher
	// opTimeout bounds one apply op (apt/dnf can take minutes).
	opTimeout time.Duration
	// listTimeout bounds list-updates (shorter; no mutation).
	listTimeout time.Duration
}

// ApprovalRequiredError is returned when a package apply is parked on an
// approval request (M4). The API layer maps it to 202 with the request id.
type ApprovalRequiredError struct {
	ApprovalID string
}

func (e *ApprovalRequiredError) Error() string {
	return "packages: approval required (" + e.ApprovalID + ")"
}

// SetApprovals installs the approvals engine (M4).
func (c *Controller) SetApprovals(ac *approvals.Controller) { c.approvals = ac }

// New builds a Controller.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{
		st: st, h: h, sse: sseB, log: lg,
		opTimeout: 10 * time.Minute, listTimeout: 60 * time.Second,
	}
}

// SetIdentity installs the server's Ed25519 signing key (signs Decisions on
// apply ops so the agent guardrail can verify them).
func (c *Controller) SetIdentity(ident *certutil.ServerIdentity) { c.ident = ident }

// SetRefresher installs the external-data refresher for CVE correlation on
// list-updates (PRD §6.3). Nil disables correlation.
func (c *Controller) SetRefresher(r *externaldata.Refresher) { c.extdata = r }

// Actor carries the requester identity for audit + policy.
type Actor struct {
	Principal string // who (token name / user)
	Role      string // viewer|operator|admin
}

// ListUpdates returns the list of available updates for a host (PRD §5.6).
// Read-only: no decision, no policy gate (like file read ops). Results are
// ranked by CVE severity (PRD §6.3: installed version correlated against
// the vuln cache / OSV.dev).
func (c *Controller) ListUpdates(ctx context.Context, agentID string, actor Actor) ([]*pb.PkgUpdate, error) {
	op := &pb.PkgOp{OpId: id.New("pko"), Kind: pb.PkgOpKind_PKG_LIST_UPDATES}
	res, err := c.doSend(ctx, agentID, op, c.listTimeout)
	if err != nil {
		c.audit(agentID, "list", op.OpId, actor, "error", 0, err.Error())
		return nil, err
	}
	if res.Code != 0 {
		c.audit(agentID, "list", op.OpId, actor, "error", 0, res.Error)
		return nil, fmt.Errorf("packages: list: %s (code %d)", res.Error, res.Code)
	}
	c.audit(agentID, "list", op.OpId, actor, "ok", int64(len(res.Updates)), "")

	// Correlate each update against the vuln cache (PRD §6.3). Failures are
	// non-fatal: the update list is returned unranked.
	if c.extdata != nil && len(res.Updates) > 0 {
		eco := c.ecosystemFor(agentID)
		if eco != "" {
			for _, u := range res.Updates {
				rows, _ := c.extdata.Correlate(ctx, u.Name, eco, u.Installed)
				if len(rows) > 0 {
					u.VulnCount = int64(len(rows))
					u.MaxSeverity = maxCVSS(rows)
					u.IsSecurity = true
					u.VulnIds = vulnIDsFromRows(rows)
				}
			}
			// Rank: highest severity first, then most CVEs, then name.
			rankUpdates(res.Updates)
		}
	}
	return res.Updates, nil
}

// ecosystemFor derives the OSV ecosystem string from the agent's os-release
// facts (PRD §6.3). Returns "" when the distro is not covered.
func (c *Controller) ecosystemFor(agentID string) string {
	f, err := c.st.LatestFacts(agentID)
	if err != nil || f == nil {
		return ""
	}
	return externaldata.OSVEcosystem(f.Data["host.distro"], f.Data["host.distro_version"])
}

// maxCVSS returns the human-readable severity label for the highest CVSS in
// a vuln set (critical ≥ 9, high ≥ 7, medium ≥ 4, low > 0, else "").
func maxCVSS(rows []store.VulnRow) string {
	best := 0.0
	for _, r := range rows {
		if r.Severity.Valid && r.Severity.Float64 > best {
			best = r.Severity.Float64
		}
	}
	switch {
	case best >= 9:
		return "critical"
	case best >= 7:
		return "high"
	case best >= 4:
		return "medium"
	case best > 0:
		return "low"
	default:
		return ""
	}
}

// rankUpdates sorts in place: max severity desc, vuln count desc, name asc.
func rankUpdates(ups []*pb.PkgUpdate) {
	sort.Slice(ups, func(i, j int) bool {
		si, sj := sevRank(ups[i].MaxSeverity), sevRank(ups[j].MaxSeverity)
		if si != sj {
			return si < sj // lower rank number = more severe
		}
		if ups[i].VulnCount != ups[j].VulnCount {
			return ups[i].VulnCount > ups[j].VulnCount
		}
		return ups[i].Name < ups[j].Name
	})
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// Apply runs the apply flow: policy gate + signed decision + dispatch +
// store journal (PRD §5.6). dryRun=true only simulates (no policy gate).
func (c *Controller) Apply(ctx context.Context, agentID string, actor Actor, filterPkgs []string, dryRun bool) (*store.PkgAction, error) {
	opName := "apply"
	if dryRun {
		opName = "dry_run"
	}
	op := &pb.PkgOp{
		OpId: id.New("pko"), Kind: pb.PkgOpKind_PKG_APPLY,
		Packages: filterPkgs, DryRun: dryRun,
	}

	// Policy gate + signed decision (real apply only; dry-run is read-only).
	if !dryRun {
		if err := c.policyGate(agentID, op, actor, opName); err != nil {
			return nil, err
		}
	}

	return c.dispatchApply(ctx, agentID, op, actor, opName)
}

// dispatchApply records + dispatches a policy-gated apply op and waits for
// the result. Shared by direct Apply and approval re-dispatch (M4).
func (c *Controller) dispatchApply(ctx context.Context, agentID string, op *pb.PkgOp, actor Actor, opName string) (*store.PkgAction, error) {
	// Record the action as "running".
	actionID := store.NewPkgActionID()
	action := &store.PkgAction{
		ID: actionID, AgentID: agentID, Kind: opName,
		Status: "running", Created: time.Now().Unix(),
	}
	if err := c.st.InsertPkgAction(action); err != nil {
		c.log.Printf("packages: insert action %s: %v", actionID, err)
	}

	// Dispatch + wait.
	res, err := c.doSend(ctx, agentID, op, c.opTimeout)
	if err != nil {
		_ = c.st.FinalizePkgAction(actionID, "failed", "", "", "", 0, err.Error())
		c.audit(agentID, opName, op.OpId, actor, "error", 0, err.Error())
		action.Status = "failed"
		action.Error = err.Error()
		return action, err
	}

	// Journal proto PkgUpdate slices → store JSON.
	beforeJSON, _ := pbUpdatesToJSON(res.Before)
	afterJSON, _ := pbUpdatesToJSON(res.After)

	status := "succeeded"
	if res.Code != 0 {
		status = "failed"
	}
	_ = c.st.FinalizePkgAction(
		actionID, status, res.DryRunSummary,
		beforeJSON, afterJSON, res.AppliedCount, res.Error,
	)
	action.Status = status
	action.DrySummary = res.DryRunSummary
	action.BeforeJSON = beforeJSON
	action.AfterJSON = afterJSON
	action.AppliedCount = res.AppliedCount
	action.Error = res.Error

	state := "ok"
	if res.Code != 0 {
		state = "error"
	}
	c.audit(agentID, opName, op.OpId, actor, state, res.AppliedCount, res.Error)
	return action, nil
}

// DispatchApprovedApply re-dispatches a package apply that was parked on an
// approval (M4). Registered as the approvals controller's "pkg.apply"
// dispatcher; the decision is already signed (EffectAllow + approval id).
func (c *Controller) DispatchApprovedApply(req *store.ApprovalRequest, dec *pb.Decision) (*store.PkgAction, error) {
	var p struct {
		Packages []string `json:"packages"`
		DryRun   bool     `json:"dry_run"`
	}
	if err := json.Unmarshal([]byte(req.PayloadJSON), &p); err != nil {
		return nil, fmt.Errorf("packages: approval %s: bad payload: %w", req.ID, err)
	}
	op := &pb.PkgOp{
		OpId: id.New("pko"), Kind: pb.PkgOpKind_PKG_APPLY,
		Packages: p.Packages, DryRun: p.DryRun,
		Decision: dec,
	}
	actor := Actor{Principal: req.DecidedBy, Role: "admin"}
	if actor.Principal == "" {
		actor = Actor{Principal: req.Actor, Role: req.ActorRole}
	}
	return c.dispatchApply(context.Background(), req.AgentID, op, actor, "apply")
}

// GetAction fetches a stored package action.
func (c *Controller) GetAction(id string) (*store.PkgAction, error) {
	return c.st.GetPkgAction(id)
}

// ListActions lists recent package actions.
func (c *Controller) ListActions(limit int) ([]*store.PkgAction, error) {
	return c.st.ListPkgActions(limit)
}

// doSend dispatches one PkgOp and waits for its result.
func (c *Controller) doSend(ctx context.Context, agentID string, op *pb.PkgOp, timeout time.Duration) (*pb.PkgResult, error) {
	if err := c.h.SendPkgOp(agentID, op); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := c.h.WaitPkgResult(opCtx, op.OpId)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// policyGate evaluates policy for a package apply op and attaches a signed
// Decision (like files.policyGate). A hard deny is audited and returned as
// an error. A require_approval match (M4) parks the op on an approval
// request and returns *ApprovalRequiredError; without the approvals engine
// wired it fails closed as a deny.
func (c *Controller) policyGate(agentID string, op *pb.PkgOp, actor Actor, opName string) error {
	class, ok := policy.PkgOpClass(op.Kind)
	if !ok {
		return fmt.Errorf("packages: %s: no action class for kind %s", opName, op.Kind)
	}
	host, err := c.st.Agent(agentID)
	if err != nil {
		return fmt.Errorf("packages: agent %s: %w", agentID, err)
	}
	action := policy.PkgAction(class, "")
	action.HostID = host.ID
	action.HostTags, _ = c.st.Tags(host.ID)
	action.HostRoles, _ = c.st.Roles(host.ID)
	action.ActorRole = actor.Role
	rules, err := c.st.GetPolicyRules()
	if err != nil {
		return fmt.Errorf("packages: load policies: %w", err)
	}
	decision := policy.Evaluate(rules, action)
	if decision.Effect == policy.EffectDeny {
		c.audit(agentID, opName, op.OpId, actor, "denied", 0, decision.Reason)
		return fmt.Errorf("packages: %s denied by policy: %s", opName, decision.Reason)
	}
	if decision.Effect == policy.EffectRequireApproval {
		if c.approvals == nil {
			// Fail closed: no approvals engine in this build.
			c.audit(agentID, opName, op.OpId, actor, "denied", 0, "approval required but the approvals engine is unavailable")
			return fmt.Errorf("packages: %s requires approval but the approvals engine is unavailable", opName)
		}
		apReq, err := c.approvals.NewRequest(approvals.NewRequestParams{
			ActionClass:  policy.ActionPkgApply,
			AgentID:      agentID,
			Actor:        actor.Principal,
			ActorRole:    actor.Role,
			MatchedRules: decision.MatchedRules,
			Payload:      map[string]any{"packages": op.Packages, "dry_run": false},
		})
		if err != nil {
			return fmt.Errorf("packages: %s: create approval request: %w", opName, err)
		}
		c.audit(agentID, opName, op.OpId, actor, "approval_required", 0, apReq.ID)
		return &ApprovalRequiredError{ApprovalID: apReq.ID}
	}
	// Sign the decision (agent guardrail verifies; arch §5.3).
	if c.ident != nil {
		version, _ := c.st.PolicyBundleVersion()
		sig := policy.SignDecision(c.ident.Priv, op.OpId, version,
			decision.Effect, decision.MatchedRules, actor.Role, "")
		op.Decision = &pb.Decision{
			RunId:         op.OpId,
			BundleVersion: version,
			Effect:        decision.Effect,
			MatchedRules:  decision.MatchedRules,
			Sig:           sig,
			ActorRole:     actor.Role,
		}
	}
	return nil
}

// audit records a package audit event + SSE event (the package_actions row
// is handled by InsertPkgAction/FinalizePkgAction).
func (c *Controller) audit(agentID, opName, opID string, actor Actor, state string, applied int64, errMsg string) {
	payload, _ := json.Marshal(map[string]any{
		"op":      opName,
		"op_id":   opID,
		"state":   state,
		"applied": applied,
		"error":   errMsg,
	})
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: "package", Actor: actor.Principal,
		AgentID: agentID, Payload: string(payload),
	})
	if c.sse != nil {
		c.sse.Emit("package.action", map[string]any{
			"agent_id": agentID, "op": opName, "op_id": opID,
			"state": state, "actor": actor.Principal,
		})
	}
}

// pbUpdatesToJSON converts proto PkgUpdate slices to store JSON.
func pbUpdatesToJSON(ups []*pb.PkgUpdate) (string, error) {
	if len(ups) == 0 {
		return "", nil
	}
	jups := make([]store.PkgUpdateJSON, 0, len(ups))
	for _, u := range ups {
		jups = append(jups, store.PkgUpdateJSON{
			Name:        u.Name,
			Installed:   u.Installed,
			Available:   u.Available,
			VulnCount:   u.VulnCount,
			MaxSeverity: u.MaxSeverity,
			IsSecurity:  u.IsSecurity,
		})
	}
	return store.MarshalPkgUpdates(jups)
}

// vulnIDsFromRows extracts the advisory/CVE ids from a correlated vuln set
// (capped), for display and the security scan findings.
func vulnIDsFromRows(rows []store.VulnRow) []string {
	var ids []string
	for _, r := range rows {
		if r.VulnID != "" && r.VulnID != "-" {
			ids = append(ids, r.VulnID)
			if len(ids) >= maxVulnIDs {
				break
			}
		}
	}
	return ids
}
