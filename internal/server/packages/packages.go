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
	// extdata provides OSV CVE correlation for list-updates (PRD §6.3).
	// Nil → no correlation (updates returned unranked).
	extdata *externaldata.Refresher
	// opTimeout bounds one apply op (apt/dnf can take minutes).
	opTimeout time.Duration
	// listTimeout bounds list-updates (shorter; no mutation).
	listTimeout time.Duration
}

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
		OpId:     id.New("pko"), Kind: pb.PkgOpKind_PKG_APPLY,
		Packages: filterPkgs, DryRun: dryRun,
	}

	// Policy gate + signed decision (real apply only; dry-run is read-only).
	if !dryRun {
		if err := c.policyGate(agentID, op, actor, opName); err != nil {
			return nil, err
		}
	}

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
// Decision (like files.policyGate). A deny is audited and returned as an
// error.
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
	if decision.Effect != policy.EffectAllow {
		c.audit(agentID, opName, op.OpId, actor, "denied", 0, decision.Reason)
		return fmt.Errorf("packages: %s denied by policy: %s", opName, decision.Reason)
	}
	// Sign the decision (agent guardrail verifies; arch §5.3).
	if c.ident != nil {
		version, _ := c.st.PolicyBundleVersion()
		sig := policy.SignDecision(c.ident.Priv, op.OpId, version,
			decision.Effect, decision.MatchedRules, actor.Role)
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