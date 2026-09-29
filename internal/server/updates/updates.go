// Package updates is the M8.1 step-3 rollout orchestrator: it drives a
// fleet self-update run (canary → waves) over the release store, the
// stream's signed directives, and the per-host state machine.
//
// The store (update_runs / update_hosts) is the source of truth; the
// in-memory loop is only a driver and can be re-attached after a server
// restart (ResumeAll). Trust is unchanged: the server never validates
// release content, and every agent re-verifies the signature before
// executing anything.
package updates

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/jobs"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/store"
)

const (
	// defaultPollS is how often a run loop re-reads its hosts and advances
	// the FSM (tests shorten it via SetPollInterval).
	defaultPollS = 2 * time.Second
	// hostTimeoutS bounds how long a dispatched host may take before the
	// run marks it timed_out (agent swap + health window + margin).
	hostTimeoutS = 15 * time.Minute
	// inFlight are the per-host statuses that count as "wave active".
)

const (
	StatusPending       = "pending"        // parked on an approval request
	StatusCanary        = "canary"         // canary cohort in flight
	StatusRolling       = "rolling"        // waves in flight
	StatusPausedFailure = "paused_failure" // wave failed; waiting for retry/skip/abort
	StatusCompleted     = "completed"
	StatusFailed        = "failed"
	StatusAborted       = "aborted"
)

const (
	HostQueued         = "queued"
	HostDispatching    = "dispatching"
	HostRestarting     = "restarting" // binary swapped; awaiting boot+connect
	HostVerified       = "verified"
	HostSkipped        = "skipped"
	HostFailedRollback = "failed_rollback"
	HostTimedOut       = "timed_out"
)

// Params is one rollout request. ReleaseID or Version selects the release
// (Version looks up (version, arch from release, kind=agent)).
type Params struct {
	ReleaseID   string   `json:"release_id,omitempty"`
	Version     string   `json:"version,omitempty"`
	Selector    string   `json:"selector,omitempty"`
	Canary      int      `json:"canary"`       // canary cohort size (0 = no canary phase)
	WavePct     int      `json:"wave_pct"`     // % of the resolved fleet per wave (default 25)
	CanaryHosts []string `json:"canary_hosts"` // explicit canary selection
	Actor       string   `json:"actor"`
	ActorRole   string   `json:"actor_role"`
}

// Manager drives update runs.
type Manager struct {
	st  *store.Store
	h   *stream.Handler
	sse stream.Emitter
	log *log.Logger

	mu    sync.Mutex
	loops map[string]chan struct{} // runID -> stop channel
	apr   *approvals.Controller
	jobC  *jobs.Controller

	poll time.Duration
}

func New(st *store.Store, h *stream.Handler, sse stream.Emitter, lg *log.Logger) *Manager {
	if lg == nil {
		lg = log.Default()
	}
	return &Manager{st: st, h: h, sse: sse, log: lg, loops: make(map[string]chan struct{}), poll: defaultPollS}
}

// SetPollInterval shortens the FSM tick (tests).
func (m *Manager) SetPollInterval(d time.Duration) {
	if d > 0 {
		m.poll = d
	}
}

// SetApprovals wires the approvals controller (require_approval runs park
// there; the manager registers its dispatcher at call time).
func (m *Manager) SetApprovals(apr *approvals.Controller) {
	m.apr = apr
	apr.RegisterDispatcher(policy.ActionUpdateApply, m.DispatchApprovedRun)
}

// SetJobs wires the jobs controller so a verified host gets its job
// decisions re-issued against the new version.
func (m *Manager) SetJobs(jobC *jobs.Controller) { m.jobC = jobC }

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

// StartRun resolves the selector, policy-gates update.apply per host, and
// creates the run. Outcomes:
//   - all allow: run starts (status canary|rolling), approval == nil
//   - any require_approval: run parked "pending" + an approval request is
//     created (the registered dispatcher starts the loop on approval)
//   - a canary host is denied: the run is not created
func (m *Manager) StartRun(p Params) (*store.UpdateRun, *store.ApprovalRequest, error) {
	if p.Selector == "" {
		p.Selector = "all"
	}
	if p.WavePct <= 0 {
		p.WavePct = 25
	}
	if p.WavePct > 100 {
		p.WavePct = 100
	}

	// Resolve the release (agent kind).
	rel, err := m.resolveRelease(p.ReleaseID, p.Version)
	if err != nil {
		return nil, nil, err
	}

	// Resolve the fleet server-side (the UI/CLI selector is server-authoritative).
	r := store.NewResolver(m.st)
	hosts, err := r.ResolveSelector(p.Selector)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve selector %q: %w", p.Selector, err)
	}
	if len(hosts) == 0 {
		return nil, nil, fmt.Errorf("selector %q matched no hosts", p.Selector)
	}
	ids := make([]string, 0, len(hosts))
	for _, hi := range hosts {
		ids = append(ids, hi.ID)
	}
	sort.Strings(ids)

	// Explicit canary hosts must be part of the resolved fleet.
	for _, c := range p.CanaryHosts {
		if !contains(ids, c) {
			return nil, nil, fmt.Errorf("canary host %s does not match selector %q", c, p.Selector)
		}
	}

	// Per-host policy gate (update.apply class).
	rules, _ := m.st.GetPolicyRules()
	var denied, approval []string
	for _, id := range ids {
		dec := policy.Evaluate(rules, policy.Action{
			ActionClass: policy.ActionUpdateApply,
			HostID:      id,
			ActorRole:   p.ActorRole,
		})
		switch dec.Effect {
		case policy.EffectDeny:
			denied = append(denied, id)
		case policy.EffectRequireApproval:
			approval = append(approval, id)
		}
	}

	now := time.Now().Unix()
	run := &store.UpdateRun{
		ID:          newRunID(),
		Version:     rel.Version,
		ReleaseID:   rel.ID,
		Arch:        rel.Arch,
		Selector:    p.Selector,
		CanaryCount: p.Canary,
		WavePct:     p.WavePct,
		CreatedBy:   p.Actor,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Canary cohort: explicit list, else the first N resolved hosts.
	cohort := p.CanaryHosts
	if len(cohort) == 0 && p.Canary > 0 {
		n := p.Canary
		if n > len(ids) {
			n = len(ids)
		}
		cohort = ids[:n]
	}
	for _, c := range cohort {
		if contains(denied, c) {
			return nil, nil, fmt.Errorf("policy denied update.apply for canary host %s (%s)", c, decReason(rules, c, p.ActorRole))
		}
	}
	run.CanaryHosts = strings.Join(cohort, ",")

	// Persist the fleet as per-host rows.
	uhs := make([]store.UpdateHost, 0, len(ids))
	for _, id := range ids {
		uh := store.UpdateHost{ID: newHostID(), RunID: run.ID, HostID: id, Status: HostQueued, UpdatedAt: now}
		if contains(denied, id) {
			// Non-canary denials are excluded up front, recorded as skipped.
			uh.Status = HostSkipped
			uh.Error = "policy: " + decReason(rules, id, p.ActorRole)
		}
		uhs = append(uhs, uh)
	}
	run.TotalHosts = len(ids)
	run.SkippedHosts = len(denied)

	// Park on approval if any host requires it.
	if len(approval) > 0 {
		run.Status = StatusPending
		if m.apr == nil {
			return nil, nil, fmt.Errorf("policy requires approval for %d host(s) but approvals are not configured", len(approval))
		}
		req, err := m.apr.NewRequest(approvals.NewRequestParams{
			ActionClass:  policy.ActionUpdateApply,
			RunID:        run.ID,
			Actor:        p.Actor,
			ActorRole:    p.ActorRole,
			MatchedRules: matchedRuleIDs(rules, approval, p.ActorRole),
			Payload: map[string]any{
				"params":   p,
				"run_id":   run.ID,
				"release":  rel.ID,
				"hosts":    len(ids),
				"approval": approval,
			},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("approval request: %w", err)
		}
		if err := m.st.CreateUpdateRun(run); err != nil {
			_, _ = m.apr.Deny(req.ID, "run create failed", approvals.Actor{Principal: p.Actor, Role: "admin"})
			return nil, nil, err
		}
		if err := m.st.AddUpdateHosts(run.ID, uhs); err != nil {
			_, _ = m.apr.Deny(req.ID, "run hosts insert failed", approvals.Actor{Principal: p.Actor, Role: "admin"})
			return nil, nil, err
		}
		_ = m.st.SetUpdateRunApproval(run.ID, req.ID)
		run.ApprovalID = req.ID
		m.emitRun(run)
		m.audit("update.run.created", p.Actor, map[string]any{"run": run.ID, "version": rel.Version, "selector": p.Selector, "state": "pending_approval", "approval": req.ID})
		return run, req, nil
	}

	// All allowed: start.
	if len(cohort) > 0 {
		run.Status = StatusCanary
	} else {
		run.Status = StatusRolling
		run.CurrentWave = 1
	}
	if err := m.st.CreateUpdateRun(run); err != nil {
		return nil, nil, err
	}
	if err := m.st.AddUpdateHosts(run.ID, uhs); err != nil {
		return nil, nil, err
	}
	m.audit("update.run.created", p.Actor, map[string]any{"run": run.ID, "version": rel.Version, "selector": p.Selector, "hosts": len(ids), "canary": cohort})
	m.emitRun(run)
	m.startLoop(run.ID)
	return run, nil, nil
}

// DispatchApprovedRun is the approvals-controller dispatcher: it resumes a
// parked run after an admin approved it.
func (m *Manager) DispatchApprovedRun(req *store.ApprovalRequest, dec *pb.Decision) error {
	var body struct {
		Params Params `json:"params"`
		RunID  string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(req.PayloadJSON), &body); err != nil {
		return fmt.Errorf("updates: bad approval payload: %w", err)
	}
	if body.RunID == "" {
		return fmt.Errorf("updates: approval payload missing run_id")
	}
	run, err := m.st.GetUpdateRun(body.RunID)
	if err != nil {
		return err
	}
	if run == nil {
		return fmt.Errorf("updates: run %s not found", body.RunID)
	}
	if store.TerminalUpdateRun(run.Status) {
		return fmt.Errorf("updates: run %s is already %s", run.ID, run.Status)
	}
	if run.Status != StatusPending {
		return fmt.Errorf("updates: run %s is %s, not pending", run.ID, run.Status)
	}
	if len(body.Params.CanaryHosts) > 0 || body.Params.Canary > 0 {
		if run.CanaryHosts != "" {
			run.Status = StatusCanary
		} else {
			run.Status = StatusRolling
			run.CurrentWave = 1
		}
	} else {
		run.Status = StatusRolling
		run.CurrentWave = 1
	}
	if err := m.st.SetUpdateRunStatus(run.ID, run.Status, ""); err != nil {
		return err
	}
	m.audit("update.run.approved", req.DecidedBy, map[string]any{"run": run.ID, "approval": req.ID})
	m.emitRun(run)
	m.startLoop(run.ID)
	return nil
}

func (m *Manager) resolveRelease(id, version string) (store.Release, error) {
	if id != "" {
		rel, err := m.st.GetRelease(id)
		if err != nil {
			return store.Release{}, err
		}
		if rel.Kind != "agent" {
			return store.Release{}, fmt.Errorf("release %s is kind %q; fleet runs need an agent release", id, rel.Kind)
		}
		return rel, nil
	}
	if version == "" {
		return store.Release{}, fmt.Errorf("updates: a release_id or version is required")
	}
	// Version without arch: take the only agent release at that version.
	var found store.Release
	var foundAny bool
	for _, arch := range []string{"linux-amd64", "linux-arm64"} {
		rel, err := m.st.GetReleaseByVer(version, arch, "agent")
		if err != nil {
			continue
		}
		if foundAny {
			return store.Release{}, fmt.Errorf("version %s has multiple archs; use release_id", version)
		}
		found, foundAny = rel, true
	}
	if !foundAny {
		return store.Release{}, store.ErrNoRelease
	}
	return found, nil
}

// matchedRuleIDs returns the rule IDs that forced approval for the given
// hosts (carried on the approval request for traceability).
func matchedRuleIDs(rules []policy.Rule, hostIDs []string, actorRole string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range hostIDs {
		dec := policy.Evaluate(rules, policy.Action{ActionClass: policy.ActionUpdateApply, HostID: id, ActorRole: actorRole})
		for _, r := range dec.MatchedRules {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

func decReason(rules []policy.Rule, hostID, actorRole string) string {
	dec := policy.Evaluate(rules, policy.Action{ActionClass: policy.ActionUpdateApply, HostID: hostID, ActorRole: actorRole})
	if dec.Reason != "" {
		return dec.Reason
	}
	switch dec.Effect {
	case policy.EffectDeny:
		return "denied by policy"
	case policy.EffectRequireApproval:
		return "policy requires approval"
	}
	return dec.Effect
}

// ---------------------------------------------------------------------------
// Result ingestion
// ---------------------------------------------------------------------------

// OnResult is the stream's UpdateResultHook: it maps an agent's update
// outcome onto its active per-host row. Results without an active row
// (canary apply outside a run, late duplicates) are ignored here — the
// stream layer already audits + SSEs them.
func (m *Manager) OnResult(agentID string, r *pb.UpdateResult) {
	row, err := m.st.ActiveUpdateHostFor(agentID)
	if err != nil || row == nil {
		return
	}
	switch r.Phase {
	case "failed":
		m.st.SetUpdateHostStatus(row.ID, HostFailedRollback, "", r.Error)
		m.clearPending(agentID)
	case "swapped":
		m.st.SetUpdateHostStatus(row.ID, HostRestarting, "", "")
	case "verified":
		m.st.SetUpdateHostStatus(row.ID, HostVerified, r.Version, "")
		m.reissueJobs(agentID)
		m.clearPending(agentID)
	default:
		return
	}
	if m.sse != nil {
		m.sse.Emit("update.host", map[string]string{
			"run_id": row.RunID, "host_id": agentID, "phase": r.Phase,
		})
	}
}

// clearPending drops any durable queued-directive row for a host that just
// reached a terminal update state: a stale directive must not be delivered
// later (after a server restart) to a host the run has already finished
// with. Idempotent; the row only exists if the host was offline when the
// directive was dispatched.
func (m *Manager) clearPending(agentID string) {
	if err := m.st.DeletePendingUpdate(agentID); err != nil {
		m.log.Printf("updates: clear pending %s: %v", agentID, err)
	}
}

// reissueJobs re-signs + re-pushes job decisions for a host whose version
// just changed, so jobs re-evaluate against the new version's facts.
func (m *Manager) reissueJobs(agentID string) {
	m.mu.Lock()
	jobC := m.jobC
	m.mu.Unlock()
	if jobC == nil {
		return
	}
	if err := jobC.ReissueForHost(agentID); err != nil {
		m.log.Printf("updates: reissue jobs for %s: %v", agentID, err)
	}
}

// ---------------------------------------------------------------------------
// Operator actions
// ---------------------------------------------------------------------------

// Retry re-dispatches the failed/timed-out hosts of a paused run (a new
// grant + directive each). A failed CANARY is not retryable — abort it.
func (m *Manager) Retry(runID, actor string) error {
	run, err := m.st.GetUpdateRun(runID)
	if err != nil || run == nil {
		return fmt.Errorf("updates: run %s not found", runID)
	}
	if run.Status != StatusPausedFailure && run.Status != StatusRolling && run.Status != StatusCanary {
		return fmt.Errorf("updates: run %s is %s; retry only from paused_failure/rolling/canary", runID, run.Status)
	}
	if run.Status == StatusCanary && run.CanaryHosts != "" {
		for _, cid := range splitIDs(run.CanaryHosts) {
			if h, _ := m.st.GetUpdateHost(runID, cid); h != nil && (h.Status == HostFailedRollback || h.Status == HostTimedOut) {
				return fmt.Errorf("updates: canary %s failed — abort the run (a canary failure is a hard gate)", cid)
			}
		}
	}
	hosts, err := m.st.ListUpdateHosts(runID)
	if err != nil {
		return err
	}
	rel, err := m.st.GetRelease(run.ReleaseID)
	if err != nil {
		return err
	}
	n := 0
	for _, h := range hosts {
		if h.Status != HostFailedRollback && h.Status != HostTimedOut {
			continue
		}
		if err := m.dispatchHost(run, h, rel); err != nil {
			m.log.Printf("updates: retry %s on %s: %v", runID, h.HostID, err)
			continue
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("updates: run %s has no failed hosts to retry", runID)
	}
	if err := m.st.SetUpdateRunStatus(runID, StatusRolling, ""); err != nil {
		return err
	}
	if run.Status == StatusCanary {
		// Canary retries (non-canary runs arrive here too) resume rolling
		// once the canary cohort is healthy.
	}
	m.audit("update.run.retry", actor, map[string]any{"run": runID, "hosts": n})
	m.emitRun(run)
	m.ensureLoop(runID)
	return nil
}

// Skip marks the failed/timed-out hosts of a paused run skipped and lets
// the remaining waves continue.
func (m *Manager) Skip(runID, actor string) error {
	run, err := m.st.GetUpdateRun(runID)
	if err != nil || run == nil {
		return fmt.Errorf("updates: run %s not found", runID)
	}
	if run.Status != StatusPausedFailure {
		return fmt.Errorf("updates: run %s is %s; skip only from paused_failure", runID, run.Status)
	}
	hosts, err := m.st.ListUpdateHosts(runID)
	if err != nil {
		return err
	}
	n := 0
	for _, h := range hosts {
		if h.Status == HostFailedRollback || h.Status == HostTimedOut {
			if err := m.st.SetUpdateHostStatus(h.ID, HostSkipped, "", "skipped by operator"); err == nil {
				m.clearPending(h.HostID)
				n++
			}
		}
	}
	if n == 0 {
		return fmt.Errorf("updates: run %s has no failed hosts to skip", runID)
	}
	if err := m.st.SetUpdateRunStatus(runID, StatusRolling, ""); err != nil {
		return err
	}
	m.audit("update.run.skip", actor, map[string]any{"run": runID, "hosts": n})
	m.emitRun(run)
	m.ensureLoop(runID)
	return nil
}

// Abort ends the run; queued hosts are left queued (they never ran).
func (m *Manager) Abort(runID, actor string) error {
	run, err := m.st.GetUpdateRun(runID)
	if err != nil || run == nil {
		return fmt.Errorf("updates: run %s not found", runID)
	}
	if store.TerminalUpdateRun(run.Status) {
		return fmt.Errorf("updates: run %s is already %s", runID, run.Status)
	}
	if err := m.st.SetUpdateRunStatus(runID, StatusAborted, "aborted by "+actor); err != nil {
		return err
	}
	// Terminate the run's non-terminal hosts so the board is consistent and
	// no queued directive for an aborted run is ever delivered.
	hosts, err := m.st.ListUpdateHosts(runID)
	if err == nil {
		for _, h := range hosts {
			if !store.TerminalRunHost(h.Status) {
				if err := m.st.SetUpdateHostStatus(h.ID, HostSkipped, "", "run aborted"); err == nil {
					m.clearPending(h.HostID)
				}
			}
		}
	}
	m.stopLoop(runID)
	m.audit("update.run.aborted", actor, map[string]any{"run": runID})
	m.emitRun(run)
	return nil
}

// ---------------------------------------------------------------------------
// The run loop (DB-driven FSM)
// ---------------------------------------------------------------------------

func (m *Manager) startLoop(runID string) { m.ensureLoop(runID) }

// ensureLoop attaches the driver goroutine for a run (idempotent).
func (m *Manager) ensureLoop(runID string) {
	m.mu.Lock()
	if ch, ok := m.loops[runID]; ok {
		_ = ch
		m.mu.Unlock()
		return
	}
	ch := make(chan struct{})
	m.loops[runID] = ch
	m.mu.Unlock()
	go m.runLoop(runID, ch)
}

// ResumeAll re-attaches loops for every non-terminal run (server restart).
func (m *Manager) ResumeAll(ctx context.Context) {
	runs, err := m.st.ListActiveUpdateRuns()
	if err != nil {
		m.log.Printf("updates: resume: %v", err)
		return
	}
	for _, r := range runs {
		if r.Status == StatusPending {
			continue // parked on approval; the dispatcher starts it
		}
		m.log.Printf("updates: resuming run %s (status %s)", r.ID, r.Status)
		m.ensureLoop(r.ID)
	}
}

func (m *Manager) stopLoop(runID string) {
	m.mu.Lock()
	ch, ok := m.loops[runID]
	if ok {
		delete(m.loops, runID)
	}
	m.mu.Unlock()
	if ok {
		close(ch)
	}
}

func (m *Manager) runLoop(runID string, stop <-chan struct{}) {
	defer m.stopLoop(runID)
	m.mu.Lock()
	poll := m.poll
	m.mu.Unlock()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		if err := m.step(runID); err != nil {
			m.log.Printf("updates: run %s: %v", runID, err)
			_ = m.st.SetUpdateRunStatus(runID, StatusFailed, err.Error())
			if run, _ := m.st.GetUpdateRun(runID); run != nil {
				m.emitRun(run)
			}
			return
		}
	}
}

// inFlightStatus reports whether a per-host status counts as "wave active".
func inFlightStatus(s string) bool {
	switch s {
	case HostDispatching, HostRestarting:
		return true
	}
	return false
}

func failedStatus(s string) bool {
	switch s {
	case HostFailedRollback, HostTimedOut:
		return true
	}
	return false
}

// step advances the FSM one tick. It reads the run + hosts from the store,
// applies transitions, persists them, and emits SSE on status changes.
func (m *Manager) step(runID string) error {
	run, err := m.st.GetUpdateRun(runID)
	if err != nil || run == nil {
		return fmt.Errorf("run %s not found", runID)
	}
	if store.TerminalUpdateRun(run.Status) {
		return nil
	}
	hosts, err := m.st.ListUpdateHosts(runID)
	if err != nil {
		return err
	}

	// Timeout sweep: in-flight hosts that go silent are timed out.
	now := time.Now().Unix()
	for _, h := range hosts {
		if inFlightStatus(h.Status) && now-h.UpdatedAt > int64(hostTimeoutS.Seconds()) {
			_ = m.st.SetUpdateHostStatus(h.ID, HostTimedOut, "", "no result within "+hostTimeoutS.String())
			m.clearPending(h.HostID)
		}
	}

	// Recompute the run's counters from the host rows (single source of
	// truth) and refresh the in-memory view.
	done, failed, skipped := 0, 0, 0
	for _, h := range hosts {
		switch h.Status {
		case HostVerified:
			done++
		case HostSkipped:
			skipped++
		case HostFailedRollback, HostTimedOut:
			failed++
		}
	}
	if run.DoneHosts != done || run.FailedHosts != failed || run.SkippedHosts != skipped {
		_ = m.st.SetUpdateRunCounters(run.ID, run.CurrentWave, run.TotalHosts, done, failed, skipped)
	}

	prev := run.Status
	switch run.Status {
	case StatusPending:
		// Waiting for the approval decision; nothing to do.
		return nil

	case StatusCanary:
		cohort := splitIDs(run.CanaryHosts)
		// Dispatch the queued canary cohort (first tick).
		if len(cohort) > 0 {
			rel, err := m.st.GetRelease(run.ReleaseID)
			if err != nil {
				return err
			}
			for _, h := range hosts {
				if h.Status == HostQueued && contains(cohort, h.HostID) {
					if err := m.dispatchHost(run, h, rel); err != nil {
						m.log.Printf("updates: canary dispatch %s: %v", h.HostID, err)
						_ = m.st.SetUpdateHostStatus(h.ID, HostFailedRollback, "", "dispatch: "+err.Error())
					}
				}
			}
		}
		var anyFailed bool
		allTerminal := true
		for _, h := range hosts {
			if !contains(cohort, h.HostID) {
				continue
			}
			if failedStatus(h.Status) {
				anyFailed = true
			}
			if !store.TerminalRunHost(h.Status) {
				allTerminal = false
			}
		}
		if anyFailed {
			// A canary failure is a hard gate: the whole run fails.
			_ = m.st.SetUpdateRunStatus(runID, StatusFailed, "canary failed (hard gate)")
			m.audit("update.run.canary_failed", "system", map[string]any{"run": runID})
			return nil
		}
		if allTerminal {
			// Canary cleared (hard gate passed): move to rolling, wave 1.
			_ = m.st.SetUpdateRunCounters(runID, 1, run.TotalHosts, done, failed, skipped)
			_ = m.st.SetUpdateRunStatus(runID, StatusRolling, "")
			m.audit("update.run.canary_passed", "system", map[string]any{"run": runID, "canary": cohort})
			if run2, _ := m.st.GetUpdateRun(runID); run2 != nil {
				run2.Status = StatusRolling
				run2.CurrentWave = 1
				m.emitRun(run2)
			}
		}
		return nil

	case StatusRolling:
		var active, failed, queued []*store.UpdateHost
		for _, h := range hosts {
			switch {
			case inFlightStatus(h.Status):
				active = append(active, h)
			case failedStatus(h.Status):
				failed = append(failed, h)
			case h.Status == HostQueued:
				queued = append(queued, h)
			}
		}
		// Nothing in flight: either finish, pause on failure, or dispatch
		// the next wave.
		if len(active) == 0 {
			if len(failed) > 0 {
				_ = m.st.SetUpdateRunStatus(runID, StatusPausedFailure, "wave failed; operator must retry/skip/abort")
				m.audit("update.run.paused", "system", map[string]any{"run": runID, "failed": len(failed)})
				return nil
			}
			if len(queued) == 0 {
				// Everything is terminal.
				_ = m.st.SetUpdateRunStatus(runID, StatusCompleted, "")
				m.audit("update.run.completed", "system", map[string]any{"run": runID, "verified": done, "skipped": skipped, "failed": failed})
				return nil
			}
			// Dispatch the next wave. CurrentWave counts waves dispatched
			// (the canary phase seeds it at 1), so bump before dispatching:
			// the UI/CLI then always shows the wave actually in flight.
			wave := waveSize(len(hosts), run.WavePct)
			if wave > len(queued) {
				wave = len(queued)
			}
			rel, err := m.st.GetRelease(run.ReleaseID)
			if err != nil {
				return err
			}
			nextWave := run.CurrentWave + 1
			_ = m.st.SetUpdateRunCounters(run.ID, nextWave, run.TotalHosts, done, 0, skipped)
			run.CurrentWave = nextWave
			for i := 0; i < wave; i++ {
				h := queued[i]
				if err := m.dispatchHost(run, h, rel); err != nil {
					m.log.Printf("updates: dispatch %s on %s: %v", runID, h.HostID, err)
					_ = m.st.SetUpdateHostStatus(h.ID, HostFailedRollback, "", "dispatch: "+err.Error())
					failed = append(failed, h)
				}
			}
			return nil
		}
		// Wave in progress: wait for it to complete (results arrive via
		// OnResult; this tick just re-checks).
		return nil

	case StatusPausedFailure:
		// Waiting for the operator; nothing to do.
		return nil
	}

	if run.Status != prev && m.sse != nil {
		m.emitRunStatus(runID, run.Status)
	}
	return nil
}

// waveSize is max(1, pct% of the total fleet).
func waveSize(total, pct int) int {
	n := total * pct / 100
	if n < 1 {
		n = 1
	}
	return n
}

// dispatchHost mints a fresh grant and queues the signed directive for one
// host. The host moves queued -> dispatching.
func (m *Manager) dispatchHost(run *store.UpdateRun, h *store.UpdateHost, rel store.Release) error {
	tok, err := m.h.IssueUpdateGrant(h.HostID, rel.ID)
	if err != nil {
		return err
	}
	dir := &pb.UpdateDirective{
		ReleaseId: rel.ID,
		Version:   rel.Version,
		Arch:      rel.Arch,
		Kind:      "agent",
		Sha256:    rel.SHA256,
		Signature: rel.Signature,
		Grant:     tok,
	}
	if err := m.h.QueueUpdateDirective(h.HostID, dir); err != nil {
		return err
	}
	if err := m.st.SetUpdateHostStatus(h.ID, HostDispatching, "", ""); err != nil {
		return err
	}
	m.audit("update.dispatch", run.CreatedBy, map[string]any{"run": run.ID, "host": h.HostID, "release": rel.ID, "grant": tok})
	return nil
}

// ---------------------------------------------------------------------------
// SSE + audit
// ---------------------------------------------------------------------------

func (m *Manager) emitRun(run *store.UpdateRun) {
	if m.sse == nil {
		return
	}
	m.sse.Emit("update.run", map[string]string{
		"run_id": run.ID, "status": run.Status, "version": run.Version,
		"wave":   fmt.Sprintf("%d", run.CurrentWave),
		"done":   fmt.Sprintf("%d", run.DoneHosts),
		"failed": fmt.Sprintf("%d", run.FailedHosts),
		"total":  fmt.Sprintf("%d", run.TotalHosts),
	})
}

func (m *Manager) emitRunStatus(runID, status string) {
	if m.sse == nil {
		return
	}
	m.sse.Emit("update.run", map[string]string{"run_id": runID, "status": status})
}

func (m *Manager) audit(kind, actor string, payload map[string]any) {
	b, _ := json.Marshal(payload)
	_ = m.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: kind, Actor: actor, Payload: string(b),
	})
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

var idCounter uint64 = 0
var idMu sync.Mutex

func newID(prefix string) string {
	idMu.Lock()
	defer idMu.Unlock()
	idCounter++
	return fmt.Sprintf("%s_%d_%06x", prefix, time.Now().UnixNano(), idCounter)
}

func newRunID() string  { return newID("run") }
func newHostID() string { return newID("uh") }

func splitIDs(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
