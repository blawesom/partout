// REST handlers for package management (M3, PRD §5.6).
//
// Routes (auth: list/actions = viewer+, apply = operator+):
//
//	GET  /api/v1/packages/updates?agent_id=
//	GET  /api/v1/packages/actions
//	GET  /api/v1/packages/actions/:id
//	POST /api/v1/packages/apply   {agent_id, packages[], dry_run}
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/blawesom/partout/internal/server/packages"
	"github.com/blawesom/partout/internal/store"
)

// RegisterPackages wires the package REST routes. Routes return 503 until
// SetPackages installs the controller.
func (h *Handler) RegisterPackages(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/packages/updates", h.requireRole(roleViewer)(http.HandlerFunc(h.pkgUpdates)))
	mux.Handle("GET /api/v1/packages/actions", h.requireRole(roleViewer)(http.HandlerFunc(h.pkgActions)))
	mux.Handle("GET /api/v1/packages/actions/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.pkgActionGet)))
	mux.Handle("POST /api/v1/packages/apply", h.requireRole(roleOperator)(http.HandlerFunc(h.pkgApply)))
}

func (h *Handler) pkgActor(r *http.Request) packages.Actor {
	principal, role := h.actorFor(r)
	return packages.Actor{Principal: principal, Role: role}
}

// pkgUpdates lists available updates for a host.
func (h *Handler) pkgUpdates(w http.ResponseWriter, r *http.Request) {
	if h.pkgs == nil {
		writeError(w, http.StatusServiceUnavailable, "packages_disabled", "packages subsystem not initialized", nil)
		return
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id required", nil)
		return
	}
	ups, err := h.pkgs.ListUpdates(r.Context(), agentID, h.pkgActor(r))
	if err != nil {
		h.pkgErr(w, err)
		return
	}
	// Convert proto PkgUpdate → JSON.
	jups := make([]map[string]any, 0, len(ups))
	for _, u := range ups {
		jups = append(jups, map[string]any{
			"name":         u.Name,
			"installed":    u.Installed,
			"available":    u.Available,
			"vuln_count":   u.VulnCount,
			"max_severity": u.MaxSeverity,
			"is_security":  u.IsSecurity,
		})
	}
	writeJSON(w, http.StatusOK, jups)
}

// pkgActions lists recent package actions.
func (h *Handler) pkgActions(w http.ResponseWriter, r *http.Request) {
	if h.pkgs == nil {
		writeError(w, http.StatusServiceUnavailable, "packages_disabled", "packages subsystem not initialized", nil)
		return
	}
	actions, err := h.pkgs.ListActions(50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(actions))
	for _, a := range actions {
		out = append(out, pkgActionJSON(a))
	}
	writeJSON(w, http.StatusOK, out)
}

// pkgActionGet fetches one package action by ID.
func (h *Handler) pkgActionGet(w http.ResponseWriter, r *http.Request) {
	if h.pkgs == nil {
		writeError(w, http.StatusServiceUnavailable, "packages_disabled", "packages subsystem not initialized", nil)
		return
	}
	id := r.PathValue("id")
	a, err := h.pkgs.GetAction(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	if a == nil {
		writeError(w, http.StatusNotFound, "not_found", "package action not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, pkgActionJSON(a))
}

// pkgApply triggers an apply-updates (or dry-run) on a host.
func (h *Handler) pkgApply(w http.ResponseWriter, r *http.Request) {
	if h.pkgs == nil {
		writeError(w, http.StatusServiceUnavailable, "packages_disabled", "packages subsystem not initialized", nil)
		return
	}
	var body pkgApplyRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	targets, err := parseApplyTargets(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	// Single target: legacy path, response shape unchanged (MCP tool and
	// `partout ctl` use this form).
	if len(targets) == 1 {
		h.applyOne(w, r, targets[0], body.DryRun)
		return
	}
	// Fan-out: every target runs the SAME single-host Apply concurrently —
	// each host independently gets its policy gate, signed decision,
	// approval parking, and audit row. Outcomes are independent, so this
	// always returns 200 with per-target results + a summary.
	results := fanoutApply(r.Context(), func(ctx context.Context, agentID string, pkgs []string, dryRun bool) (*store.PkgAction, error) {
		return h.pkgs.Apply(ctx, agentID, h.pkgActor(r), pkgs, dryRun)
	}, targets, body.DryRun)
	writeJSON(w, http.StatusOK, results)
}

// applyOne is the single-target apply (the pre-fanout handler body).
func (h *Handler) applyOne(w http.ResponseWriter, r *http.Request, t pkgApplyTarget, dryRun bool) {
	a, err := h.pkgs.Apply(r.Context(), t.AgentID, h.pkgActor(r), t.Packages, dryRun)
	if err != nil {
		var apprErr *packages.ApprovalRequiredError
		if errors.As(err, &apprErr) {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"state":       "approval_required",
				"approval_id": apprErr.ApprovalID,
				"message":     "apply parked on an approval request; an admin must approve it",
			})
			return
		}
		h.pkgErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pkgActionJSON(a))
}

// pkgActionJSON converts a store.PkgAction to a JSON-friendly map.
func pkgActionJSON(a *store.PkgAction) map[string]any {
	return map[string]any{
		"id":            a.ID,
		"agent_id":      a.AgentID,
		"kind":          a.Kind,
		"status":        a.Status,
		"dry_summary":   a.DrySummary,
		"applied_count": a.AppliedCount,
		"error":         a.Error,
		"created":       a.Created,
	}
}

// pkgErr maps a package controller error to an HTTP response.
func (h *Handler) pkgErr(w http.ResponseWriter, err error) {
	// Policy denial → 403; stream/timeout → 504; other → 500.
	switch {
	case isPolicyDeny(err):
		writeError(w, http.StatusForbidden, "denied", err.Error(), nil)
	default:
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
	}
}

// ---- fan-out apply (multi-host) -------------------------------------------

// pkgApplyRequest accepts two forms:
//
//	legacy single host: {agent_id, packages[], dry_run}
//	fan-out N hosts:    {targets: [{agent_id, packages[]}, ...], dry_run}
//
// packages[] empty means "all pending updates" on that host (unchanged).
type pkgApplyRequest struct {
	AgentID  string   `json:"agent_id"`
	Packages []string `json:"packages,omitempty"`
	DryRun   bool     `json:"dry_run"`
	Targets  []struct {
		AgentID  string   `json:"agent_id"`
		Packages []string `json:"packages,omitempty"`
	} `json:"targets,omitempty"`
}

// pkgApplyTarget is one (host, packages) pair in an apply.
type pkgApplyTarget struct {
	AgentID  string
	Packages []string
}

// parseApplyTargets normalizes the request forms into a validated target
// list: explicit targets[] win; otherwise the legacy agent_id field is a
// single target. Duplicate hosts are rejected (per-host outcomes are
// independent; one target per host keeps the audit trail unambiguous).
func parseApplyTargets(body pkgApplyRequest) ([]pkgApplyTarget, error) {
	if len(body.Targets) > 0 {
		targets := make([]pkgApplyTarget, 0, len(body.Targets))
		seen := make(map[string]bool, len(body.Targets))
		for _, t := range body.Targets {
			id := strings.TrimSpace(t.AgentID)
			if id == "" {
				return nil, errors.New("targets[].agent_id is required")
			}
			if seen[id] {
				return nil, fmt.Errorf("duplicate agent_id in targets: %s", id)
			}
			seen[id] = true
			targets = append(targets, pkgApplyTarget{AgentID: id, Packages: t.Packages})
		}
		return targets, nil
	}
	if strings.TrimSpace(body.AgentID) == "" {
		return nil, errors.New("agent_id required (or targets)")
	}
	return []pkgApplyTarget{{AgentID: strings.TrimSpace(body.AgentID), Packages: body.Packages}}, nil
}

// fanoutApply runs apply for every target concurrently and aggregates
// per-target outcomes. apply mirrors *packages.Controller.Apply (one call
// per host; each keeps its own policy gate, decision, approval, audit).
// Returns {results: [...], summary: {ok, approval_required, error}}.
func fanoutApply(ctx context.Context, apply func(ctx context.Context, agentID string, pkgs []string, dryRun bool) (*store.PkgAction, error), targets []pkgApplyTarget, dryRun bool) map[string]any {
	results := make([]map[string]any, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t pkgApplyTarget) {
			defer wg.Done()
			res := map[string]any{"agent_id": t.AgentID}
			a, err := apply(ctx, t.AgentID, t.Packages, dryRun)
			switch {
			case err == nil:
				res["state"] = "ok"
				for k, v := range pkgActionJSON(a) {
					res[k] = v
				}
			default:
				var apprErr *packages.ApprovalRequiredError
				if errors.As(err, &apprErr) {
					res["state"] = "approval_required"
					res["approval_id"] = apprErr.ApprovalID
					res["message"] = "apply parked on an approval request; an admin must approve it"
				} else {
					res["state"] = "error"
					res["error"] = err.Error()
				}
			}
			results[i] = res
		}(i, t)
	}
	wg.Wait()
	summary := map[string]int{"ok": 0, "approval_required": 0, "error": 0}
	for _, res := range results {
		summary[res["state"].(string)]++
	}
	return map[string]any{"results": results, "summary": summary}
}
