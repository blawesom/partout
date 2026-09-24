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
	"net/http"

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
	return packages.Actor{Principal: h.roleFor(r), Role: h.roleFor(r)}
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
	var body struct {
		AgentID  string   `json:"agent_id"`
		Packages []string `json:"packages,omitempty"`
		DryRun   bool     `json:"dry_run"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if body.AgentID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id required", nil)
		return
	}
	a, err := h.pkgs.Apply(r.Context(), body.AgentID, h.pkgActor(r), body.Packages, body.DryRun)
	if err != nil {
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