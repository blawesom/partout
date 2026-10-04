// Package api — fleet-management preset endpoints.
//
// The preset seeds a sensible safety net (deny rules + standard alert
// rules) on first boot. These endpoints let an operator re-apply missing
// defaults (e.g. after a restore) or inspect what a fresh install would
// have, without hand-creating each row.
package api

import (
	"net/http"

	"github.com/blawesom/partout/internal/preset"
)

// RegisterPreset mounts the preset routes.
func (h *Handler) RegisterPreset(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/preset", h.requireRole(roleViewer)(http.HandlerFunc(h.handlePresetStatus)))
	mux.Handle("POST /api/v1/preset/apply", h.requireRole(roleAdmin)(http.HandlerFunc(h.handlePresetApply)))
}

func (h *Handler) handlePresetStatus(w http.ResponseWriter, r *http.Request) {
	st, err := preset.Status(h.st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "preset status", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *Handler) handlePresetApply(w http.ResponseWriter, r *http.Request) {
	res, err := preset.Apply(h.st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "apply preset", err)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("preset.apply", actor, map[string]string{
		"created_policies":           joinOrNone(res.Policies),
		"created_alerts":             joinOrNone(res.Alerts),
		"created_elevation_policies": joinOrNone(res.ElevationPolicies),
		"created_tasks":              joinOrNone(res.Tasks),
		"created_jobs":               joinOrNone(res.Jobs),
	})
	// If new policy rows were added, push the updated bundle so agents
	// re-check against the new rule set immediately.
	if len(res.Policies) > 0 {
		h.ctrl.BroadcastPolicyBundle()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"created_policies":           res.Policies,
		"created_alerts":             res.Alerts,
		"created_elevation_policies": res.ElevationPolicies,
		"created_tasks":              res.Tasks,
		"created_jobs":               res.Jobs,
	})
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
