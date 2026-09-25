// Package api — capability probe (ui-guidelines B1, S0 prerequisite).
//
// GET /api/v1/capabilities returns a boolean per subsystem so the UI can
// gate its chrome on *what this build actually wires*, not on hardcoded
// milestone assumptions (ui-guidelines §4). The UI must render a control
// enabled only if the probe says so; unknown/absent ⇒ unavailable.
package api

import (
	"net/http"
)

// RegisterCapabilities adds the probe endpoint (viewer).
func (h *Handler) RegisterCapabilities(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/capabilities", h.requireRole(roleViewer)(http.HandlerFunc(h.handleCapabilities)))
}

func (h *Handler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	caps := map[string]bool{
		// Core control plane — wired in every build.
		"hosts":    true,
		"groups":   true,
		"exec":     h.ctrl != nil,
		"policies": h.ctrl != nil,
		"audit":    true,

		// M2 — wired when the controller/manager is installed.
		"files":    h.files != nil,
		"sessions": h.sess != nil,

		// M3 — wired when the controller/manager is installed.
		"jobs":     h.jobs != nil,
		"tasks":    h.tasks != nil,
		"packages": h.pkgs != nil,
		"secrets":  h.secretsMgr != nil,

		// External data (EOL / vulnerability feeds) — wired when installed.
		"external_data": h.extdata != nil,

		// M1 host provisioning — wired when a provisioner is installed.
		"provision": h.prov != nil,

		// Local-user identity (PRD Decision 6). When false the server runs in
		// single-user local mode (all requests are admin); the UI still shows
		// the account surface, just without a password gate.
		"auth":  h.authC != nil,
		"users": h.usersActive,

		// M5 observe read path (R18–R20) — wired in this build.
		"observe": true,

		// M6 alert engine and M4 approvals — not built yet. The UI renders
		// these as "not yet available (M6/M4)" placeholders, and the probe
		// must say so honestly rather than let the UI guess.
		"alerts":    false,
		"approvals": false,
	}
	writeJSON(w, http.StatusOK, caps)
}
