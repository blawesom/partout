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
		// Secrets master key: env, or the data-dir default file the UI
		// bootstrap creates (POST /api/v1/secrets/bootstrap installs the
		// manager at runtime).
		"secrets": h.secretsMgr != nil,

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

		// M6 alert engine (PRD R23/R25) — wired in this build: rules CRUD,
		// GET /alerts, SSE alert.firing/alert.resolved, MCP list_alerts.
		"alerts": true,
		// M4 approvals — wired when the approvals controller is installed.
		"approvals": h.approvals != nil,

		// M4 MCP server (R11) — true once the /mcp route is registered.
		// The UI gates its MCP page on this; the info endpoint is always
		// available (read-only catalog) but the live surface is only usable
		// when wired.
		"mcp": h.mcpWired,
		// R26 assistant: configured AND enabled (the nav entry hides when off).
		"assistant": h.assistant != nil && h.assistantEnabled(),
	}
	writeJSON(w, http.StatusOK, caps)
}
