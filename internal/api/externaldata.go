// REST handlers for external data (M3, PRD §6.3).
//
// Routes:
//
//	GET  /api/v1/external-data/status        (viewer) — refresh status + counts
//	POST /api/v1/external-data/refresh       (admin)  — trigger a manual refresh
//	GET  /api/v1/hosts/{id}/eol              (viewer) — one host's EOL state
package api

import (
	"net/http"
)

// RegisterExternalData wires the external data REST routes.
func (h *Handler) RegisterExternalData(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/external-data/status", h.requireRole(roleViewer)(http.HandlerFunc(h.extStatus)))
	mux.Handle("POST /api/v1/external-data/refresh", h.requireRole(roleAdmin)(http.HandlerFunc(h.extRefresh)))
	mux.Handle("GET /api/v1/hosts/{id}/eol", h.requireRole(roleViewer)(http.HandlerFunc(h.extHostEOL)))
}

// extStatus returns the external data subsystem status.
func (h *Handler) extStatus(w http.ResponseWriter, r *http.Request) {
	if h.extdata == nil {
		writeError(w, http.StatusServiceUnavailable, "external_data_disabled",
			"external data not initialized", nil)
		return
	}
	writeJSON(w, http.StatusOK, h.extdata.GetStatus())
}

// extRefresh triggers a manual EOL refresh (admin only).
func (h *Handler) extRefresh(w http.ResponseWriter, r *http.Request) {
	if h.extdata == nil {
		writeError(w, http.StatusServiceUnavailable, "external_data_disabled",
			"external data not initialized", nil)
		return
	}
	ctx := r.Context()
	n, err := h.extdata.DoRefresh(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "refresh_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": n, "status": "ok"})
}

// extHostEOL returns the EOL state for one host (from its os-release facts).
func (h *Handler) extHostEOL(w http.ResponseWriter, r *http.Request) {
	if h.extdata == nil {
		writeError(w, http.StatusServiceUnavailable, "external_data_disabled",
			"external data not initialized", nil)
		return
	}
	agentID := r.PathValue("id")
	facts, err := h.st.LatestFacts(agentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no facts for host", nil)
		return
	}
	distro, _ := facts.Data["host.distro"]
	cycle, _ := facts.Data["host.distro_version"]
	if distro == "" {
		writeError(w, http.StatusNotFound, "no_os_release",
			"host has no os-release facts (non-Linux?)", nil)
		return
	}
	st := h.extdata.EOLStateFor(distro, cycle)
	writeJSON(w, http.StatusOK, st)
}