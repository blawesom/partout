// Package api — provisioning REST endpoints (PRD R17, arch §3.5).
// All endpoints are admin-gated (RBAC).
package api

import (
	"net/http"

	"github.com/blawesom/partout/internal/store"
)

// RegisterProvision adds admin-gated provisioning endpoints.
// When the provisioner is not yet set, handlers return 503.
func (h *Handler) RegisterProvision(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/provision-runs", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleCreateRun)))
	mux.Handle("GET /api/v1/provision-runs", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListRuns)))
	mux.Handle("GET /api/v1/provision-runs/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetRun)))
	mux.Handle("POST /api/v1/provision-runs/{id}/key", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleConfirmKey)))
	mux.Handle("POST /api/v1/provision-runs/{id}/cancel", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleCancelRun)))
}

// ---- admin: create provisioning run ----------------------------------------

type createRunRequest struct {
	Host string `json:"host"`
	Mode string `json:"mode"`
}

func (h *Handler) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	var req createRunRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "host is required", nil)
		return
	}
	if req.Mode == "" {
		req.Mode = "fresh"
	}
	run, err := h.prov.Start(req.Host, req.Mode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error",
			"failed to start provisioning: "+err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": run.ID, "state": run.State, "host": run.Host})
}

// ---- viewer: list provisioning runs ----------------------------------------

type listRunsResponse struct {
	Items []*store.ProvisionRun `json:"items"`
}

func (h *Handler) handleListRuns(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	limit := queryInt(r, "limit", 50)
	runs, err := h.st.ProvisionRuns(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error",
			"list runs: "+err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, listRunsResponse{Items: runs})
}

// ---- viewer: get provisioning run + steps -----------------------------------

type getRunResponse struct {
	Run   *store.ProvisionRun    `json:"run"`
	Steps []*store.ProvisionStep `json:"steps"`
}

func (h *Handler) handleGetRun(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	runID := r.PathValue("id")
	run, err := h.st.ProvisionRun(runID)
	if err != nil || run == nil {
		writeError(w, http.StatusNotFound, "not_found", "provision run not found", nil)
		return
	}
	steps, err := h.st.ProvisionRunSteps(runID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error",
			"list steps: "+err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, getRunResponse{Run: run, Steps: steps})
}

// ---- admin: confirm/deny host key ------------------------------------------

type confirmKeyRequest struct {
	Action string `json:"action"` // "confirm" or "deny"
}

func (h *Handler) handleConfirmKey(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	runID := r.PathValue("id")
	var req confirmKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	switch req.Action {
	case "confirm":
		if err := h.prov.ConfirmKey(runID); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"action": "confirmed"})
	case "deny":
		if err := h.prov.DenyKey(runID); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"action": "denied"})
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "action must be confirm or deny", nil)
	}
}

// ---- admin: cancel provisioning run -----------------------------------------

func (h *Handler) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	runID := r.PathValue("id")
	if err := h.prov.Cancel(runID); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"action": "cancelled"})
}

// ---- helpers ---------------------------------------------------------------

func (h *Handler) provIsReady() bool { return h.prov != nil }
