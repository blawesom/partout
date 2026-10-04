// Package api — provisioning REST endpoints (PRD R17, arch §3.5).
// All endpoints are admin-gated (RBAC).
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/blawesom/partout/internal/server/provision"
	"github.com/blawesom/partout/internal/store"
)

// RegisterProvision adds admin-gated provisioning endpoints.
// When the provisioner is not yet set, handlers return 503.
func (h *Handler) RegisterProvision(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/provision-runs", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleCreateRun)))
	mux.Handle("GET /api/v1/provision-runs", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListRuns)))
	mux.Handle("GET /api/v1/provision-runs/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetRun)))
	mux.Handle("POST /api/v1/provision-runs/{id}/key", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleConfirmKey)))
	mux.Handle("POST /api/v1/provision-runs/{id}/rekey", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleReconfirmKey)))
	mux.Handle("POST /api/v1/provision-runs/{id}/cancel", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleCancelRun)))
	mux.Handle("GET /api/v1/provision/ssh-status", h.requireRole(roleViewer)(http.HandlerFunc(h.handleSSHStatus)))
}

// ---- admin: create provisioning run ----------------------------------------

type createRunRequest struct {
	Host string `json:"host"`
	Mode string `json:"mode"`
	// D1 onboarding options: elevation bootstrap + agent.env extras.
	Elevate           bool               `json:"elevate"`
	ElevationPolicies []elevationRefSpec `json:"elevation_policies"`
	ServiceLabels     string             `json:"service_labels"`
	CertPaths         string             `json:"cert_paths"`
}

// elevationRefSpec is one policy by store name, or inline rules.
type elevationRefSpec struct {
	Name  string          `json:"name"`
	Rules json.RawMessage `json:"rules"`
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
	if req.Mode != "fresh" && req.Mode != "join" {
		writeError(w, http.StatusBadRequest, "bad_request",
			"mode must be fresh or join", nil)
		return
	}
	// Resolve the elevation policies: store names and/or inline rules →
	// concrete content for the provisioner (fail fast on anything bad).
	var policies []provision.ElevationPolicySpec
	for _, ref := range req.ElevationPolicies {
		if len(ref.Rules) > 0 {
			policies = append(policies, provision.ElevationPolicySpec{
				Name: ref.Name, RulesJSON: string(ref.Rules),
			})
			continue
		}
		if ref.Name == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "elevation policy: name or rules required", nil)
			return
		}
		p, err := h.st.ElevationPolicy(ref.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "unknown elevation policy: "+ref.Name, nil)
			return
		}
		policies = append(policies, provision.ElevationPolicySpec{
			Name: p.Name, RulesJSON: p.RulesJSON, SHA: p.PolicySHA,
		})
	}
	// --elevate with no explicit policy defaults to the seeded baseline
	// (ready-to-apply posture: the operator is admin; the grant is visible
	// in the run detail and revocable by re-provisioning).
	if req.Elevate && len(policies) == 0 {
		p, err := h.st.ElevationPolicy("default-baseline")
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request",
				"--elevate needs --elevation-policy or a seeded default-baseline policy (partout ctl preset apply)", nil)
			return
		}
		policies = append(policies, provision.ElevationPolicySpec{
			Name: p.Name, RulesJSON: p.RulesJSON, SHA: p.PolicySHA,
		})
	}
	run, err := h.prov.Start(req.Host, req.Mode, provision.StartOptions{
		Elevate:           req.Elevate,
		ElevationPolicies: policies,
		ServiceLabels:     req.ServiceLabels,
		CertPaths:         req.CertPaths,
	})
	if err != nil {
		// A concurrent run for the same host is a conflict, not a server
		// error — the operator should see which run holds the host.
		if errors.Is(err, provision.ErrHostBusy) {
			writeError(w, http.StatusConflict, "host_busy", err.Error(), nil)
			return
		}
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
	if _, err := h.st.ProvisionRun(runID); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "provision run not found", nil)
		return
	}
	var req confirmKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	switch req.Action {
	case "confirm":
		if err := h.prov.ConfirmKey(runID); err != nil {
			// A duplicate/racing confirm is a conflict, not a bad request.
			writeError(w, http.StatusConflict, "not_pending", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"action": "confirmed"})
	case "deny":
		if err := h.prov.DenyKey(runID); err != nil {
			writeError(w, http.StatusConflict, "not_pending", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"action": "denied"})
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "action must be confirm or deny", nil)
	}
}

// ---- admin: re-confirm a rotated host key -----------------------------------

// handleReconfirmKey restarts the fingerprint gate for a failed run whose
// host key no longer matches the trusted entry (host reinstalled): the
// stale entry is removed, the current key re-captured, and the run paused
// at key_confirm again.
func (h *Handler) handleReconfirmKey(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	runID := r.PathValue("id")
	if _, err := h.st.ProvisionRun(runID); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "provision run not found", nil)
		return
	}
	if err := h.prov.ReconfirmKey(runID); err != nil {
		writeError(w, http.StatusConflict, "rekey_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"action": "reconfirming"})
}

// ---- admin: cancel provisioning run -----------------------------------------

func (h *Handler) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	runID := r.PathValue("id")
	run, err := h.st.ProvisionRun(runID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "provision run not found", nil)
		return
	}
	if err := h.prov.Cancel(runID); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	// Cancel is a no-op on an already-terminal run: report the real outcome
	// instead of claiming a fresh cancellation.
	if next, err := h.st.ProvisionRun(runID); err == nil && next.State == run.State {
		writeJSON(w, http.StatusOK, map[string]string{"action": "noop", "state": run.State})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"action": "cancelled"})
}

// ---- viewer: ssh identity readiness for provisioning ---------------------

// handleSSHStatus reports the identity keys the provisioner would offer, so
// the wizard can show the operator what will be used (or that none was
// found) before starting a run. Read-only; exposes file paths + a boolean
// only, never key material. An optional ?host= parameter resolves the ssh
// config for that specific target (alias + host-specific IdentityFile
// blocks) — without it the probe is host-agnostic (defaults + "Host *").
func (h *Handler) handleSSHStatus(w http.ResponseWriter, r *http.Request) {
	if !h.provIsReady() {
		writeError(w, http.StatusServiceUnavailable, "provisioner_unavailable",
			"provisioner not yet configured", nil)
		return
	}
	writeJSON(w, http.StatusOK, h.prov.SSHStatusFor(r.URL.Query().Get("host")))
}

// ---- helpers ---------------------------------------------------------------

func (h *Handler) provIsReady() bool { return h.prov != nil }
