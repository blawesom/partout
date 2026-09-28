// REST handlers for the approvals engine (M4, PRD §5.8).
//
// Routes (auth: list/get = viewer+, approve/deny = admin):
//
//	GET   /api/v1/approvals?state=&limit=
//	GET   /api/v1/approvals/{id}
//	POST  /api/v1/approvals/{id}/approve
//	POST  /api/v1/approvals/{id}/deny   {reason?}
package api

import (
	"net/http"
	"strings"

	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/oauth"
	"github.com/blawesom/partout/internal/store"
)

// RegisterApprovals wires the approvals REST routes. Routes return 503
// until SetApprovals installs the controller.
func (h *Handler) RegisterApprovals(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/approvals", h.requireRole(roleViewer)(http.HandlerFunc(h.approvalsList)))
	mux.Handle("GET /api/v1/approvals/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.approvalGet)))
	mux.Handle("POST /api/v1/approvals/{id}/approve", h.requireRole(roleAdmin)(http.HandlerFunc(h.approvalApprove)))
	mux.Handle("POST /api/v1/approvals/{id}/deny", h.requireRole(roleAdmin)(http.HandlerFunc(h.approvalDeny)))
}

// SetOAuth installs the OAuth2 (PKCE) manager (M4, R11/A20).
func (h *Handler) SetOAuth(m *oauth.Manager) { h.oauthC = m }

// SetApprovals installs the approvals controller (M4).
func (h *Handler) SetApprovals(ac *approvals.Controller) { h.approvals = ac }

func (h *Handler) approvalActor(r *http.Request) approvals.Actor {
	principal, role := h.actorFor(r)
	return approvals.Actor{Principal: principal, Role: role}
}

func approvalJSON(r *store.ApprovalRequest) map[string]any {
	return map[string]any{
		"id":              r.ID,
		"action_class":    r.ActionClass,
		"agent_id":        r.AgentID,
		"execution_id":    r.ExecutionID,
		"run_id":          r.RunID,
		"actor":           r.Actor,
		"actor_role":      r.ActorRole,
		"matched_rules":   r.MatchedRules,
		"state":           r.State,
		"created_unix":    r.CreatedUnix,
		"expires_unix":    r.ExpiresUnix,
		"decided_unix":    r.DecidedUnix,
		"decided_by":      r.DecidedBy,
		"decision_reason": r.DecisionReason,
	}
}

func (h *Handler) approvalsList(w http.ResponseWriter, r *http.Request) {
	if h.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approvals_disabled", "approvals subsystem not initialized", nil)
		return
	}
	state := r.URL.Query().Get("state")
	limit := queryInt(r, "limit", 50)
	reqs, err := h.approvals.List(state, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(reqs))
	for _, a := range reqs {
		out = append(out, approvalJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
}

func (h *Handler) approvalGet(w http.ResponseWriter, r *http.Request) {
	if h.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approvals_disabled", "approvals subsystem not initialized", nil)
		return
	}
	req, err := h.approvals.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	if req == nil {
		writeError(w, http.StatusNotFound, "not_found", "approval request not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, approvalJSON(req))
}

func (h *Handler) approvalApprove(w http.ResponseWriter, r *http.Request) {
	if h.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approvals_disabled", "approvals subsystem not initialized", nil)
		return
	}
	req, err := h.approvals.Approve(r.PathValue("id"), h.approvalActor(r))
	if err != nil {
		if req != nil {
			// Known request in a non-approvable state (denied/expired/…).
			writeError(w, http.StatusConflict, "not_pending", err.Error(), approvalJSON(req))
			return
		}
		if errStr := err.Error(); strings.Contains(errStr, "not found") {
			writeError(w, http.StatusNotFound, "not_found", errStr, nil)
			return
		}
		writeError(w, http.StatusForbidden, "forbidden", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approval_id": req.ID,
		"state":       "approved",
		"dispatched":  true,
	})
}

func (h *Handler) approvalDeny(w http.ResponseWriter, r *http.Request) {
	if h.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approvals_disabled", "approvals subsystem not initialized", nil)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &body) // reason is optional; malformed body is fine
	req, err := h.approvals.Deny(r.PathValue("id"), body.Reason, h.approvalActor(r))
	if err != nil {
		if req != nil {
			writeError(w, http.StatusConflict, "not_pending", err.Error(), approvalJSON(req))
			return
		}
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "not_found", err.Error(), nil)
			return
		}
		writeError(w, http.StatusForbidden, "forbidden", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approval_id": req.ID,
		"state":       "denied",
	})
}
