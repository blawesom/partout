// Package api — policy rule CRUD (architecture §5.2).
//
// Policies are declarative deny / require_approval / allow rules. Creating
// or deleting a rule bumps the policy bundle version so connected agents
// pick up the change.
package api

import (
	"net/http"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
)

// RegisterPolicies mounts the policy CRUD routes.
func (h *Handler) RegisterPolicies(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/policies", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListPolicies)))
	mux.Handle("POST /api/v1/policies", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleCreatePolicy)))
	mux.Handle("DELETE /api/v1/policies/{id}", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleDeletePolicy)))
}

// policyRequest is the body for creating a rule.
type policyRequest struct {
	Name     string       `json:"name"`
	Match    policy.Match `json:"match"`
	Effect   string       `json:"effect"`
	Priority int          `json:"priority"`
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	rules, err := h.st.GetPolicyRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "list policies", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rules})
}

func (h *Handler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid policy body", err)
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "name is required", nil)
		return
	}
	if req.Effect != policy.EffectDeny && req.Effect != policy.EffectRequireApproval && req.Effect != policy.EffectAllow {
		writeError(w, http.StatusBadRequest, "bad_request",
			"effect must be deny|require_approval|allow", nil)
		return
	}
	// Validate the command regex before persisting (the store must never hold
	// a broken pattern — see architecture §5.2).
	if req.Match.CommandRegex != "" {
		if _, err := policy.CompileCommandRegex(req.Match.CommandRegex); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid command_regex", err)
			return
		}
	}
	ruleID := id.New("pol")
	if err := h.st.CreatePolicy(ruleID, req.Name, req.Match, req.Effect, req.Priority); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "create policy", err)
		return
	}
	actor := h.roleFor(r)
	h.audit("policy.create", actor, map[string]string{
		"policy_id": ruleID,
		"name":      req.Name,
		"effect":    req.Effect,
	})
	// Push the updated bundle to all connected agents so they re-check
	// against the new rule set immediately (architecture §5.2).
	h.ctrl.BroadcastPolicyBundle()
	writeJSON(w, http.StatusCreated, map[string]string{"id": ruleID})
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	n, err := h.st.DeletePolicy(ruleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "delete policy", err)
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "not_found", "policy not found", nil)
		return
	}
	h.audit("policy.delete", h.roleFor(r), map[string]string{
		"policy_id": ruleID,
	})
	// Push the updated bundle to all connected agents.
	h.ctrl.BroadcastPolicyBundle()
	writeJSON(w, http.StatusOK, map[string]string{"deleted": ruleID})
}

// roleFor returns the actor label from the request's bearer token.
// Falls back to "local" when no tokens are configured.
func (h *Handler) roleFor(r *http.Request) string {
	if !h.tokensConfigured() {
		return "local"
	}
	tok := bearerToken(r)
	if tok == "" {
		return "unknown"
	}
	role := h.auth.roleFor(tok)
	if role == roleNone {
		return "token"
	}
	return role.String()
}
