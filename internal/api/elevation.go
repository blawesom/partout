// REST handlers for the server-side elevation policy store (PRD Decision 3
// onboarding): named policy documents that provisioning ships to hosts.
//
// Routes (auth: reads = viewer+, writes = admin):
//
//	GET    /api/v1/elevation/policies        list
//	POST   /api/v1/elevation/policies        create {name, description?, rules|[file]}
//	GET    /api/v1/elevation/policies/{id}   one (by id or name)
//	PUT    /api/v1/elevation/policies/{id}   update rules/description
//	DELETE /api/v1/elevation/policies/{id}    delete
//
// The policy itself stays host-owned: this store is the operator's
// canonical document, provisioning is the shipping channel (with sha256
// verification), and `partout ctl elevation check` on the host detects
// drift. Nothing here can widen a host's sudoers wall by itself.
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/store"
)

// RegisterElevationPolicies wires the elevation-policy store routes.
func (h *Handler) RegisterElevationPolicies(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/elevation/policies", h.requireRole(roleViewer)(http.HandlerFunc(h.eplList)))
	mux.Handle("POST /api/v1/elevation/policies", h.requireRole(roleAdmin)(http.HandlerFunc(h.eplCreate)))
	mux.Handle("GET /api/v1/elevation/policies/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.eplGet)))
	mux.Handle("PUT /api/v1/elevation/policies/{id}", h.requireRole(roleAdmin)(http.HandlerFunc(h.eplUpdate)))
	mux.Handle("DELETE /api/v1/elevation/policies/{id}", h.requireRole(roleAdmin)(http.HandlerFunc(h.eplDelete)))
}

type eplBody struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Rules       json.RawMessage `json:"rules"` // rules array (or an object with "rules")
}

// normalizeEplRules accepts either a bare rules array or a full
// {"rules": [...]} document and returns the canonical rules-only JSON plus
// the policy hash.
func normalizeEplRules(raw json.RawMessage) (string, string, error) {
	b := []byte(raw)
	if len(b) > 0 && b[0] == '{' {
		// full document form: keep only its "rules"
		var doc struct {
			Rules json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return "", "", err
		}
		b = doc.Rules
	}
	wrapped, err := json.Marshal(map[string]json.RawMessage{"rules": json.RawMessage(b)})
	if err != nil {
		return "", "", err
	}
	pol, err := elevate.LoadPolicyJSON(wrapped)
	if err != nil {
		return "", "", err
	}
	canonical, err := json.Marshal(pol.Rules)
	if err != nil {
		return "", "", err
	}
	return string(canonical), pol.PolicyHash(), nil
}

func (h *Handler) eplList(w http.ResponseWriter, r *http.Request) {
	pols, err := h.st.ElevationPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(pols))
	for _, p := range pols {
		out = append(out, eplJSON(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) eplGet(w http.ResponseWriter, r *http.Request) {
	p, err := h.st.ElevationPolicy(r.PathValue("id"))
	if err != nil {
		h.eplErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, eplJSON(p))
}

func (h *Handler) eplCreate(w http.ResponseWriter, r *http.Request) {
	var body eplBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "name is required", nil)
		return
	}
	if len(body.Rules) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "rules are required", nil)
		return
	}
	rulesJSON, hash, err := normalizeEplRules(body.Rules)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_policy", "invalid elevation policy: "+err.Error(), nil)
		return
	}
	p := &store.ElevationPolicy{
		Name: name, Description: body.Description,
		RulesJSON: rulesJSON, PolicySHA: hash,
	}
	if err := h.st.CreateElevationPolicy(p); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "conflict", "an elevation policy named "+name+" already exists", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	principal, _ := h.actorFor(r)
	h.audit("elevation.policy.create", principal, map[string]string{
		"policy_id": p.ID, "name": name, "sha256": hash,
	})
	writeJSON(w, http.StatusCreated, eplJSON(p))
}

func (h *Handler) eplUpdate(w http.ResponseWriter, r *http.Request) {
	var body eplBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	if len(body.Rules) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "rules are required", nil)
		return
	}
	rulesJSON, hash, err := normalizeEplRules(body.Rules)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_policy", "invalid elevation policy: "+err.Error(), nil)
		return
	}
	p, err := h.st.UpdateElevationPolicy(r.PathValue("id"), body.Description, rulesJSON, hash)
	if err != nil {
		h.eplErr(w, err)
		return
	}
	principal, _ := h.actorFor(r)
	h.audit("elevation.policy.update", principal, map[string]string{
		"policy_id": p.ID, "name": p.Name, "sha256": hash,
	})
	writeJSON(w, http.StatusOK, eplJSON(p))
}

func (h *Handler) eplDelete(w http.ResponseWriter, r *http.Request) {
	if err := h.st.DeleteElevationPolicy(r.PathValue("id")); err != nil {
		h.eplErr(w, err)
		return
	}
	principal, _ := h.actorFor(r)
	h.audit("elevation.policy.delete", principal, map[string]string{"id": r.PathValue("id")})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (h *Handler) eplErr(w http.ResponseWriter, err error) {
	if err == store.ErrElevationPolicyNotFound {
		writeError(w, http.StatusNotFound, "not_found", err.Error(), nil)
		return
	}
	writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
}

func eplJSON(p *store.ElevationPolicy) map[string]any {
	return map[string]any{
		"id": p.ID, "name": p.Name, "description": p.Description,
		"rules": json.RawMessage(p.RulesJSON), "policy_sha256": p.PolicySHA,
		"created": p.Created, "updated": p.Updated,
	}
}
