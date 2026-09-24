// REST handlers for secrets (M3, PRD §5.7).
//
// Routes (auth: reads = operator+, writes = admin):
//
//	GET    /api/v1/secrets                 list (metadata only — never values)
//	GET    /api/v1/secrets/{name}          one secret (metadata only)
//	POST   /api/v1/secrets                 create {name, value, selector, offline_ttl_s}
//	POST   /api/v1/secrets/{name}/rotate   new version {value}
//	POST   /api/v1/secrets/{name}/revoke   revoke current version
//	DELETE /api/v1/secrets/{name}          delete
//
// Values are write-only: no read endpoint ever returns a value.
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/blawesom/partout/internal/server/secrets"
	"github.com/blawesom/partout/internal/store"
)

// RegisterSecrets wires the secret REST routes. Routes return 503 until
// SetSecrets installs the manager (i.e. a master key is configured).
func (h *Handler) RegisterSecrets(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/secrets", h.requireRole(roleOperator)(http.HandlerFunc(h.secretList)))
	mux.Handle("GET /api/v1/secrets/{name}", h.requireRole(roleOperator)(http.HandlerFunc(h.secretGet)))
	mux.Handle("POST /api/v1/secrets", h.requireRole(roleAdmin)(http.HandlerFunc(h.secretCreate)))
	mux.Handle("POST /api/v1/secrets/{name}/rotate", h.requireRole(roleAdmin)(http.HandlerFunc(h.secretRotate)))
	mux.Handle("POST /api/v1/secrets/{name}/revoke", h.requireRole(roleAdmin)(http.HandlerFunc(h.secretRevoke)))
	mux.Handle("DELETE /api/v1/secrets/{name}", h.requireRole(roleAdmin)(http.HandlerFunc(h.secretDelete)))
}

// SetSecrets installs the secret manager (nil = feature disabled → 503).
func (h *Handler) SetSecrets(sm *secrets.Manager) { h.secretsMgr = sm }

func (h *Handler) secretList(w http.ResponseWriter, r *http.Request) {
	if h.secretsMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "secrets_disabled",
			"secrets feature disabled: no master key configured", nil)
		return
	}
	views, err := h.secretsMgr.List()
	if err != nil {
		h.secretErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": views})
}

func (h *Handler) secretGet(w http.ResponseWriter, r *http.Request) {
	if h.secretsMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "secrets_disabled",
			"secrets feature disabled: no master key configured", nil)
		return
	}
	sec, err := h.secretsMgr.Get(r.PathValue("name"))
	if err != nil {
		h.secretErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sec)
}

type secretCreateBody struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	Selector   string `json:"selector"`
	OfflineTTL int64  `json:"offline_ttl_s"`
}

func (h *Handler) secretCreate(w http.ResponseWriter, r *http.Request) {
	if h.secretsMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "secrets_disabled",
			"secrets feature disabled: no master key configured", nil)
		return
	}
	var body secretCreateBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid json: "+err.Error(), nil)
		return
	}
	if body.Name == "" || body.Value == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "name and value required", nil)
	}
	principal, _ := h.actorFor(r)
	sec, err := h.secretsMgr.CreateSecret(body.Name, body.Value, body.Selector, body.OfflineTTL, principal)
	if err != nil {
		h.secretErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": sec.ID, "name": sec.Name, "selector": sec.Selector, "version": 1,
	})
}

type secretRotateBody struct {
	Value string `json:"value"`
}

func (h *Handler) secretRotate(w http.ResponseWriter, r *http.Request) {
	if h.secretsMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "secrets_disabled",
			"secrets feature disabled: no master key configured", nil)
		return
	}
	var body secretRotateBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid json: "+err.Error(), nil)
		return
	}
	if body.Value == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "value required", nil)
	}
	principal, _ := h.actorFor(r)
	v, err := h.secretsMgr.RotateSecret(r.PathValue("name"), body.Value, principal)
	if err != nil {
		h.secretErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": v})
}

func (h *Handler) secretRevoke(w http.ResponseWriter, r *http.Request) {
	if h.secretsMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "secrets_disabled",
			"secrets feature disabled: no master key configured", nil)
		return
	}
	principal, _ := h.actorFor(r)
	if err := h.secretsMgr.RevokeSecret(r.PathValue("name"), principal); err != nil {
		h.secretErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (h *Handler) secretDelete(w http.ResponseWriter, r *http.Request) {
	if h.secretsMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "secrets_disabled",
			"secrets feature disabled: no master key configured", nil)
		return
	}
	name := r.PathValue("name")
	principal, _ := h.actorFor(r)
	if err := h.secretsMgr.DeleteSecret(name, principal); err != nil {
		h.secretErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "name": name})
}

func (h *Handler) secretErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case err == store.ErrNotFound:
		writeError(w, http.StatusNotFound, "not_found", "secret not found", nil)
	case strings.Contains(msg, "already exists"):
		writeError(w, http.StatusConflict, "conflict", msg, nil)
	case strings.Contains(msg, "invalid name") || strings.Contains(msg, "exceeds") || strings.Contains(msg, "selector"):
		writeError(w, http.StatusBadRequest, "bad_request", msg, nil)
	case strings.Contains(msg, "no active version"):
		writeError(w, http.StatusConflict, "conflict", msg, nil)
	case strings.Contains(msg, "not bound to agent"):
		writeError(w, http.StatusForbidden, "forbidden", msg, nil)
	default:
		writeError(w, http.StatusInternalServerError, "internal", msg, nil)
	}
}
