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
//	POST   /api/v1/secrets/bootstrap       one-click enable (Setup checklist):
//	                                   generate+adopt the data-dir master key
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
	// One-click enable from the Setup checklist (works while the feature is
	// off — that is its point — so it is not gated on secretsMgr).
	mux.Handle("POST /api/v1/secrets/bootstrap", h.requireRole(roleAdmin)(http.HandlerFunc(h.secretBootstrap)))
}

// SetSecrets installs the secret manager (nil = feature disabled → 503).
func (h *Handler) SetSecrets(sm *secrets.Manager) { h.secretsMgr = sm }

// SetSecretsKeyPath sets the data-dir default master-key file used by the
// UI bootstrap (POST /api/v1/secrets/bootstrap). Empty (never called)
// disables bootstrap — the feature is then env-config only.
func (h *Handler) SetSecretsKeyPath(p string) { h.secretsKeyPath = p }

// secretBootstrap is the Setup checklist's one-click enable: generate a
// master key into the data-dir default file (adopting an existing one),
// install the manager at runtime and let the assistant adopt the key for
// sealing its endpoint credentials. Admin-only; when the feature is
// already on it answers 409 (never rotates anything).
func (h *Handler) secretBootstrap(w http.ResponseWriter, r *http.Request) {
	if h.secretsMgr != nil {
		writeError(w, http.StatusConflict, "secrets_already_enabled",
			"secrets feature is already enabled (master key configured)", nil)
		return
	}
	if h.secretsKeyPath == "" {
		writeError(w, http.StatusServiceUnavailable, "bootstrap_unavailable",
			"secrets bootstrap is not available on this server (set PARTOUT_SECRET_KEY_FILE or PARTOUT_SECRET_KEY)", nil)
		return
	}
	master, err := secrets.BootstrapKey(h.secretsKeyPath)
	if err != nil {
		writeError(w, http.StatusConflict, "bootstrap_failed", err.Error(), nil)
		return
	}
	sm, err := secrets.New(h.st, h.streamH, master, h.log)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "secrets manager: "+err.Error(), nil)
		return
	}
	h.secretsMgr = sm
	// The assistant seals its endpoint API key under the master key; when it
	// was built keyless (nothing sealed yet) it adopts the fresh key so the
	// operator can configure a hosted endpoint right after this click.
	if h.assistant != nil {
		h.assistant.SetKeyMaster(master)
	}
	principal, _ := h.actorFor(r)
	h.audit("secrets.bootstrap", principal, map[string]string{
		"key_file": h.secretsKeyPath,
	})
	h.log.Printf("server: secrets feature enabled (bootstrap from web UI; key file %s)", h.secretsKeyPath)
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "key_file": h.secretsKeyPath})
}

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
