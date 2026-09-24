// REST handlers for local user identity (PRD Decision 6).
//
// Routes:
//
//	POST /api/v1/auth/login     (public)  — username+password → session token
//	GET  /api/v1/auth/me        (any)     — who am I
//	POST /api/v1/auth/logout    (any)     — invalidate this session token
//	POST /api/v1/auth/password  (any)     — change own password
//	GET  /api/v1/users          (admin)   — list users
//	POST /api/v1/users          (admin)   — create user
//	PATCH /api/v1/users/{name}  (admin)   — change role / disabled / reset password
//	DELETE /api/v1/users/{name} (admin)   — delete user
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	serverauth "github.com/blawesom/partout/internal/server/auth"
	"github.com/blawesom/partout/internal/store"
)

// RegisterAuth wires the auth + user-management routes.
func (h *Handler) RegisterAuth(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/auth/login", http.HandlerFunc(h.authLogin))
	mux.Handle("GET /api/v1/auth/me", h.requireRole(roleViewer)(http.HandlerFunc(h.authMe)))
	mux.Handle("POST /api/v1/auth/logout", h.requireRole(roleViewer)(http.HandlerFunc(h.authLogout)))
	mux.Handle("POST /api/v1/auth/password", h.requireRole(roleViewer)(http.HandlerFunc(h.authChangePassword)))

	mux.Handle("GET /api/v1/users", h.requireRole(roleAdmin)(http.HandlerFunc(h.userList)))
	mux.Handle("POST /api/v1/users", h.requireRole(roleAdmin)(http.HandlerFunc(h.userCreate)))
	mux.Handle("PATCH /api/v1/users/{name}", h.requireRole(roleAdmin)(http.HandlerFunc(h.userPatch)))
	mux.Handle("DELETE /api/v1/users/{name}", h.requireRole(roleAdmin)(http.HandlerFunc(h.userDelete)))
}

func (h *Handler) authController() bool {
	return h.authC != nil
}

func (h *Handler) authDisabled(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "auth_disabled",
		"local user auth not initialized", nil)
}

// authLogin is public: it is the credential exchange. It returns a generic
// 401 for both unknown user and wrong password (no user enumeration).
func (h *Handler) authLogin(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "username and password required", nil)
		return
	}
	// Bound the username: it is echoed into audit rows and throttle keys, so
	// unbounded input would be a log/memory amplification vector.
	if len(body.Username) > 64 || len(body.Password) > 1024 {
		writeError(w, http.StatusBadRequest, "bad_request", "username or password too long", nil)
		return
	}
	sess, err := h.authC.Login(body.Username, body.Password)
	if errors.Is(err, serverauth.ErrThrottled) {
		writeError(w, http.StatusTooManyRequests, "throttled",
			"too many failed attempts; retry later", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        sess.Token,
		"username":     sess.Username,
		"role":         sess.Role,
		"expires_unix": sess.ExpiresUnix,
	})
}

// authMe reports the caller's identity (session token required).
func (h *Handler) authMe(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	tok := bearerToken(r)
	sess, err := h.authC.Validate(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid session token", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     sess.Username,
		"role":         sess.Role,
		"expires_unix": sess.ExpiresUnix,
	})
}

// authLogout invalidates the caller's session token.
func (h *Handler) authLogout(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	h.authC.Logout(bearerToken(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// authChangePassword changes the caller's own password (requires the old
// one) and invalidates the caller's other sessions.
func (h *Handler) authChangePassword(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.OldPassword == "" || body.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "old_password and new_password required", nil)
		return
	}
	tok := bearerToken(r)
	sess, err := h.authC.Validate(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid session token", nil)
		return
	}
	if err := h.authC.ChangePassword(sess.Username, body.OldPassword, body.NewPassword); err != nil {
		switch {
		case errors.Is(err, serverauth.ErrBadCredentials):
			writeError(w, http.StatusUnauthorized, "unauthorized", "old password incorrect", nil)
		case errors.Is(err, serverauth.ErrWeakPassword):
			writeError(w, http.StatusBadRequest, "weak_password", err.Error(), nil)
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		}
		return
	}
	// The caller's current token was invalidated; issue a fresh one so the
	// UI stays logged in.
	sess, err = h.authC.Login(sess.Username, body.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "re-login: "+err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        sess.Token,
		"expires_unix": sess.ExpiresUnix,
	})
}

func (h *Handler) userErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, serverauth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", err.Error(), nil)
	case errors.Is(err, serverauth.ErrSelfDelete), errors.Is(err, serverauth.ErrSelfModify):
		writeError(w, http.StatusConflict, "self_modify", err.Error(), nil)
	case errors.Is(err, serverauth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "weak_password", err.Error(), nil)
	case errors.Is(err, store.ErrNoPrincipal):
		writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
	default:
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		}
	}
}

// userList returns all users (no password material).
func (h *Handler) userList(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	plist, err := h.st.ListPrincipals()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(plist))
	for _, p := range plist {
		out = append(out, map[string]any{
			"username": p.Username, "role": p.Role,
			"disabled": p.Disabled, "created_unix": p.CreatedUnix,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// userCreate creates a user (admin).
func (h *Handler) userCreate(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	actor, _ := h.actorFor(r)
	if err := h.authC.CreateUser(actor, body.Username, body.Password, body.Role); err != nil {
		h.userErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"username": body.Username})
}

// userPatch changes a user's role / disabled flag / password (admin).
func (h *Handler) userPatch(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	name := r.PathValue("name")
	var body struct {
		Role     string `json:"role"`
		Disabled *bool  `json:"disabled"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	actor, _ := h.actorFor(r)
	if body.Role != "" {
		if err := h.authC.SetRole(actor, name, body.Role); err != nil {
			h.userErr(w, err)
			return
		}
	}
	if body.Disabled != nil {
		if err := h.authC.SetDisabled(actor, name, *body.Disabled); err != nil {
			h.userErr(w, err)
			return
		}
	}
	if body.Password != "" {
		if err := h.authC.ResetPassword(actor, name, body.Password); err != nil {
			h.userErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": name, "status": "ok"})
}

// userDelete removes a user (admin).
func (h *Handler) userDelete(w http.ResponseWriter, r *http.Request) {
	if !h.authController() {
		h.authDisabled(w)
		return
	}
	name := r.PathValue("name")
	actor, _ := h.actorFor(r)
	if err := h.authC.DeleteUser(actor, name); err != nil {
		h.userErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}
