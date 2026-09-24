// RBAC middleware (PRD R10, arch §10.1). Roles: viewer < operator < admin.
//
// Credentials, in order: (1) a local-user session token (PRD Decision 6,
// from POST /api/v1/auth/login), (2) static env bearer tokens. If no
// users exist AND no tokens are configured the server runs in single-user
// local mode (all requests allowed) — the embedded/self-hosted
// single-operator case before any user is created.
package api

import (
	"net/http"
	"strings"
	"sync/atomic"
)

type role int

const (
	roleNone role = iota
	roleViewer
	roleOperator
	roleAdmin
)

func (r role) String() string {
	switch r {
	case roleViewer:
		return "viewer"
	case roleOperator:
		return "operator"
	case roleAdmin:
		return "admin"
	default:
		return "none"
	}
}

func (r role) atLeast(min role) bool { return r >= min }

func roleFromString(s string) role {
	switch s {
	case "admin":
		return roleAdmin
	case "operator":
		return roleOperator
	case "viewer":
		return roleViewer
	default:
		return roleNone
	}
}

// auth holds the RBAC bearer tokens for the three roles.
type auth struct {
	admin    string
	operator string
	viewer   string
}

func newAuth(admin, operator, viewer string) *auth {
	return &auth{admin: admin, operator: operator, viewer: viewer}
}

func (a *auth) configured() bool {
	return a.admin != "" || a.operator != "" || a.viewer != ""
}

func (a *auth) roleFor(tok string) role {
	switch tok {
	case a.admin:
		return roleAdmin
	case a.operator:
		return roleOperator
	case a.viewer:
		return roleViewer
	}
	return roleNone
}

// roleFromToken maps a bearer token to its role (roleNone if unknown).
// Local-user session tokens are checked first, then static env tokens.
func (h *Handler) roleFromToken(tok string) role {
	if h.authC != nil {
		if _, roleStr, ok := h.authC.RoleFor(tok); ok {
			return roleFromString(roleStr)
		}
	}
	if h.auth == nil {
		return roleNone
	}
	return h.auth.roleFor(tok)
}

// tokensConfigured reports whether any role token is set.
func (h *Handler) tokensConfigured() bool {
	return h.auth != nil && h.auth.configured()
}

// authRequired reports whether the API enforces authentication (any local
// user exists, or static tokens are configured).
func (h *Handler) authRequired() bool {
	return h.tokensConfigured() || h.usersActive
}

// actorFor derives the (principal, role) audit label from the request:
// session token → (username, role); static token → (role, role); local
// mode → ("local", "admin"); unauthenticated → ("unknown", "none").
func (h *Handler) actorFor(r *http.Request) (string, string) {
	tok := bearerToken(r)
	if tok != "" && h.authC != nil {
		if u, roleStr, ok := h.authC.RoleFor(tok); ok {
			return u, roleStr
		}
	}
	if !h.authRequired() {
		return "local", "admin"
	}
	if tok == "" {
		return "unknown", "none"
	}
	role := h.roleFromToken(tok)
	if role == roleNone {
		return "unknown", "none"
	}
	return role.String(), role.String()
}

// requireRole wraps a handler with a minimum-role check.
func (h *Handler) requireRole(min role) func(http.Handler) http.Handler {
	var warnedOnce atomic.Bool
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !h.authRequired() {
				if warnedOnce.CompareAndSwap(false, true) && h.log != nil {
					h.log.Printf("api: no RBAC tokens or local users configured; running in single-user local mode (all requests allowed)")
				}
				next.ServeHTTP(w, r)
				return
			}
			tok := bearerToken(r)
			if tok == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized",
					"missing bearer token (Authorization: Bearer <token>)", nil)
				return
			}
			got := h.roleFromToken(tok)
			if got == roleNone {
				writeError(w, http.StatusUnauthorized, "unauthorized",
					"invalid bearer token", nil)
				return
			}
			if !got.atLeast(min) {
				writeError(w, http.StatusForbidden, "forbidden",
					"insufficient role (need "+min.String()+", got "+got.String()+")", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	authHdr := r.Header.Get("Authorization")
	if authHdr == "" || !strings.HasPrefix(authHdr, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(authHdr, "Bearer ")
}
