// OAuth2 (PKCE) + MCP client REST routes (M4, PRD R11, A20).
//
//	POST /api/v1/mcp/clients        (admin)  — register an MCP client
//	GET  /api/v1/mcp/clients        (viewer) — list MCP clients
//	POST /oauth2/authorize          (any authenticated user, on their own
//	                                   behalf) — issue a PKCE-bound
//	                                   authorization code
//	POST /oauth2/token              (unauthenticated; the code + PKCE
//	                                   verifier are the credentials) —
//	                                   exchange for a short-lived access
//	                                   token, accepted as a bearer on the
//	                                   REST/MCP routes like any credential.
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/blawesom/partout/internal/server/oauth"
)

// RegisterOAuth wires the OAuth2 + MCP client routes.
func (h *Handler) RegisterOAuth(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/mcp/clients", h.requireRole(roleAdmin)(http.HandlerFunc(h.oauthCreateClient)))
	mux.Handle("GET /api/v1/mcp/clients", h.requireRole(roleViewer)(http.HandlerFunc(h.oauthListClients)))
	mux.Handle("POST /oauth2/authorize", h.requireRole(roleViewer)(http.HandlerFunc(h.oauthAuthorize)))
	mux.Handle("POST /oauth2/token", http.HandlerFunc(h.oauthToken))
}

func (h *Handler) oauthCreateClient(w http.ResponseWriter, r *http.Request) {
	if h.oauthC == nil {
		writeError(w, http.StatusServiceUnavailable, "oauth_disabled", "oauth not initialized", nil)
		return
	}
	var body struct {
		Name        string `json:"name"`
		Scope       string `json:"scope"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	c, err := h.oauthC.CreateClient(body.Name, body.Scope, body.RedirectURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": c.ID, "name": c.Name, "scope": c.Scope, "redirect_uri": c.RedirectURI,
	})
}

func (h *Handler) oauthListClients(w http.ResponseWriter, r *http.Request) {
	if h.oauthC == nil {
		writeError(w, http.StatusServiceUnavailable, "oauth_disabled", "oauth not initialized", nil)
		return
	}
	clients, err := h.oauthC.ListClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scope": c.Scope, "redirect_uri": c.RedirectURI, "created": c.Created,
		})
	}
}

func (h *Handler) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.oauthC == nil {
		writeError(w, http.StatusServiceUnavailable, "oauth_disabled", "oauth not initialized", nil)
		return
	}
	var body struct {
		ClientID            string `json:"client_id"`
		RedirectURI         string `json:"redirect_uri"` // must equal the client's registered redirect_uri (empty matches empty)
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		Scope               string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	// The resource owner is the authenticated caller (their existing bearer
	// credential) — this codebase has no browser login.
	principal, role := h.actorFor(r)
	code, ttl, err := h.oauthC.Authorize(r.Context(), body.ClientID, principal, role, body.Scope, body.CodeChallenge, body.CodeChallengeMethod, body.RedirectURI)
	if err != nil {
		if errors.Is(err, oauth.ErrRedirectURI) {
			writeError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error(), nil)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code":         code,
		"expires_in":   ttl,
		"client_id":    body.ClientID,
		"principal":    principal,
		"redirect_uri": body.RedirectURI,
	})
}

func (h *Handler) oauthToken(w http.ResponseWriter, r *http.Request) {
	if h.oauthC == nil {
		writeError(w, http.StatusServiceUnavailable, "oauth_disabled", "oauth not initialized", nil)
		return
	}
	var body struct {
		GrantType    string `json:"grant_type"`
		ClientID     string `json:"client_id"`
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if body.GrantType != "authorization_code" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be \"authorization_code\"", nil)
		return
	}
	token, ttl, t, err := h.oauthC.Exchange(r.Context(), body.ClientID, body.Code, body.CodeVerifier)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   ttl,
		"scope":        t.Scope,
		"client_id":    t.ClientID,
		"principal":    t.Principal,
		"role":         t.Role,
	})
}
