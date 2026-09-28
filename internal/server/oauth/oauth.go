// Package oauth implements the OAuth2 authorization-code + PKCE flow for
// the MCP HTTP transport (PRD R11, architecture A20).
//
// v1 design (tracked as a deviation from the full post-v1 OAuth2 model):
// the resource owner authenticates with their existing bearer credential
// (local-user session token or static role token) on POST /oauth2/authorize
// — there is no separate browser login in this codebase. The issued access
// token is short-lived, bound to (client, principal, role, scope), stored
// only as a SHA-256 hash, and accepted as a bearer on the REST/MCP routes
// exactly like any other credential (RBAC + policy + audit apply unchanged).
//
// PKCE (RFC 7636) is mandatory: only S256 challenges are accepted, and the
// token exchange verifies S256(code_verifier) == code_challenge.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/store"
)

const (
	CodeTTL    = 5 * time.Minute
	TokenTTL   = time.Hour
	MethodS256 = "S256"
)

// Manager owns the PKCE flow + client registry.
type Manager struct {
	st *store.Store
}

func New(st *store.Store) *Manager { return &Manager{st: st} }

// --- client registry (admin-managed) ---

// CreateClient registers one MCP client.
func (m *Manager) CreateClient(name, scope string) (*store.MCPClient, error) {
	if name == "" {
		return nil, errors.New("oauth: client name required")
	}
	if scope == "" {
		scope = "fleet"
	}
	c := &store.MCPClient{
		ID: id.New("mcpcl"), Name: name, Scope: scope,
		Created: time.Now().Unix(),
	}
	if err := m.st.CreateMCPClient(c); err != nil {
		return nil, err
	}
	return c, nil
}

func (m *Manager) ListClients() ([]*store.MCPClient, error) {
	return m.st.ListMCPClients()
}

// --- authorization ---

// Authorize issues a one-time authorization code for (client, principal)
// bound to the PKCE challenge. principal/role come from the authenticated
// caller (their existing bearer credential).
func (m *Manager) Authorize(ctx context.Context, clientID, principal, role, scope, challenge, method string) (string, int64, error) {
	if method != MethodS256 {
		return "", 0, fmt.Errorf("oauth: code_challenge_method must be %s (got %q)", MethodS256, method)
	}
	if challenge == "" || principal == "" {
		return "", 0, errors.New("oauth: challenge and principal required")
	}
	client, err := m.st.GetMCPClient(clientID)
	if err != nil {
		return "", 0, fmt.Errorf("oauth: client: %w", err)
	}
	if client == nil {
		return "", 0, fmt.Errorf("oauth: unknown client %q", clientID)
	}
	if scope == "" {
		scope = client.Scope
	}
	code := randomToken("par_acd_")
	expires := time.Now().Add(CodeTTL).Unix()
	if err := m.st.InsertOAuthCode(&store.OAuthCode{
		ID: id.New("oac"), CodeHash: hash(code),
		ClientID: clientID, Principal: principal, Role: role, Scope: scope,
		Challenge: challenge, Expires: expires, Created: time.Now().Unix(),
	}); err != nil {
		return "", 0, err
	}
	return code, int64(CodeTTL.Seconds()), nil
}

// Exchange redeems an authorization code with its PKCE verifier for a
// short-lived access token.
func (m *Manager) Exchange(ctx context.Context, clientID, code, verifier string) (string, int64, *store.OAuthToken, error) {
	codeHash := hash(code)
	row, err := m.st.GetOAuthCodeByHash(codeHash)
	if err != nil {
		return "", 0, nil, fmt.Errorf("oauth: code lookup: %w", err)
	}
	if row == nil {
		return "", 0, nil, errors.New("oauth: invalid or expired authorization code")
	}
	if row.Used {
		return "", 0, nil, errors.New("oauth: authorization code already used")
	}
	if row.Expires <= time.Now().Unix() {
		return "", 0, nil, errors.New("oauth: authorization code expired")
	}
	if row.ClientID != clientID {
		return "", 0, nil, errors.New("oauth: code was issued to a different client")
	}
	if s256Challenge(verifier) != row.Challenge {
		return "", 0, nil, errors.New("oauth: PKCE verification failed (code_verifier does not match the challenge)")
	}
	if err := m.st.MarkOAuthCodeUsed(row.ID); err != nil {
		return "", 0, nil, err
	}
	token := randomToken("par_atk_")
	t := &store.OAuthToken{
		TokenHash: hash(token), ClientID: row.ClientID,
		Principal: row.Principal, Role: row.Role, Scope: row.Scope,
		Created: time.Now().Unix(), Expires: time.Now().Add(TokenTTL).Unix(),
	}
	if err := m.st.InsertOAuthToken(t); err != nil {
		return "", 0, nil, err
	}
	return token, int64(TokenTTL.Seconds()), t, nil
}

// Lookup resolves an access token to its (principal, role) for the RBAC
// layer. ok=false means unknown or expired.
func (m *Manager) Lookup(token string) (principal, role string, ok bool) {
	if token == "" {
		return "", "", false
	}
	t, err := m.st.GetOAuthTokenByHash(hash(token))
	if err != nil || t == nil {
		return "", "", false
	}
	if t.Expires <= time.Now().Unix() {
		return "", "", false
	}
	return t.Principal, t.Role, true
}

// --- helpers ---

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// s256Challenge is the RFC 7636 S256 transform:
// BASE64URL(SHA256(ASCII(verifier))) without padding.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oauth: rand: " + err.Error())
	}
	return prefix + hex.EncodeToString(b)
}
