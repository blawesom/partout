// Package ssetoken mints and validates short-lived SSE-scoped tokens
// (PRD R10). EventSource cannot set request headers, so the web UI passes
// the credential as ?token= on GET /api/v1/events — a URL, which leaks into
// reverse-proxy access logs. Minted tokens therefore carry a short TTL
// (PARTOUT_SSE_TOKEN_TTL_S, default 60 s), are bound to the caller's role,
// and are accepted ONLY by the SSE endpoint (never as a general bearer, and
// never on any other API route).
//
// Storage follows the OAuth2 token pattern: random 256-bit token, only its
// SHA-256 hash is persisted, expiry enforced on every lookup.
package ssetoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/blawesom/partout/internal/store"
)

// Controller owns the SSE-scoped token store.
type Controller struct {
	st  *store.Store
	log *log.Logger
	ttl time.Duration
}

// New builds a Controller with the given token TTL (0 → 60 s).
func New(st *store.Store, ttl time.Duration, lg *log.Logger) *Controller {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{st: st, log: lg, ttl: ttl}
}

// SetTTL overrides the token TTL.
func (c *Controller) SetTTL(d time.Duration) {
	if d > 0 {
		c.ttl = d
	}
}

// Mint issues a short-lived SSE-scoped token carrying the caller's
// principal and role. Returns the plaintext token (shown once) and its
// expiry in unix seconds.
func (c *Controller) Mint(principal, role string) (string, int64, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", 0, err
	}
	token := "par_sse_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	expires := time.Now().Add(c.ttl).Unix()
	t := &store.SSEToken{
		TokenHash: hex.EncodeToString(sum[:]),
		Principal: principal, Role: role,
		Created: time.Now().Unix(), Expires: expires,
	}
	if err := c.st.InsertSSEToken(t); err != nil {
		return "", 0, fmt.Errorf("ssetoken: mint: %w", err)
	}
	return token, expires, nil
}

// Lookup resolves an SSE-scoped token to its (principal, role).
// ok=false means unknown or expired.
func (c *Controller) Lookup(token string) (principal, role string, ok bool) {
	if token == "" {
		return "", "", false
	}
	sum := sha256.Sum256([]byte(token))
	t, err := c.st.GetSSETokenByHash(hex.EncodeToString(sum[:]))
	if err != nil || t == nil {
		return "", "", false
	}
	if t.Expires <= time.Now().Unix() {
		return "", "", false
	}
	return t.Principal, t.Role, true
}

// Sweep drops expired SSE tokens. Safe to call concurrently; wire it to the
// same ticker as the session sweeper.
func (c *Controller) Sweep() int {
	n, err := c.st.DeleteExpiredSSETokens(time.Now().Unix())
	if err != nil {
		c.log.Printf("ssetoken: sweep: %v", err)
	}
	return n
}
