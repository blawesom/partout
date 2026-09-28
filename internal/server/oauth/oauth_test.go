package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/server/oauth"
	"github.com/blawesom/partout/internal/store"
)

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func newOAuth(t *testing.T) (*store.Store, *oauth.Manager, string) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	m := oauth.New(st)
	c, err := m.CreateClient("claude-code", "")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return st, m, c.ID
}

// TestOAuthPKCEFlow is the full RFC 7636 loop: register client → authorize
// (S256) → exchange with the verifier → access token resolves to the
// original principal/role.
func TestOAuthPKCEFlow(t *testing.T) {
	_, m, clientID := newOAuth(t)
	ctx := context.Background()
	verifier, challenge := pkce()

	code, ttl, err := m.Authorize(ctx, clientID, "alice", "admin", "", challenge, "S256")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if ttl <= 0 || code == "" {
		t.Fatalf("code=%q ttl=%d", code, ttl)
	}

	// Wrong verifier must fail.
	if _, _, _, err := m.Exchange(ctx, clientID, code, "wrong-verifier"); err == nil {
		t.Fatal("exchange with wrong verifier must fail")
	}

	// Correct verifier succeeds; the token resolves to the principal/role.
	token, ttl2, tok, err := m.Exchange(ctx, clientID, code, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ttl2 <= 0 {
		t.Fatalf("token ttl = %d", ttl2)
	}
	if tok.Principal != "alice" || tok.Role != "admin" {
		t.Fatalf("token identity = %s/%s, want alice/admin", tok.Principal, tok.Role)
	}
	p, r, ok := m.Lookup(token)
	if !ok || p != "alice" || r != "admin" {
		t.Fatalf("Lookup = (%q,%q,%v), want alice/admin/true", p, r, ok)
	}

	// The code is single-use.
	if _, _, _, err := m.Exchange(ctx, clientID, code, verifier); err == nil {
		t.Fatal("code reuse must fail")
	}
}

// TestOAuthPKCEFailures covers the rejection paths: non-S256 method,
// unknown client, and cross-client code use.
func TestOAuthPKCEFailures(t *testing.T) {
	st, m, clientID := newOAuth(t)
	ctx := context.Background()
	verifier, challenge := pkce()

	if _, _, err := m.Authorize(ctx, clientID, "alice", "admin", "", challenge, "plain"); err == nil {
		t.Fatal("plain challenge method must be rejected")
	}
	if _, _, err := m.Authorize(ctx, "mcpcl_nope", "alice", "admin", "", challenge, "S256"); err == nil {
		t.Fatal("unknown client must be rejected")
	}
	code, _, err := m.Authorize(ctx, clientID, "alice", "admin", "", challenge, "S256")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// A second client cannot redeem another client's code.
	c2, err := m.CreateClient("other", "")
	if err != nil {
		t.Fatalf("CreateClient 2: %v", err)
	}
	if _, _, _, err := m.Exchange(ctx, c2.ID, code, verifier); err == nil {
		t.Fatal("cross-client exchange must fail")
	}
	_ = st
}

// TestOAuthTokenExpiry checks that an expired token no longer resolves.
func TestOAuthTokenExpiry(t *testing.T) {
	st, m, clientID := newOAuth(t)
	ctx := context.Background()
	verifier, challenge := pkce()
	code, _, err := m.Authorize(ctx, clientID, "bob", "operator", "", challenge, "S256")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	token, _, _, err := m.Exchange(ctx, clientID, code, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	_, _, ok := m.Lookup(token)
	if !ok {
		t.Fatal("fresh token must resolve")
	}
	// Force-expire the stored token and confirm Lookup rejects it.
	if _, err := st.DB().Exec(`UPDATE oauth_tokens SET expires = ?`, time.Now().Unix()-10); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, _, ok := m.Lookup(token); ok {
		t.Fatal("expired token must not resolve")
	}
}
