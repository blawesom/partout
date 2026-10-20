package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	serverauth "github.com/blawesom/partout/internal/server/auth"
	"github.com/blawesom/partout/internal/server/ssetoken"
)

// fetchSSE performs an SSE subscription (with a hard deadline so the test
// never hangs on the open stream) and returns the status code plus the bytes
// read before the deadline. A successful stream opens with an
// "event: connected" ping.
func fetchSSE(t *testing.T, url string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// A deadline-exceeded read on a live stream is a 200 we already got;
		// surface the error only for a pre-stream failure.
		t.Fatalf("SSE request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body) // bounded by the context deadline
	return resp.StatusCode, string(b)
}

// TestSSEAuthUnauthenticatedLocked: with local users present (local mode
// lifted), the SSE stream must reject anonymous and bad-credential clients
// before opening the stream.
func TestSSEAuthUnauthenticatedLocked(t *testing.T) {
	_, base := startAuthTest(t)

	// No token at all → 401, not an opened stream.
	code, body := fetchSSE(t, base+"/api/v1/events")
	if code != http.StatusUnauthorized {
		t.Fatalf("anonymous SSE: status %d, want 401 (body %q)", code, body)
	}
	// A bad ?token= → 401.
	code, body = fetchSSE(t, base+"/api/v1/events?token=nope")
	if code != http.StatusUnauthorized {
		t.Fatalf("bad-token SSE: status %d, want 401 (body %q)", code, body)
	}
}

// TestSSEAuthTokenQuery: the UI authenticates via ?token= (EventSource
// cannot set headers). A minted short-lived SSE-scoped token in the query
// opens the stream; the caller's full session token must NOT (it would leak
// into proxy access logs — the very thing the scoped token avoids).
func TestSSEAuthTokenQuery(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "viewer1", "viewerpass1", "viewer")
	apiH.SetAuthController(serverauth.New(apiH.Store(), nil))
	apiH.SetSSETokens(ssetoken.New(apiH.Store(), 0, nil))
	base := srv.URL
	tok := loginToken(t, base, "viewer1", "viewerpass1")

	// A session bearer in the query is rejected (not SSE-scoped).
	code, _ := fetchSSE(t, base+"/api/v1/events?token="+tok)
	if code != http.StatusUnauthorized {
		t.Fatalf("session-token-in-query SSE: status %d, want 401", code)
	}

	// A minted SSE-scoped token opens the stream.
	sseTok := mintSSEToken(t, base, tok)
	code, body := fetchSSE(t, base+"/api/v1/events?token="+sseTok)
	if code != http.StatusOK {
		t.Fatalf("token-in-query SSE: status %d, want 200", code)
	}
	if !strings.Contains(body, "event: connected") {
		t.Fatalf("expected the connected ping, got %q", body)
	}
}

// TestSSEAuthTokenHeader: header auth still works and is preferred (no query
// token present).
func TestSSEAuthTokenHeader(t *testing.T) {
	_, base := startAuthTest(t)
	tok := loginToken(t, base, "admin", "adminpass1")

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("header-token SSE: status %d, want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "event: connected") {
		t.Fatalf("expected the connected ping, got %q", b)
	}
}

// TestSSEAuthStaticTokenQuery: with the SSE-scoped store installed, a
// static env token in the query is NO LONGER a valid SSE credential (only
// minted SSE tokens are); the same static token still works in the header.
func TestSSEAuthStaticTokenQuery(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "admin", "adminpass1", "admin")
	apiH.SetAuth(staticAdminToken, "static-op-token", "static-viewer-token")
	apiH.SetAuthController(serverauth.New(apiH.Store(), nil))
	apiH.SetSSETokens(ssetoken.New(apiH.Store(), 0, nil))
	base := srv.URL

	// Static token in the query: rejected (full bearer in a URL).
	code, _ := fetchSSE(t, base+"/api/v1/events?token=static-viewer-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("static-viewer SSE in query: status %d, want 401", code)
	}

	// The same token in the header still works.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer static-viewer-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("static-viewer SSE in header: status %d, want 200", resp.StatusCode)
	}

	// A garbage token is rejected.
	code, _ = fetchSSE(t, base+"/api/v1/events?token=not-a-real-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("bad static token SSE: status %d, want 401", code)
	}
}

// TestSSELocalModeStillOpen: with no users and no tokens configured the server
// runs single-user local mode and the stream stays open (embedded/self-hosted
// first-run case, before any identity is created).
func TestSSELocalModeStillOpen(t *testing.T) {
	_, _, srv := startAPITest(t) // no auth configured
	code, body := fetchSSE(t, srv.URL+"/api/v1/events")
	if code != http.StatusOK {
		t.Fatalf("local-mode SSE: status %d, want 200", code)
	}
	if !strings.Contains(body, "event: connected") {
		t.Fatalf("expected the connected ping, got %q", body)
	}
}

// TestSSETokenMintAndScope: POST /api/v1/auth/sse-token mints a
// short-lived token carrying the caller's role; it opens the SSE stream
// but is NOT a valid bearer on any other API route.
func TestSSETokenMintAndScope(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "viewer1", "viewerpass1", "viewer")
	apiH.SetAuthController(serverauth.New(apiH.Store(), nil))
	apiH.SetSSETokens(ssetoken.New(apiH.Store(), 0, nil))
	base := srv.URL
	tok := loginToken(t, base, "viewer1", "viewerpass1")

	code, b := apiReq(t, "POST", base+"/api/v1/auth/sse-token", tok, "")
	if code != http.StatusOK {
		t.Fatalf("mint sse-token: status %d body %s", code, b)
	}
	var res struct {
		Token           string `json:"token"`
		ExpiresUnix     int64  `json:"expires_unix"`
		Role            string `json:"role"`
		AuthorizedRoute string `json:"authorized_route"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("mint response: %v", err)
	}
	if res.Token == "" || res.ExpiresUnix == 0 || res.Role != "viewer" || res.AuthorizedRoute != "/api/v1/events" {
		t.Fatalf("mint response = %+v", res)
	}

	// The minted token is SSE-only: as a bearer on the general API it is
	// just an unknown credential.
	code, _ = apiReq(t, "GET", base+"/api/v1/hosts", res.Token, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("sse-token as general bearer: status %d, want 401", code)
	}
}

// TestSSETokenExpiry: an expired SSE-scoped token no longer opens the
// stream.
func TestSSETokenExpiry(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "viewer1", "viewerpass1", "viewer")
	apiH.SetAuthController(serverauth.New(apiH.Store(), nil))
	base := srv.URL
	tok := loginToken(t, base, "viewer1", "viewerpass1")
	c := ssetoken.New(apiH.Store(), 0, nil)
	apiH.SetSSETokens(c)

	sseTok := mintSSEToken(t, base, tok)
	// Force-expire every stored sse token.
	if _, err := apiH.Store().DB().Exec(`UPDATE sse_tokens SET expires = ?`, time.Now().Unix()-10); err != nil {
		t.Fatalf("expire: %v", err)
	}
	code, _ := fetchSSE(t, base+"/api/v1/events?token="+sseTok)
	if code != http.StatusUnauthorized {
		t.Fatalf("expired sse-token SSE: status %d, want 401", code)
	}
}

// mintSSEToken logs in with the session token tok and mints an
// SSE-scoped token via the API route.
func mintSSEToken(t *testing.T, base, tok string) string {
	t.Helper()
	code, b := apiReq(t, "POST", base+"/api/v1/auth/sse-token", tok, "")
	if code != http.StatusOK {
		t.Fatalf("mint sse-token: status %d body %s", code, b)
	}
	var res struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("mint response: %v", err)
	}
	return res.Token
}
