package api_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	serverauth "github.com/blawesom/partout/internal/server/auth"
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

// TestSSEAuthTokenQuery: the UI authenticates via ?token= (EventSource cannot
// set headers). A valid session token in the query must open the stream.
func TestSSEAuthTokenQuery(t *testing.T) {
	_, base := startAuthTest(t)
	tok := loginToken(t, base, "viewer1", "viewerpass1")

	code, body := fetchSSE(t, base+"/api/v1/events?token="+tok)
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

// TestSSEAuthStaticTokenQuery: a static env token in the query also authorizes
// (the static/admin-operator/viewer tokens are valid SSE credentials).
func TestSSEAuthStaticTokenQuery(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "admin", "adminpass1", "admin")
	apiH.SetAuth(staticAdminToken, "static-op-token", "static-viewer-token")
	apiH.SetAuthController(serverauth.New(apiH.Store(), nil))
	base := srv.URL

	// Static viewer token (lowest role) is enough for the read-only stream.
	code, body := fetchSSE(t, base+"/api/v1/events?token=static-viewer-token")
	if code != http.StatusOK {
		t.Fatalf("static-viewer SSE: status %d, want 200", code)
	}
	if !strings.Contains(body, "event: connected") {
		t.Fatalf("expected the connected ping, got %q", body)
	}

	// A garbage static token is rejected.
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
