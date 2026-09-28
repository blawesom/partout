package api_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/blawesom/partout/internal/server/oauth"
)

// TestOAuthPKCE_EndToEnd drives the full R11 flow over HTTP: register a
// client → authorize (S256) → exchange (PKCE) → the access token works as a
// bearer on the REST + MCP routes.
func TestOAuthPKCE_EndToEnd(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	apiH.SetOAuth(oauth.New(apiH.Store()))

	// 1. Register a client.
	var client struct {
		ID string `json:"id"`
	}
	code, b := doJSON(t, "POST", srv.URL+"/api/v1/mcp/clients", "",
		map[string]any{"name": "claude-code"})
	if code != http.StatusCreated {
		t.Fatalf("create client = %d (%s)", code, b)
	}
	mustJSON(t, b, &client)
	if client.ID == "" {
		t.Fatal("no client id")
	}

	// 2. PKCE pair + authorize (local mode: the caller is "local"/admin).
	verifier, challenge := pkcePair(t)
	var authz struct {
		Code string `json:"code"`
	}
	code, b = doJSON(t, "POST", srv.URL+"/oauth2/authorize", "",
		map[string]any{
			"client_id":             client.ID,
			"code_challenge":        challenge,
			"code_challenge_method": "S256",
		})
	if code != http.StatusOK {
		t.Fatalf("authorize = %d (%s)", code, b)
	}
	mustJSON(t, b, &authz)
	if authz.Code == "" {
		t.Fatal("no code")
	}

	// 3. Exchange with the verifier.
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Principal   string `json:"principal"`
		Role        string `json:"role"`
	}
	code, b = doJSON(t, "POST", srv.URL+"/oauth2/token", "",
		map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     client.ID,
			"code":          authz.Code,
			"code_verifier": verifier,
		})
	if code != http.StatusOK {
		t.Fatalf("token = %d (%s)", code, b)
	}
	mustJSON(t, b, &tok)
	if tok.AccessToken == "" || tok.TokenType != "Bearer" || tok.ExpiresIn <= 0 {
		t.Fatalf("token response = %+v", tok)
	}

	// 4. The access token works as a bearer on the REST API…
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /hosts: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /hosts with oauth token = %d", resp.StatusCode)
	}

	// …and on the MCP route.
	r := mcpCall(t, srv.URL+"/mcp", tok.AccessToken, "tools/call", map[string]any{
		"name":      "list_hosts",
		"arguments": map[string]any{},
	}, 1)
	if r.Error != nil {
		t.Fatalf("mcp with oauth token: rpc error %+v", r.Error)
	}

	// 5. Code reuse must fail at the token endpoint.
	code, b = doJSON(t, "POST", srv.URL+"/oauth2/token", "",
		map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     client.ID,
			"code":          authz.Code,
			"code_verifier": verifier,
		})
	if code != http.StatusBadRequest {
		t.Fatalf("code reuse = %d (%s), want 400", code, b)
	}
}

// pkcePair builds an RFC 7636 S256 (verifier, challenge) pair.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func doJSON(t *testing.T, method, url, token string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return resp.StatusCode, b
}

func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %q: %v", string(b), err)
	}
}
