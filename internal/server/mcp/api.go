// Package mcp implements the Partout MCP server (R11, PRD §10.3): a
// JSON-RPC 2.0 tool surface for AI assistants (Claude Code / Cursor / CI)
// over two transports —
//
//   - stdio: `partout mcp --server host:port --token T` (line-delimited
//     JSON-RPC on stdin/stdout; the launched process IS the trust boundary,
//     and the caller's bearer token authenticates every call)
//   - Streamable HTTP: POST /mcp on the main listener (bearer token in the
//     Authorization header; the MCP handler calls the in-process REST router
//     with the same token, so RBAC, policy gating, and audit are enforced by
//     the same control plane the UI/CLI use — no duplicated write path)
//
// Write tools are request/response only (interactive PTY is deliberately
// NOT an MCP tool, PRD §10.3). Structured refusals (403 role, policy deny,
// approval_required) surface verbatim so an agent can reason about them.
//
// OAuth2 (PKCE) is the post-v1 auth model for the HTTP transport (PRD R11);
// v1 uses the existing bearer-token + local-user model (architecture §15,
// tracked as a deviation).
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// API executes one REST call with the caller's token and returns the status
// and body. Two implementations: restClient (stdio mode, remote server) and
// localAPI (in-process /mcp route, same token, in-process router).
type API interface {
	Call(ctx context.Context, method, path, token string, body any) (int, []byte, error)
}

// ---------------------------------------------------------------------------
// restClient — stdio mode against a remote server
// ---------------------------------------------------------------------------

type restClient struct {
	base   string // "http://host:port" or "https://host:port"
	client *http.Client
}

// NewRESTClient builds an API client for a remote server. caPEM (optional)
// enables HTTPS with the given root CA.
func NewRESTClient(base string, client *http.Client) API {
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	if client == nil {
		client = &http.Client{}
	}
	return &restClient{base: strings.TrimRight(base, "/"), client: client}
}

func (c *restClient) Call(ctx context.Context, method, path, token string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("mcp: call %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("mcp: read %s %s: %w", method, path, err)
	}
	return resp.StatusCode, b, nil
}

// ---------------------------------------------------------------------------
// localAPI — in-process /mcp route (serves the caller's token back into the
// REST router; authz/policy/audit are the router's, not the MCP layer's)
// ---------------------------------------------------------------------------

type localAPI struct {
	router http.Handler // the api Handler's mux (includes RBAC middleware)
}

// NewLocalAPI builds an in-process API client over the REST router.
func NewLocalAPI(router http.Handler) API { return &localAPI{router: router} }

func (l *localAPI) Call(ctx context.Context, method, path, token string, body any) (int, []byte, error) {
	var rd io.ReadCloser
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = io.NopCloser(bytes.NewReader(b))
	} else {
		rd = io.NopCloser(bytes.NewReader(nil))
	}
	u, err := url.Parse(path)
	if err != nil {
		return 0, nil, err
	}
	req := &http.Request{
		Method: method,
		URL:    u,
		Body:   rd,
		Header: http.Header{},
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req = req.WithContext(ctx)
	rec := newRecorder()
	l.router.ServeHTTP(rec, req)
	return rec.status, rec.body.Bytes(), nil
}

// newRecorder is a minimal ResponseWriter that captures status + body.
type recorder struct {
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder { return &recorder{status: http.StatusOK} }

func (r *recorder) Header() http.Header         { return http.Header{} }
func (r *recorder) WriteHeader(code int)        { r.status = code }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) Flush()                      {}
