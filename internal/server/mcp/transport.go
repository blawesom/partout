package mcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// RunStdio serves the MCP server over stdin/stdout (line-delimited JSON-RPC)
// until stdin closes. This backs `partout mcp --server host:port --token T`:
// an MCP client (Claude Code / Cursor / CI) launches the process; the token
// authenticates every tool call to the control plane.
func RunStdio(ctx context.Context, s *Server, token string) error {
	in := bufio.NewScanner(StdioIn)
	in.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // tool results can be large
	for ctx.Err() == nil && in.Scan() {
		line := in.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if resp := s.HandleRPC(ctx, line, token); resp != nil {
			if _, err := fmt.Fprintf(StdioOut, "%s\n", resp); err != nil {
				return fmt.Errorf("mcp stdio: write: %w", err)
			}
		}
	}
	return in.Err()
}

// StdioIn/StdioOut are the stdio transport's input/output (defaults: os
// stdin/stdout; replaced by tests).
var (
	StdioIn  io.Reader = os.Stdin
	StdioOut io.Writer = os.Stdout
)

// HTTPHandler returns the Streamable HTTP handler for POST /mcp. The caller's
// bearer token (Authorization header) is forwarded to the control plane for
// every tool call, so RBAC + policy + audit attribute actions to the caller
// exactly as the REST API does.
func HTTPHandler(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed (POST only)", http.StatusMethodNotAllowed)
			return
		}
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			http.Error(w, `content-type must be application/json`, http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		token := bearer(r)
		resp := s.HandleRPC(r.Context(), body, token)
		if resp == nil {
			// Notification: 202 Accepted, empty body (MCP Streamable HTTP).
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}
