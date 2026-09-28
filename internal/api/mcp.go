package api

import (
	"net/http"

	"github.com/blawesom/partout/internal/server/mcp"
)

// RegisterMCP adds the MCP self-description route (viewer). The UI's MCP
// page renders from this; it is read-only and carries no credentials.
func (h *Handler) RegisterMCP(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/mcp/info", h.requireRole(roleViewer)(http.HandlerFunc(h.mcpInfo)))
}

// mcpInfo describes the MCP surface: transports, endpoints, protocol
// version, and the full tool catalog (name + read/write class +
// description). The stdio command line is rendered with this server's
// listener address so an operator can copy it into an MCP client config.
func (h *Handler) mcpInfo(w http.ResponseWriter, r *http.Request) {
	// The stdio client needs a network address; advertise the request's
	// Host (works for both http://localhost:8443 and TLS names).
	host := r.Host
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol_version": "2025-06-18",
		"http_endpoint":    "/mcp",
		"transports":       []string{"http", "stdio"},
		"stdio_command":    "partout --mode=mcp --server " + host + " --token <bearer>",
		"auth":             "caller's bearer token (static RBAC token or local-user session token); RBAC + policy + audit are enforced by the REST control plane",
		"tools":            mcp.ToolCatalog(),
	})
}
