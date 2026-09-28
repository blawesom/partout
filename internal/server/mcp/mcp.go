package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/blawesom/partout/internal/agent/facts"
)

// Protocol constants (MCP spec, 2025-06-18).
const (
	protocolVersion = "2025-06-18"
	serverName      = "partout"
)

// JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// rpcRequest is one JSON-RPC 2.0 request (or notification when ID is null).
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"` // number or string; null/absent = notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Server is the MCP method dispatcher. It is stateless per request (MCP
// clients may retry; tool calls are idempotent at the MCP layer because the
// REST control plane owns idempotency/dedup).
type Server struct {
	api   API
	tools []*Tool
	log   *log.Logger
}

// New builds a Server with the default tool set.
func New(api API, lg *log.Logger) *Server {
	if lg == nil {
		lg = log.Default()
	}
	return &Server{api: api, tools: DefaultTools(), log: lg}
}

// HandleRPC processes one JSON-RPC message with the caller's bearer token
// (enforced by the transport layer; forwarded to the control plane so
// RBAC/audit attribute every action to the caller) and returns the response
// bytes (nil for notifications, which get no response per JSON-RPC 2.0).
func (s *Server) HandleRPC(ctx context.Context, data []byte, token string) []byte {
	var req rpcRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return s.errorResponse(nil, codeParseError, "parse error: "+err.Error())
	}
	if req.JSONRPC != "2.0" {
		return s.errorResponse(req.ID, codeInvalidRequest, "jsonrpc must be \"2.0\"")
	}
	notification := len(req.ID) == 0 || string(req.ID) == "null"

	var result any
	var rpcErr *rpcError
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      any    `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &p)
		result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": facts.Version},
			"instructions": "Partout fleet control plane. Read tools are read-only. " +
				"Write tools (run_command, cancel_execution, run_job, apply_updates, " +
				"create_secret, decide_approval) mutate hosts and are RBAC-gated " +
				"(operator/admin) and policy-gated; policy denials and approval " +
				"requests come back as structured errors — do not retry them " +
				"without operator input.",
		}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		out := make([]map[string]any, 0, len(s.tools))
		for _, t := range s.tools {
			out = append(out, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": t.InputSchema,
			})
		}
		result = map[string]any{"tools": out}
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			rpcErr = &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}
			break
		}
		res, err := s.callTool(ctx, token, p.Name, p.Arguments)
		if err != nil {
			// Tool-level errors are results with isError=true (MCP spec): the
			// client sees the structured refusal text, not a JSON-RPC error.
			result = map[string]any{
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
				"isError": true,
			}
			break
		}
		result = res
	case "notifications/initialized":
		// Notification: acknowledged with no response.
	default:
		rpcErr = &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}
	}

	if notification && rpcErr == nil {
		return nil // notifications get no response
	}
	if notification && rpcErr != nil {
		// A malformed notification: report the error with a null id.
		req.ID = []byte("null")
	}
	return s.errorOrResult(req.ID, result, rpcErr)
}

func (s *Server) errorOrResult(id json.RawMessage, result any, rpcErr *rpcError) []byte {
	resp := rpcResponse{JSONRPC: "2.0", ID: idOrNull(id)}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	b, err := json.Marshal(resp)
	if err != nil {
		s.log.Printf("mcp: encode response: %v", err)
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal"}}`)
	}
	return b
}

func (s *Server) errorResponse(id json.RawMessage, code int, msg string) []byte {
	return s.errorOrResult(id, nil, &rpcError{Code: code, Message: msg})
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 || string(id) == "null" {
		return []byte("null")
	}
	return id
}

// callTool dispatches a tools/call to the registered tool.
func (s *Server) callTool(ctx context.Context, token, name string, args map[string]any) (any, error) {
	for _, t := range s.tools {
		if t.Name != name {
			continue
		}
		text, err := t.Call(ctx, s.api, token, args)
		if err != nil {
			// Tool-level errors are results with isError=true (MCP spec): the
			// client sees the structured refusal text, not a JSON-RPC error.
			return map[string]any{
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
				"isError": true,
			}, nil
		}
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		}, nil
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}
