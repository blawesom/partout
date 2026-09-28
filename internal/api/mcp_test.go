package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// mcpCall POSTs one JSON-RPC message to /mcp with a bearer token.
func mcpCall(t *testing.T, url, token, method string, params any, id int) *struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
} {
	t.Helper()
	pb, _ := json.Marshal(params)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, pb)
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		t.Fatalf("%s: unexpected 202 (notification?)", method)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status = %d", method, resp.StatusCode)
	}
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("%s: decode: %v", method, err)
	}
	return &r
}

// TestMCPHTTP_EndToEnd drives the /mcp endpoint through the real router in
// single-user local mode (no tokens): reads work and write tools are allowed
// (the local-mode principal is admin).
func TestMCPHTTP_EndToEnd(t *testing.T) {
	_, _, srv := startAPITest(t)

	// tools/list must return the tool set.
	r := mcpCall(t, srv.URL+"/mcp", "", "tools/list", map[string]any{}, 1)
	if r.Error != nil {
		t.Fatalf("tools/list: rpc error %+v", r.Error)
	}
	var list struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &list); err != nil {
		t.Fatalf("decode tools: %v", err)
	}
	if len(list.Tools) < 20 {
		t.Fatalf("tools = %d, want >= 20", len(list.Tools))
	}

	// list_hosts reads the real store.
	r = mcpCall(t, srv.URL+"/mcp", "", "tools/call", map[string]any{
		"name":      "list_hosts",
		"arguments": map[string]any{},
	}, 2)
	if r.Error != nil {
		t.Fatalf("list_hosts: rpc error %+v", r.Error)
	}
	var res struct {
		Content []map[string]any `json:"content"`
		IsError bool             `json:"isError"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_hosts failed: %+v", res.Content)
	}
	if len(res.Content) != 1 || !strings.Contains(res.Content[0]["text"].(string), "ag_api") {
		t.Fatalf("list_hosts content = %+v", res.Content)
	}
}

// TestMCPHTTP_RBACGating verifies the RBAC layer gates MCP write tools: a
// viewer token calling run_command gets a structured 403 tool error, while an
// admin token is allowed (the dispatch proceeds to the control plane).
func TestMCPHTTP_RBACGating(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	apiH.SetAuth("admin-tok", "op-tok", "view-tok")

	// viewer → run_command: structured refusal (need operator).
	r := mcpCall(t, srv.URL+"/mcp", "view-tok", "tools/call", map[string]any{
		"name":      "run_command",
		"arguments": map[string]any{"selector": "role:test", "cmd": "uptime"},
	}, 1)
	if r.Error != nil {
		t.Fatalf("viewer run_command: rpc error %+v (want a tool error)", r.Error)
	}
	var res struct {
		Content []map[string]any `json:"content"`
		IsError bool             `json:"isError"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !res.IsError {
		t.Fatalf("viewer run_command should be refused: %+v", res)
	}
	text, _ := res.Content[0]["text"].(string)
	if !strings.Contains(text, "insufficient role") {
		t.Fatalf("refusal text = %q, want 'insufficient role'", text)
	}

	// admin → run_command: allowed by RBAC; the control plane dispatches to
	// the connected fixture agent (role:test matches the seeded host).
	r = mcpCall(t, srv.URL+"/mcp", "admin-tok", "tools/call", map[string]any{
		"name":      "run_command",
		"arguments": map[string]any{"selector": "role:test", "cmd": "uptime"},
	}, 2)
	if r.Error != nil {
		t.Fatalf("admin run_command: rpc error %+v", r.Error)
	}
	res = struct {
		Content []map[string]any `json:"content"`
		IsError bool             `json:"isError"`
	}{}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.IsError {
		t.Fatalf("admin run_command refused: %+v", res.Content)
	}
	text, _ = res.Content[0]["text"].(string)
	if !strings.Contains(text, "execution_id") {
		t.Fatalf("run_command result = %q, want execution_id", text)
	}
}
