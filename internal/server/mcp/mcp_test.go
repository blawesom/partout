package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeAPI returns canned responses keyed by "METHOD path".
type fakeAPI struct {
	mu  atomic.Pointer[map[string]fakeResp]
	log *log.Logger
}

type fakeResp struct {
	code int
	body string
}

func (f *fakeAPI) set(method, path, body string, code int) {
	m := map[string]fakeResp{method + " " + path: {code: code, body: body}}
	f.mu.Store(&m)
}

func (f *fakeAPI) Call(ctx context.Context, method, path, token string, body any) (int, []byte, error) {
	m := f.mu.Load()
	if m == nil {
		return 500, []byte(`{"code":"internal","message":"fake: no canned response"}`), nil
	}
	if r, ok := (*m)[method+" "+path]; ok {
		return r.code, []byte(r.body), nil
	}
	return 404, []byte(`{"code":"not_found","message":"fake: no route " + method + " " + path}`), nil
}

func testServer(api API) *Server {
	return New(api, log.New(io.Discard, "", 0))
}

func rpc(t *testing.T, s *Server, method string, params any, id int) *rpcResponse {
	t.Helper()
	pb, _ := json.Marshal(params)
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, pb)
	resp := s.HandleRPC(context.Background(), []byte(req), "tok-1")
	if resp == nil {
		t.Fatalf("%s: nil response (want a response)", method)
	}
	var r rpcResponse
	if err := json.Unmarshal(resp, &r); err != nil {
		t.Fatalf("%s: decode: %v (%s)", method, err, resp)
	}
	return &r
}

func TestMCPInitialize(t *testing.T) {
	api := &fakeAPI{}
	s := testServer(api)
	r := rpc(t, s, "initialize", map[string]any{"protocolVersion": protocolVersion}, 1)
	if r.Error != nil {
		t.Fatalf("initialize error: %v", r.Error)
	}
	res, _ := r.Result.(map[string]any)
	if res["protocolVersion"] != protocolVersion {
		t.Fatalf("protocolVersion = %v", res["protocolVersion"])
	}
	info, _ := res["serverInfo"].(map[string]any)
	if info["name"] != serverName {
		t.Fatalf("serverInfo.name = %v", info["name"])
	}
	if _, ok := res["capabilities"]; !ok {
		t.Fatal("missing capabilities")
	}
}

func TestMCPToolsList(t *testing.T) {
	api := &fakeAPI{}
	s := testServer(api)
	r := rpc(t, s, "tools/list", map[string]any{}, 2)
	if r.Error != nil {
		t.Fatalf("tools/list error: %v", r.Error)
	}
	res, _ := r.Result.(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) < 20 {
		t.Fatalf("expected >=20 tools, got %d", len(tools))
	}
	byName := map[string]map[string]any{}
	for _, it := range tools {
		m, _ := it.(map[string]any)
		byName[m["name"].(string)] = m
	}
	for _, want := range []string{"list_hosts", "get_host_facts", "get_audit", "list_approvals",
		"run_command", "apply_updates", "create_secret", "decide_approval", "list_services", "list_certificates",
		"list_alerts"} {
		if _, ok := byName[want]; !ok {
			t.Fatalf("missing tool %q", want)
		}
	}
	// Every tool must carry a JSON Schema.
	for name, m := range byName {
		if _, ok := m["inputSchema"].(map[string]any); !ok {
			t.Errorf("tool %s missing inputSchema object", name)
		}
	}
}

func TestMCPToolCallRead(t *testing.T) {
	api := &fakeAPI{}
	api.set("GET", "/api/v1/hosts", `{"items":[{"id":"ag_x","state":"connected"}]}`, 200)
	s := testServer(api)
	r := rpc(t, s, "tools/call", map[string]any{
		"name":      "list_hosts",
		"arguments": map[string]any{},
	}, 3)
	if r.Error != nil {
		t.Fatalf("tools/call error: %v", r.Error)
	}
	res, _ := r.Result.(map[string]any)
	if res["isError"] == true {
		t.Fatalf("unexpected tool error: %+v", res)
	}
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content = %+v", content)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "ag_x") {
		t.Fatalf("text missing data: %s", text)
	}
}

func TestMCPToolCallStructuredRefusal(t *testing.T) {
	api := &fakeAPI{}
	api.set("POST", "/api/v1/executions",
		`{"code":"forbidden","message":"insufficient role (need operator, got viewer)"}`, 403)
	s := testServer(api)
	r := rpc(t, s, "tools/call", map[string]any{
		"name":      "run_command",
		"arguments": map[string]any{"selector": "all", "cmd": "uptime"},
	}, 4)
	if r.Error != nil {
		t.Fatalf("tools/call error: %v (refusals are tool results, not rpc errors)", r.Error)
	}
	res, _ := r.Result.(map[string]any)
	if res["isError"] != true {
		t.Fatalf("expected isError result, got %+v", res)
	}
	content, _ := res["content"].([]any)
	text, _ := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "insufficient role") || !strings.Contains(text, "operator") {
		t.Fatalf("refusal text must name the rule: %s", text)
	}
}

func TestMCPUnknownToolAndMethod(t *testing.T) {
	api := &fakeAPI{}
	s := testServer(api)

	r := rpc(t, s, "tools/call", map[string]any{"name": "nope", "arguments": map[string]any{}}, 5)
	res, _ := r.Result.(map[string]any)
	if res["isError"] != true {
		t.Fatalf("unknown tool should be a tool error: %+v", res)
	}

	// Unknown method → JSON-RPC error -32601.
	req := `{"jsonrpc":"2.0","id":6,"method":"bogus/method"}`
	resp := s.HandleRPC(context.Background(), []byte(req), "tok")
	var rr rpcResponse
	_ = json.Unmarshal(resp, &rr)
	if rr.Error == nil || rr.Error.Code != codeMethodNotFound {
		t.Fatalf("want -32601, got %+v", rr.Error)
	}
}

func TestMCPNotificationNoResponse(t *testing.T) {
	api := &fakeAPI{}
	s := testServer(api)
	req := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	if resp := s.HandleRPC(context.Background(), []byte(req), "tok"); resp != nil {
		t.Fatalf("notification must get no response, got %s", resp)
	}
}

func TestMCPParseError(t *testing.T) {
	api := &fakeAPI{}
	s := testServer(api)
	resp := s.HandleRPC(context.Background(), []byte(`{not json`), "tok")
	var rr rpcResponse
	_ = json.Unmarshal(resp, &rr)
	if rr.Error == nil || rr.Error.Code != codeParseError {
		t.Fatalf("want -32700, got %+v", rr.Error)
	}
}

func TestMCPHTTPHandler(t *testing.T) {
	api := &fakeAPI{}
	api.set("GET", "/api/v1/groups", `[{"name":"web","selector":"all"}]`, 200)
	s := testServer(api)
	h := HTTPHandler(s)

	// POST with bearer token works.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_groups","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var rr rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rr.Error != nil {
		t.Fatalf("rpc error: %+v", rr.Error)
	}

	// GET → 405.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "/mcp", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec2.Code)
	}
}
