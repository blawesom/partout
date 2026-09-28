package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/sse"
)

// This file locks the response shapes the embedded web UI reads (the API has no
// compile-time link to internal/api/webui/app.js, so a handler-side rename
// silently blanks a page). These assert the container keys and field names the
// UI dereferences; each one corresponds to a bug found by rendering the UI
// against a live server (see scripts/ui-smoke.sh for that end-to-end harness).
//
// Scope: only endpoints the base test fixture wires. Subsystems that return 503
// here (files/sessions/secrets) are covered end-to-end by the browser harness,
// not by this file.

// TestUIShape_PoliciesFields: GET /policies → {items:[{id,name,match,effect,
// priority}]}. The UI renders name/match/effect/priority; it previously read
// p.cmd_pattern (never present) and dumped raw JSON.
func TestUIShape_PoliciesFields(t *testing.T) {
	_, _, srv := startAPITest(t)

	code, b := apiReq(t, "POST", srv.URL+"/api/v1/policies", "",
		`{"name":"deny-shape","effect":"deny","priority":10,"match":{"command_regex":"^rm"}}`)
	if code != http.StatusCreated {
		t.Fatalf("POST /policies = %d (%s)", code, b)
	}

	code, b = apiReq(t, "GET", srv.URL+"/api/v1/policies", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /policies = %d (%s)", code, b)
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) == 0 {
		t.Fatal("expected at least one policy")
	}
	for _, k := range []string{"id", "name", "match", "effect", "priority"} {
		if _, ok := body.Items[0][k]; !ok {
			t.Errorf("policy missing %q (UI reads it); got %v", k, keysOf(body.Items[0]))
		}
	}
}

// TestUIShape_BareArrays: /tasks, /jobs, /playbooks return bare JSON arrays; the
// UI iterates the response directly (d.items || d). Subsystems not wired in this
// fixture answer 503 <x>_disabled and are skipped (the browser harness covers
// them end-to-end).
func TestUIShape_BareArrays(t *testing.T) {
	_, _, srv := startAPITest(t)
	for _, path := range []string{"/api/v1/tasks", "/api/v1/jobs", "/api/v1/playbooks", "/api/v1/groups"} {
		code, b := apiReq(t, "GET", srv.URL+path, "", "")
		if code == http.StatusServiceUnavailable {
			t.Logf("GET %s not wired in this fixture: %s", path, truncate(b, 60))
			continue
		}
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", path, code, b)
		}
		trimmed := trimSpace(b)
		if len(trimmed) == 0 || trimmed[0] != '[' {
			t.Errorf("GET %s = %s, want a bare JSON array (UI iterates it directly)", path, truncate(b, 80))
		}
	}
}

// TestUIShape_HostsWrappedItems: /hosts → {items, next_cursor}; the UI reads
// data.items for the fleet table.
func TestUIShape_HostsWrappedItems(t *testing.T) {
	_, _, srv := startAPITest(t)
	code, b := apiReq(t, "GET", srv.URL+"/api/v1/hosts", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /hosts = %d (%s)", code, b)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["items"]; !ok {
		t.Errorf("GET /hosts keys = %v, want %q (UI reads data.items)", mapKeys(body), "items")
	}
	// The host object the fleet list and overview card read.
	var items struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(b, &items); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	if len(items.Items) == 0 {
		t.Fatal("expected the seeded agent in /hosts")
	}
	for _, k := range []string{"id", "uuid", "state", "version", "first_seen", "last_seen"} {
		if _, ok := items.Items[0][k]; !ok {
			t.Errorf("host entry missing %q (fleet table + overview read it); got %v", k, keysOf(items.Items[0]))
		}
	}
}

// TestUIShape_ObserveWrappedCount: /services, /certificates, /configs →
// {items, count}; the UI reads data.items.
func TestUIShape_ObserveWrappedCount(t *testing.T) {
	_, _, srv := startAPITest(t)
	for _, path := range []string{"/api/v1/services", "/api/v1/certificates", "/api/v1/configs"} {
		code, b := apiReq(t, "GET", srv.URL+path, "", "")
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", path, code, b)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if _, ok := body["items"]; !ok {
			t.Errorf("GET %s keys = %v, want %q (UI reads data.items)", path, mapKeys(body), "items")
		}
	}
}

// TestUIShape_PerHostEndpointsFailClosed: the UI must always send a host to the
// per-host endpoints. Assert they reject a missing agent_id with the stable
// bad_request code (so the UI shows "pick a host" rather than a broken page),
// and that the disabled code is the documented one when unwired.
func TestUIShape_PerHostEndpointsFailClosed(t *testing.T) {
	_, _, srv := startAPITest(t)
	cases := []struct {
		path     string
		wantCode string
	}{
		{"/api/v1/packages/updates", "bad_request"},
		{"/api/v1/files/list?path=/", "files_disabled"},
	}
	for _, c := range cases {
		code, b := apiReq(t, "GET", srv.URL+c.path, "", "")
		if code != http.StatusBadRequest && code != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want 400 or 503 (%s)", c.path, code, b)
			continue
		}
		var e map[string]any
		if err := json.Unmarshal(b, &e); err != nil {
			t.Errorf("decode %s: %v", c.path, err)
			continue
		}
		// Either the exact "missing agent_id" rejection or the disabled marker;
		// both are non-2xx with a stable code the UI can branch on.
		switch e["code"] {
		case c.wantCode:
		case "packages_disabled", "files_disabled":
			t.Logf("GET %s not wired in this fixture: %v", c.path, e["code"])
		default:
			t.Errorf("GET %s code = %v, want %q or a *_disabled marker", c.path, e["code"], c.wantCode)
		}
	}
}

// ---- helpers ----

// TestUIShape_ApprovalsFields: GET /approvals → {approvals:[{id,action_class,
// agent_id,actor,actor_role,matched_rules,state,created_unix,expires_unix,
// decided_by,decision_reason}]}. The UI (Approvals page, M4) dereferences
// these; a handler-side rename silently blanks the page.
func TestUIShape_ApprovalsFields(t *testing.T) {
	apiH, streamH, srv := startAPITest(t)

	// Wire the approvals controller (the shared fixture leaves it at 503).
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	apr := approvals.New(apiH.Store(), streamH, sse.New(), nil)
	apr.SetIdentity(ident)
	apiH.SetApprovals(apr)
	if _, err := apr.NewRequest(approvals.NewRequestParams{
		ActionClass: "exec", AgentID: "ag_api",
		Actor: "alice", ActorRole: "operator",
		MatchedRules: []string{"r1"}, Payload: map[string]any{"cmd": "rm"},
	}); err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	code, b := apiReq(t, "GET", srv.URL+"/api/v1/approvals", "", "")
	if code == http.StatusServiceUnavailable {
		t.Skipf("GET /approvals not wired in this fixture: %s", truncate(b, 60))
	}
	if code != http.StatusOK {
		t.Fatalf("GET /approvals = %d (%s)", code, truncate(b, 120))
	}
	var body struct {
		Approvals []map[string]any `json:"approvals"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Approvals) == 0 {
		t.Fatal("expected at least one approval request")
	}
	for _, k := range []string{"id", "action_class", "agent_id", "actor", "actor_role",
		"matched_rules", "state", "created_unix", "expires_unix", "decided_by", "decision_reason"} {
		if _, ok := body.Approvals[0][k]; !ok {
			t.Errorf("approval missing %q (UI reads it); got %v", k, keysOf(body.Approvals[0]))
		}
	}
}

// TestUIShape_MCPInfo: GET /mcp/info → {protocol_version, http_endpoint,
// transports[], stdio_command, auth, tools:[{name,write,description}]}.
// The UI (MCP page, M4/R11) renders the connect card + tools table from
// these; a rename silently blanks the page.
func TestUIShape_MCPInfo(t *testing.T) {
	_, _, srv := startAPITest(t)

	code, b := apiReq(t, "GET", srv.URL+"/api/v1/mcp/info", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /mcp/info = %d (%s)", code, truncate(b, 120))
	}
	var body struct {
		ProtocolVersion string           `json:"protocol_version"`
		HTTPEndpoint    string           `json:"http_endpoint"`
		Transports      []string         `json:"transports"`
		StdioCommand    string           `json:"stdio_command"`
		Auth            string           `json:"auth"`
		Tools           []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ProtocolVersion == "" || body.HTTPEndpoint == "" || len(body.Transports) == 0 {
		t.Errorf("missing protocol/endpoint/transports: %+v", body)
	}
	if len(body.Tools) < 20 {
		t.Errorf("expected 20+ tools, got %d", len(body.Tools))
	}
	names := map[string]bool{}
	for _, tl := range body.Tools {
		for _, k := range []string{"name", "write", "description"} {
			if _, ok := tl[k]; !ok {
				t.Errorf("tool missing %q; got %v", k, keysOf(tl))
			}
		}
		names[fmt.Sprint(tl["name"])] = true
	}
	for _, want := range []string{"list_hosts", "get_host_facts", "run_command", "decide_approval"} {
		if !names[want] {
			t.Errorf("expected tool %q in catalog", want)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mapKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestUIShape_Alerts: GET /alerts + /alerts/rules shapes for the M6 alert
// engine (capability "alerts": true; UI page lands in M7). A rename or
// reshaped payload silently blanks the consumers, so pin the field names.
func TestUIShape_Alerts(t *testing.T) {
	_, _, srv := startAPITest(t)

	code, b := apiReq(t, "POST", srv.URL+"/api/v1/alerts/rules", "",
		`{"name":"shape","kind":"service_failed","selector":"all","severity":"warning"}`)
	if code != http.StatusCreated {
		t.Fatalf("POST /alerts/rules = %d (%s)", code, truncate(b, 120))
	}

	code, b = apiReq(t, "GET", srv.URL+"/api/v1/alerts/rules", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /alerts/rules = %d (%s)", code, truncate(b, 120))
	}
	var rules struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(b, &rules); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	if len(rules.Rules) != 1 {
		t.Fatalf("rules: %s", b)
	}
	for _, k := range []string{"id", "name", "kind", "selector", "thresholds", "severity", "enabled"} {
		if _, ok := rules.Rules[0][k]; !ok {
			t.Errorf("rule missing field %q", k)
		}
	}

	code, b = apiReq(t, "GET", srv.URL+"/api/v1/alerts", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /alerts = %d (%s)", code, truncate(b, 120))
	}
	var alerts struct {
		Alerts []map[string]any `json:"alerts"`
		Count  int              `json:"count"`
	}
	if err := json.Unmarshal(b, &alerts); err != nil {
		t.Fatalf("decode alerts: %v", err)
	}
	if alerts.Count != 0 {
		t.Errorf("alerts: count = %d, want 0 (nothing fired yet)", alerts.Count)
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\t' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\t' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}
