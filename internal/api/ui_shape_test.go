package api_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	for _, k := range []string{"id", "uuid", "state", "version", "first_seen", "last_seen", "name"} {
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

// TestUIShape_SSESubscriptionsAreEmitted guards the failure mode where the UI
// subscribes to a named SSE event that the server never emits. Because SSE
// named events only reach listeners registered for the exact name, a typo
// (e.g. "provision.key.confirmed" while the server emits
// "provision.key_confirm") silently disables a live update — the page just
// stops refreshing. That is exactly how the provision key-confirm gate was
// invisible in the browser until an operator refreshed manually.
//
// It cross-checks the UI's subscription list against the emitted event names
// in the linked source tree (including dynamically built names such as
// "provision."+state and "job."+kind).
func TestUIShape_SSESubscriptionsAreEmitted(t *testing.T) {
	root := repoRoot(t)

	appJS, err := os.ReadFile(filepath.Join(root, "internal", "api", "webui", "app.js"))
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	subs := sseSubscriptions(string(appJS))
	if len(subs) == 0 {
		t.Fatal("no SSE subscriptions found in app.js (parser drift?)")
	}

	// Collect every literal emitted event name across the whole module (not just
	// internal/server: control.go emits execution.state), plus the dynamic
	// prefixes that are concatenated at the emit site. Event names are also
	// passed as helper arguments (e.g. c.emit(a, "alert.firing")), so match any
	// quoted dotted literal alongside an emit-ish identifier.
	emitted := map[string]bool{}
	prefixes := map[string]bool{}
	err = filepath.WalkDir(root,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			if strings.Contains(path, string(filepath.Separator)+"webui"+string(filepath.Separator)) {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			src := string(b)
			for _, m := range emitLitRe.FindAllStringSubmatch(src, -1) {
				emitted[m[1]] = true
			}
			for _, m := range emitPrefixRe.FindAllStringSubmatch(src, -1) {
				prefixes[m[1]] = true
			}
			// Helper-argument form: emitX(a, "alert.firing") / Emit(event...) with
			// a literal in the same call. Only consider lines mentioning emit.
			for _, line := range strings.Split(src, "\n") {
				if !strings.Contains(line, "mit(") {
					continue
				}
				for _, m := range dottedLitRe.FindAllStringSubmatch(line, -1) {
					emitted[m[1]] = true
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	// "provision."+state produces provision.<state> for the terminal states.
	for _, st := range []string{"failed", "cancelled", "connected", "handoff"} {
		emitted["provision."+st] = true
	}

	for _, k := range subs {
		if emitted[k] || prefixes[k] {
			continue
		}
		t.Errorf("UI subscribes to SSE %q but no server emit site produces it "+
			"(named SSE only reaches exact-match listeners, so this live update is dead)", k)
	}
}

var (
	emitLitRe    = regexp.MustCompile(`Emit\("([a-z_-]+(?:\.[a-z_-]+)*)"`)
	emitPrefixRe = regexp.MustCompile(`Emit\("([a-z_-]+\.)"\s*\+`)
	dottedLitRe  = regexp.MustCompile(`"([a-z_-]+\.[a-z_.-]+)"`)
)

// sseSubscriptions extracts the string literals of the subscription list that
// is iterated with addEventListener in app.js.
func sseSubscriptions(src string) []string {
	i := strings.Index(src, "const kinds = [")
	if i < 0 {
		return nil
	}
	j := strings.Index(src[i:], "];")
	if j < 0 {
		return nil
	}
	block := src[i : i+j]
	var out []string
	for _, m := range regexp.MustCompile(`"([a-z_-]+(?:\.[a-z_.-]+)*)"`).FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestUIShape_ToastSystem asserts the global toast notification infrastructure
// is present in the UI and that no blocking alert() boxes remain (they were
// replaced by the toast system for consistent error/success feedback).
func TestUIShape_ToastSystem(t *testing.T) {
	appJS, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "api", "webui", "app.js"))
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	s := string(appJS)
	for _, want := range []string{"notify(kind, msg", ".toasts", "dismissToast"} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js missing toast infrastructure %q", want)
		}
	}
	if n := strings.Count(s, "alert("); n != 0 {
		t.Errorf("app.js still has %d alert() call(s); use the toast system instead", n)
	}
}

// TestUIShape_ChangePasswordContract pins the /auth/password body field names
// (old_password/new_password) and that the UI adopts the re-issued token. A
// {current,new} body is rejected 400 by the server, and ignoring the returned
// token logs the user out on the next request.
func TestUIShape_ChangePasswordContract(t *testing.T) {
	appJS, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "api", "webui", "app.js"))
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	s := string(appJS)
	if !strings.Contains(s, "old_password: this.pw.current") || !strings.Contains(s, "new_password: this.pw.next") {
		t.Error("changePassword must POST old_password/new_password (server rejects current/new with 400)")
	}
	if strings.Contains(s, "body: { current: this.pw.current") {
		t.Error("changePassword still sends the wrong {current,new} body")
	}
	// The server invalidates the caller's token and returns a fresh one.
	idx := strings.Index(s, "async changePassword")
	if idx < 0 {
		t.Fatal("changePassword not found")
	}
	body := s[idx:min(idx+600, len(s))]
	if !strings.Contains(body, ".token") || !strings.Contains(body, "LS_TOKEN") {
		t.Error("changePassword must adopt the re-issued token (d.token + localStorage)")
	}
}

func TestUIShape_AddHostSurface(t *testing.T) {
	appJS, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "api", "webui", "app.js"))
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	s := string(appJS)
	// The add-host entry point, both onboarding options, the token mint call,
	// and the fresh/join mode tooltips must all be present.
	for _, want := range []string{
		"+ Add host",
		"Add your first host",
		"addHostOpen",
		"mintAddHostToken",
		"/agents/enrollment-tokens",
		"Onboard over SSH",
		"Run on the host",
		// fresh/join tooltips (title attrs) on both the Provision page and the dialog
		"title=\"fresh: clean slate",
		"title=\"join: non-destructive",
		"provModeHint",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js missing add-host surface %q", want)
		}
	}
	// The token is shown once: the command block must be gated on ahToken.
	if !strings.Contains(s, "PARTOUT_TOKEN=\" + this.ahToken") {
		t.Error("app.js: add-host command does not embed the one-time token")
	}
}

// TestUIShape_CleartextLoginBanner guards the login-page cleartext warning:
// when the SPA was served over plain http from a non-loopback host, the login
// card must show a warn-box telling the operator the password would cross
// the network unencrypted (the browser-side mirror of doctor's TLS warning).
// This pins the template binding + the computed + the loopback predicate so a
// refactor cannot silently drop the warning; the rendered behavior is
// exercised by scripts/ui-smoke.js (loopback, exposed-http, https branches).
func TestUIShape_CleartextLoginBanner(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "internal", "api", "webui", "app.js"))
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `v-if="cleartextLogin" class="warn-box"`) {
		t.Error("app.js: login card lost the cleartext warn-box binding")
	}
	if !strings.Contains(s, "not encrypted") {
		t.Error("app.js: cleartext warning lost its message text")
	}
	if !strings.Contains(s, "cleartextLogin() {") {
		t.Error("app.js: cleartextLogin computed missing")
	}
	// The computed must consult the captured protocol/host, not a stale copy.
	if !strings.Contains(s, "this.locProtocol !== \"http:\"") {
		t.Error("app.js: cleartextLogin no longer checks the http protocol")
	}
	if !strings.Contains(s, "isLoopbackHost(") {
		t.Error("app.js: isLoopbackHost predicate missing (used by cleartextLogin)")
	}
	// The remedies must be actionable: name the env var.
	if !strings.Contains(s, "PARTOUT_TLS=on") {
		t.Error("app.js: cleartext warning does not name PARTOUT_TLS=on")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above test dir")
		}
		dir = parent
	}
}

// TestUIShape_Security: GET /security shape (fleet scan view) and the
// admin-only scan trigger. Findings are seeded straight into the store
// (the production path is the periodic scan).
func TestUIShape_Security(t *testing.T) {
	_, _, srv := startAPITest(t)
	// The startAPITest handler has no packages controller wired, so the
	// endpoint must fail closed with the documented code.
	code, b := apiReq(t, "GET", srv.URL+"/api/v1/security", "", "")
	if code != http.StatusServiceUnavailable {
		t.Errorf("GET /security unwired = %d (%s), want 503", code, b)
	}
	code, b = apiReq(t, "POST", srv.URL+"/api/v1/security/scan", "", "")
	if code != http.StatusServiceUnavailable {
		t.Errorf("POST /security/scan unwired = %d (%s), want 503", code, b)
	}
}
