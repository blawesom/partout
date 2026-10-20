package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/preset"
	"github.com/blawesom/partout/internal/store"
)

// postElev posts a JSON body to an elevation legibility endpoint.
func postElev(t *testing.T, srv *httptest.Server, path, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

// TestElevationValidate: the validate endpoint gives typing-time
// feedback — a valid document answers ok+tier+rule_count, a bad rule
// fails with ok=false naming the rule (a 200, not a 4xx: a malformed
// draft is expected editor state).
func TestElevationValidate(t *testing.T) {
	_, _, srv := startAPITest(t)
	defer srv.Close()

	// Valid document form (broad shapes).
	code, body := postElev(t, srv, "/api/v1/elevation/validate",
		`{"rules":[{"allow":"apt-get","args_prefix":["-y"]},{"allow":"reboot"}]}`)
	if code != http.StatusOK {
		t.Fatalf("valid doc: %d %s", code, body)
	}
	var ok struct {
		OK        bool   `json:"ok"`
		Tier      string `json:"tier"`
		RuleCount int    `json:"rule_count"`
	}
	if err := json.Unmarshal([]byte(body), &ok); err != nil {
		t.Fatal(err)
	}
	if !ok.OK || ok.Tier != "broad" || ok.RuleCount != 2 {
		t.Fatalf("valid doc response: %s", body)
	}

	// Valid {"rules":[...]} document form (strict shapes).
	code, body = postElev(t, srv, "/api/v1/elevation/validate",
		`{"rules":[{"allow":"reboot"}]}`)
	if code != http.StatusOK {
		t.Fatalf("doc form: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &ok)
	if !ok.OK || ok.Tier != "strict" || ok.RuleCount != 1 {
		t.Fatalf("doc form response: %s", body)
	}

	// Bad rule: ambiguous matchers — the error must name rule 1.
	code, body = postElev(t, srv, "/api/v1/elevation/validate",
		`{"rules":[{"allow":"reboot"},{"allow":"cat","args":["x"],"files":["/etc/*"]}]}`)
	if code != http.StatusOK {
		t.Fatalf("bad rule: %d %s", code, body)
	}
	var bad struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(body), &bad)
	if bad.OK || !strings.Contains(bad.Error, "rule 1") {
		t.Fatalf("bad rule response must name rule 1: %s", body)
	}

	// Empty body → ok=false (missing rules), not a panic.
	code, body = postElev(t, srv, "/api/v1/elevation/validate", `{}`)
	if code != http.StatusOK {
		t.Fatalf("empty: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &bad)
	if bad.OK {
		t.Fatalf("empty body must not validate: %s", body)
	}
}

// TestElevationExplain: the explain endpoint answers the editor's
// "why does (not) this command elevate" for inline rules and for a
// stored policy, with a shell-like quoted command split.
func TestElevationExplain(t *testing.T) {
	h, _, srv := startAPITest(t)
	defer srv.Close()

	rules := `[{"allow":"systemctl","verbs":["restart"],"units":["nginx*"]},{"allow":"reboot"}]`

	// Matching rule: index 0, elevated.
	code, body := postElev(t, srv, "/api/v1/elevation/explain",
		`{"rules":`+rules+`,"command":"systemctl restart nginx"}`)
	if code != http.StatusOK {
		t.Fatalf("match: %d %s", code, body)
	}
	var res struct {
		Elevated  bool   `json:"elevated"`
		Note      string `json:"note"`
		RuleIndex int    `json:"rule_index"`
		Tier      string `json:"tier"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Elevated || res.RuleIndex != 0 || res.Tier != "broad" {
		t.Fatalf("match response: %s", body)
	}
	if !strings.Contains(res.Note, "policy rule matched") || !strings.Contains(res.Note, "systemctl") {
		t.Fatalf("match note: %s", body)
	}

	// No match: not elevated, the no-rule note, rule_index -1.
	code, body = postElev(t, srv, "/api/v1/elevation/explain",
		`{"rules":`+rules+`,"command":"systemctl restart postgresql"}`)
	if code != http.StatusOK {
		t.Fatalf("no-match: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &res)
	if res.Elevated || res.RuleIndex != -1 || !strings.Contains(res.Note, "no elevation rule matches") {
		t.Fatalf("no-match response: %s", body)
	}

	// Quoted command split: apt-get -y install "some pkg".
	code, body = postElev(t, srv, "/api/v1/elevation/explain",
		`{"rules":[{"allow":"apt-get","args_prefix":["-y"]}],"command":"apt-get -y install \"some pkg\""}`)
	if code != http.StatusOK {
		t.Fatalf("quoted: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &res)
	if !res.Elevated {
		t.Fatalf("quoted split must keep argv intact: %s", body)
	}

	// Stored-policy form: seed the preset, explain against default-strict.
	presetApply(t, h)
	code, body = postElev(t, srv, "/api/v1/elevation/explain",
		`{"policy":"default-strict","command":"systemctl restart sshd"}`)
	if code != http.StatusOK {
		t.Fatalf("stored: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &res)
	if !res.Elevated || res.Tier == "" {
		t.Fatalf("stored-policy response: %s", body)
	}

	// Unknown stored policy → 400.
	code, _ = postElev(t, srv, "/api/v1/elevation/explain",
		`{"policy":"nope","command":"reboot"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown policy: %d, want 400", code)
	}

	// No rules and no policy → 400.
	code, _ = postElev(t, srv, "/api/v1/elevation/explain", `{"command":"reboot"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("no policy/rules: %d, want 400", code)
	}

	// Empty command → 400.
	code, _ = postElev(t, srv, "/api/v1/elevation/explain", `{"rules":`+rules+`,"command":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("empty command: %d, want 400", code)
	}
}

// TestElevationGenerate: the fleet-aware generator trims a proposal to
// what the matched hosts actually run, explains every decision, and
// refuses empty selections.
func TestElevationGenerate(t *testing.T) {
	h, _, srv := startAPITest(t)
	defer srv.Close()

	// Seed a second host with role web + facts: ubuntu, a labeled custom
	// unit "myapp", nginx + haproxy config facts.
	st := h.Store()
	if err := st.UpsertAgent(store.Agent{ID: "ag_web", UUID: "u-web"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRole("ag_web", "web"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_web", Data: map[string]string{
		"host.distro": "ubuntu", "host.hostname": "web01",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertHostFactsJSON("ag_web", `{
		"services_detailed":{"units":[
			{"name":"myapp","state":"active","labels":["myapp"]},
			{"name":"unlabeled","state":"active"}
		]},
		"configs":{"nginx":{"present":true,"config_valid":true},"haproxy":{"present":true,"config_valid":true}}
	}`); err != nil {
		t.Fatal(err)
	}

	// Broad basis.
	code, body := postElev(t, srv, "/api/v1/elevation/generate",
		`{"selector":"role:web","basis":"broad"}`)
	if code != http.StatusOK {
		t.Fatalf("generate: %d %s", code, body)
	}
	var gen struct {
		Rules        []map[string]any `json:"rules"`
		Tier         string           `json:"tier"`
		HostsMatched int              `json:"hosts_matched"`
		HostDetails  []struct {
			AgentID string   `json:"agent_id"`
			Distro  string   `json:"distro"`
			Units   []string `json:"units"`
			Configs []string `json:"configs"`
		} `json:"host_details"`
		Notes []string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(body), &gen); err != nil {
		t.Fatal(err)
	}
	if gen.HostsMatched != 1 || len(gen.HostDetails) != 1 {
		t.Fatalf("hosts: %s", body)
	}
	hd := gen.HostDetails[0]
	if hd.AgentID != "ag_web" || hd.Distro != "ubuntu" || hd.Units[0] != "myapp" {
		t.Fatalf("host detail: %+v", hd)
	}
	if gen.Tier != "broad" {
		t.Fatalf("tier: %s", body)
	}
	// Trimming: apt present, dnf absent; unit glob myapp*; nginx +
	// haproxy validators; unlabeled unit NOT in scope.
	var hasAllow = func(allow string) bool {
		for _, r := range gen.Rules {
			if r["allow"] == allow {
				return true
			}
		}
		return false
	}
	if !hasAllow("apt-get") || hasAllow("dnf") {
		t.Fatalf("package family trimming failed: %s", body)
	}
	if !hasAllow("nginx") || !hasAllow("haproxy") || hasAllow("caddy") {
		t.Fatalf("validator trimming failed: %s", body)
	}
	var systemctlRule map[string]any
	for _, r := range gen.Rules {
		if r["allow"] == "systemctl" {
			if _, ok := r["units"]; ok {
				systemctlRule = r
			}
		}
	}
	if systemctlRule == nil {
		t.Fatalf("no verb-scoped systemctl rule: %s", body)
	}
	unitsJSON, _ := json.Marshal(systemctlRule["units"])
	if !strings.Contains(string(unitsJSON), "myapp*") || strings.Contains(string(unitsJSON), "unlabeled") {
		t.Fatalf("unit scoping failed: %s", unitsJSON)
	}
	// Notes: legibility vocabulary present.
	joined := strings.Join(gen.Notes, "\n")
	for _, want := range []string{"apt family", "dnf family dropped", "myapp*", "nginx validator included", "haproxy validator included", "self-grant included"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes missing %q: %v", want, gen.Notes)
		}
	}

	// Strict basis: exact-argv forms, no prefix grants.
	code, body = postElev(t, srv, "/api/v1/elevation/generate",
		`{"selector":"role:web","basis":"strict"}`)
	if code != http.StatusOK {
		t.Fatalf("generate strict: %d %s", code, body)
	}
	var gen2 struct {
		Rules []map[string]any `json:"rules"`
		Tier  string           `json:"tier"`
	}
	_ = json.Unmarshal([]byte(body), &gen2)
	if gen2.Tier != "broad" {
		t.Fatalf("strict tier: %s", body)
	}
	for _, r := range gen2.Rules {
		if r["allow"] == "apt-get" {
			if _, ok := r["args_prefix"]; ok {
				t.Fatalf("strict basis must not emit prefix grants: %s", body)
			}
		}
	}
	if !hasRule(gen2.Rules, "apt-get", "args", []any{"-y", "upgrade"}) {
		t.Fatalf("strict basis missing exact-argv upgrade: %s", body)
	}

	// Broad vs strict must differ.
	if fmt.Sprint(gen.Rules) == fmt.Sprint(gen2.Rules) {
		t.Fatalf("broad and strict bases produced identical rules")
	}

	// Empty selector match → 400.
	code, _ = postElev(t, srv, "/api/v1/elevation/generate", `{"selector":"role:nothing"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("empty selector: %d, want 400", code)
	}

	// Bad basis → 400.
	code, _ = postElev(t, srv, "/api/v1/elevation/generate", `{"selector":"role:web","basis":"wild"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("bad basis: %d, want 400", code)
	}
}

func hasRule(rules []map[string]any, allow, matcher string, want []any) bool {
	for _, r := range rules {
		if r["allow"] != allow {
			continue
		}
		got, ok := r[matcher].([]any)
		if !ok || len(got) != len(want) {
			continue
		}
		same := true
		for i := range want {
			if got[i] != want[i] {
				same = false
			}
		}
		if same {
			return true
		}
	}
	return false
}

// presetApply seeds the preset into a test handler's store (bypassing
// the admin-only HTTP surface).
func presetApply(t *testing.T, h *api.Handler) {
	t.Helper()
	if _, err := preset.Apply(h.Store()); err != nil {
		t.Fatalf("preset apply: %v", err)
	}
}
