package api_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func labelsReq(t *testing.T, method, url, body string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(b) > 0 {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s %s: decode: %v (body %s)", method, url, err, b)
		}
	}
	return resp.StatusCode, out
}

// TestHostTagRoleLifecycle verifies the tag/role write endpoints: set a tag,
// see it drive the computed name, add/remove roles, delete the tag, and the
// validation + 404 paths.
func TestHostTagRoleLifecycle(t *testing.T) {
	_, _, srv := startAPITest(t)
	base := srv.URL + "/api/v1/hosts/ag_api"

	// PUT tag name → host name becomes the tag value.
	code, e := labelsReq(t, "PUT", base+"/tags/name", `{"value":"web-01-prod"}`)
	if code != http.StatusOK {
		t.Fatalf("PUT tag name = %d: %v", code, e)
	}
	if e["name"] != "web-01-prod" {
		t.Errorf("name after tag set = %v, want web-01-prod", e["name"])
	}
	tags, _ := e["tags"].(map[string]any)
	if tags["name"] != "web-01-prod" {
		t.Errorf("tags.name = %v, want web-01-prod", tags["name"])
	}

	// Key-only tag (no body).
	code, e = labelsReq(t, "PUT", base+"/tags/staging", "")
	if code != http.StatusOK {
		t.Fatalf("PUT key-only tag = %d: %v", code, e)
	}
	tags, _ = e["tags"].(map[string]any)
	if _, ok := tags["staging"]; !ok {
		t.Errorf("expected key-only tag staging in %v", tags)
	}

	// PUT role prod → name falls back to the first role when the name tag is
	// removed (roles are returned sorted: prod < test).
	code, e = labelsReq(t, "PUT", base+"/roles/prod", "")
	if code != http.StatusOK {
		t.Fatalf("PUT role = %d: %v", code, e)
	}
	roles, _ := e["roles"].([]any)
	if len(roles) != 2 || roles[0] != "prod" || roles[1] != "test" {
		t.Errorf("roles = %v, want [prod test]", roles)
	}

	code, e = labelsReq(t, "DELETE", base+"/tags/name", "")
	if code != http.StatusOK {
		t.Fatalf("DELETE tag = %d: %v", code, e)
	}
	if e["name"] != "prod" {
		t.Errorf("name after tag delete = %v, want prod (first role)", e["name"])
	}

	// DELETE role → back to the remaining role.
	code, e = labelsReq(t, "DELETE", base+"/roles/prod", "")
	if code != http.StatusOK {
		t.Fatalf("DELETE role = %d: %v", code, e)
	}
	if e["name"] != "test" {
		t.Errorf("name after role delete = %v, want test", e["name"])
	}

	// The list endpoint carries the same computed name.
	code, list := labelsReq(t, "GET", srv.URL+"/api/v1/hosts", "")
	if code != http.StatusOK {
		t.Fatalf("GET /hosts = %d", code)
	}
	items, _ := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	if h, _ := items[0].(map[string]any); h["name"] != "test" {
		t.Errorf("list name = %v, want test", h["name"])
	}

	// Validation: bad keys/roles are 400; unknown host is 404.
	if code, _ = labelsReq(t, "PUT", base+"/tags/bad,key", `{"value":"x"}`); code != http.StatusBadRequest {
		t.Errorf("PUT tag bad key = %d, want 400", code)
	}
	if code, _ = labelsReq(t, "PUT", base+"/roles/bad role", ""); code != http.StatusBadRequest {
		t.Errorf("PUT role bad name = %d, want 400", code)
	}
	if code, _ = labelsReq(t, "PUT", srv.URL+"/api/v1/hosts/ag_nope/tags/name", `{"value":"x"}`); code != http.StatusNotFound {
		t.Errorf("PUT tag unknown host = %d, want 404", code)
	}
}

// TestHostOSAndDelete verifies the computed OS label (from os-release facts)
// and the admin DELETE /hosts/{id} endpoint.
func TestHostOSAndDelete(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sseB := sse.New()
	streamH := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := api.New(st, streamH, sseB, log.New(io.Discard, "api: ", 0))
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)

	for _, a := range []store.Agent{
		{ID: "ag_api", UUID: "u-os"},
		{ID: "ag_del", UUID: "u-del"},
	} {
		if err := st.UpsertAgent(a); err != nil {
			t.Fatalf("UpsertAgent: %v", err)
		}
	}

	// Seed os-release facts for the surviving agent.
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_api", TS: 0, Data: map[string]string{
		"host.hostname": "api-box", "host.distro_name": "Ubuntu", "host.distro_version": "24.04",
	}}); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
	}
	code, e := labelsReq(t, "GET", srv.URL+"/api/v1/hosts/ag_api", "")
	if code != http.StatusOK {
		t.Fatalf("GET host = %d", code)
	}
	if e["os"] != "Ubuntu 24.04" {
		t.Errorf("os = %v, want \"Ubuntu 24.04\"", e["os"])
	}
	if e["name"] != "api-box" {
		t.Errorf("name = %v, want api-box (hostname)", e["name"])
	}

	// Delete the second agent; it disappears and re-delete 404s.
	code, _ = labelsReq(t, "DELETE", srv.URL+"/api/v1/hosts/ag_del", "")
	if code != http.StatusOK {
		t.Fatalf("DELETE host = %d", code)
	}
	if code, _ = labelsReq(t, "GET", srv.URL+"/api/v1/hosts/ag_del", ""); code != http.StatusNotFound {
		t.Errorf("GET deleted host = %d, want 404", code)
	}
	if code, _ = labelsReq(t, "DELETE", srv.URL+"/api/v1/hosts/ag_del", ""); code != http.StatusNotFound {
		t.Errorf("DELETE unknown host = %d, want 404", code)
	}

	// The surviving agent is untouched.
	code, list := labelsReq(t, "GET", srv.URL+"/api/v1/hosts", "")
	if code != http.StatusOK {
		t.Fatalf("GET /hosts = %d", code)
	}
	if items, _ := list["items"].([]any); len(items) != 1 {
		t.Errorf("hosts after delete = %d, want 1", len(items))
	}
}
