package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestCapabilitiesEndpoint verifies the B1 probe returns honest booleans: the
// observe read path is wired, the alert/approval engines are not, and core
// control-plane capabilities are true.
func TestCapabilitiesEndpoint(t *testing.T) {
	_, _, srv := startAPITest(t)
	code, b := apiReq(t, "GET", srv.URL+"/api/v1/capabilities", "", "")
	if code != 200 {
		t.Fatalf("GET /capabilities: %d, want 200 (%s)", code, b)
	}
	var caps map[string]bool
	if err := json.Unmarshal(b, &caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	for _, wantTrue := range []string{"hosts", "groups", "exec", "policies", "audit", "observe"} {
		if !caps[wantTrue] {
			t.Errorf("capability %s = false, want true", wantTrue)
		}
	}
	for _, wantFalse := range []string{"alerts", "approvals"} {
		if caps[wantFalse] {
			t.Errorf("capability %s = true, want false (not built)", wantFalse)
		}
	}
}

// TestStaticServing verifies the embedded UI is served same-origin: the SPA
// document on /, assets with correct content types, a deep-link fallback to
// index.html, and that API/health routes are not swallowed by the fallback.
func TestStaticServing(t *testing.T) {
	_, _, srv := startAPITest(t)

	cases := []struct {
		path       string
		wantCT     string
		wantSubstr string
	}{
		{"/", "text/html", "Partout"},
		{"/index.html", "text/html", "Partout"},
		{"/app.js", "text/javascript", "partout"},
		{"/style.css", "text/css", "--brand"},
		{"/lib/vue.global.prod.js", "text/javascript", "vue"},
		// Deep client-side route → SPA fallback (index.html).
		{"/fleet/somehost/facts", "text/html", "Partout"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest("GET", srv.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", c.path, err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("GET %s: status %d, want 200", c.path, resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, c.wantCT) {
			t.Errorf("GET %s: content-type %q, want prefix %q", c.path, ct, c.wantCT)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if c.wantSubstr != "" && !strings.Contains(strings.ToLower(string(body)), strings.ToLower(c.wantSubstr)) {
			t.Errorf("GET %s: body missing %q (first 200: %q)", c.path, c.wantSubstr, string(body[:min(len(body), 200)]))
		}
	}

	// /healthz must still be the JSON health route, not the SPA.
	code, b := apiReq(t, "GET", srv.URL+"/healthz", "", "")
	if code != 200 || !strings.Contains(string(b), "ok") {
		t.Errorf("GET /healthz: %d %s, want 200 ok", code, b)
	}
}

// TestSelectorResolveB2 verifies the ?selector= preview endpoint resolves the
// server-authoritative host set, and that an unresolvable selector is a 400
// (never a silent empty).
func TestSelectorResolveB2(t *testing.T) {
	_, _, srv := startAPITest(t)

	// "all" resolves the seeded agent.
	code, b := apiReq(t, "GET", srv.URL+"/api/v1/hosts?selector=all", "", "")
	if code != 200 {
		t.Fatalf("selector=all: %d, want 200 (%s)", code, b)
	}
	var res struct {
		Count int `json:"count"`
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Count != 1 || len(res.Items) != 1 || res.Items[0].ID != "ag_api" {
		t.Errorf("selector=all = %+v, want count 1 with ag_api", res)
	}

	// An explicit host: selector resolves the same host.
	code, b = apiReq(t, "GET", srv.URL+"/api/v1/hosts?selector=host:ag_api", "", "")
	if code != 200 {
		t.Fatalf("selector=host:ag_api: %d (%s)", code, b)
	}

	// A bogus selector is a hard 400, not a 200 with an empty set.
	code, b = apiReq(t, "GET", srv.URL+"/api/v1/hosts?selector=nope", "", "")
	if code != http.StatusBadRequest {
		t.Errorf("selector=nope: status %d, want 400 (%s)", code, b)
	}
}
