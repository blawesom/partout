package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestPresetAPI: GET status + POST apply over the router. A fresh test
// server has no preset rows (the test harness builds the store directly,
// bypassing main's first-boot seed), so apply creates all defaults and a
// second apply is a no-op.
func TestPresetAPI(t *testing.T) {
	_, _, srv := startAPITest(t)
	defer srv.Close()

	do := func(method, path string, body string) (int, string) {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, srv.URL+path, rd)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// Status before apply: nothing present.
	code, body := do("GET", "/api/v1/preset", "")
	if code != http.StatusOK {
		t.Fatalf("status: %d %s", code, body)
	}
	var st struct {
		Policies []struct {
			Present bool `json:"present"`
		} `json:"policies"`
		AlertRules []struct {
			Present bool `json:"present"`
		} `json:"alert_rules"`
	}
	_ = json.Unmarshal([]byte(body), &st)
	if len(st.Policies) != 4 || len(st.AlertRules) != 6 {
		t.Fatalf("status rows = %d policies / %d alerts, want 4/6", len(st.Policies), len(st.AlertRules))
	}
	for _, p := range st.Policies {
		if p.Present {
			t.Fatalf("policy %v present before apply", p)
		}
	}

	// Apply: creates everything.
	code, body = do("POST", "/api/v1/preset/apply", "{}")
	if code != http.StatusOK {
		t.Fatalf("apply: %d %s", code, body)
	}
	var res struct {
		CreatedPolicies []string `json:"created_policies"`
		CreatedAlerts   []string `json:"created_alerts"`
	}
	_ = json.Unmarshal([]byte(body), &res)
	if len(res.CreatedPolicies) != 4 || len(res.CreatedAlerts) != 6 {
		t.Fatalf("apply created %d/%d, want 4/6: %s", len(res.CreatedPolicies), len(res.CreatedAlerts), body)
	}

	// Apply again: no-op.
	code, body = do("POST", "/api/v1/preset/apply", "{}")
	if code != http.StatusOK {
		t.Fatalf("re-apply: %d %s", code, body)
	}
	var res2 struct {
		CreatedPolicies []string `json:"created_policies"`
		CreatedAlerts   []string `json:"created_alerts"`
	}
	_ = json.Unmarshal([]byte(body), &res2)
	if len(res2.CreatedPolicies) != 0 || len(res2.CreatedAlerts) != 0 {
		t.Fatalf("re-apply created rows: %s", body)
	}

	// Status now: all present.
	_, body = do("GET", "/api/v1/preset", "")
	_ = json.Unmarshal([]byte(body), &st)
	for _, p := range st.Policies {
		if !p.Present {
			t.Fatalf("policy not present after apply: %+v", st.Policies)
		}
	}
	for _, a := range st.AlertRules {
		if !a.Present {
			t.Fatalf("alert rule not present after apply: %+v", st.AlertRules)
		}
	}
}
