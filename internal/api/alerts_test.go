// M6 alert engine: REST API tests (rules CRUD + alert list) and an
// engine→SSE E2E (fact flip → alert.firing / alert.resolved events).
package api_test

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/server/observe"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestAlertsRulesCRUD: create → list → update → delete via the router.
func TestAlertsRulesCRUD(t *testing.T) {
	_, _, srv := startAPITest(t)
	defer srv.Close()

	post := func(path, body string) (int, string) {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// Invalid kind → 400.
	code, body := post("/api/v1/alerts/rules", `{"name":"bad","kind":"nope"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("bad kind: %d %s", code, body)
	}

	// Create (local mode = admin).
	code, body = post("/api/v1/alerts/rules",
		`{"name":"db ssh down","kind":"service_failed","selector":"role:db","severity":"critical","thresholds":{"service_failed_minutes":0}}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created map[string]any
	_ = json.Unmarshal([]byte(body), &created)
	ruleID, _ := created["id"].(string)
	if ruleID == "" {
		t.Fatalf("create: no id in %s", body)
	}
	if created["severity"] != "critical" || created["enabled"] != true {
		t.Fatalf("create: %+v", created)
	}

	// List (viewer-equivalent read in local mode).
	code, body = get("/api/v1/alerts/rules")
	if code != http.StatusOK || !strings.Contains(body, "db ssh down") {
		t.Fatalf("list: %d %s", code, body)
	}

	// Update: disable.
	req, _ := http.NewRequest("PUT", srv.URL+"/api/v1/alerts/rules/"+ruleID,
		strings.NewReader(`{"enabled":false}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `"enabled":false`) {
		t.Fatalf("update: %d %s", resp.StatusCode, b)
	}

	// Delete.
	req, _ = http.NewRequest("DELETE", srv.URL+"/api/v1/alerts/rules/"+ruleID, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	code, _ = get("/api/v1/alerts/rules/" + ruleID)
	if code != http.StatusNotFound {
		t.Fatalf("get deleted rule: %d, want 404", code)
	}
}

// TestAlertsRuleKinds: all five rule kinds are accepted by the API (M6.1 + M7
// added service_restarting and config_drift); unknown kinds stay 400.
func TestAlertsRuleKinds(t *testing.T) {
	_, _, srv := startAPITest(t)
	defer srv.Close()
	for _, kind := range []string{"service_failed", "service_restarting", "cert_expiring", "config_invalid", "config_drift"} {
		resp, err := http.Post(srv.URL+"/api/v1/alerts/rules", "application/json",
			strings.NewReader(`{"name":"k","kind":"`+kind+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("kind %s: %d, want 201", kind, resp.StatusCode)
		}
	}
	resp, err := http.Post(srv.URL+"/api/v1/alerts/rules", "application/json",
		strings.NewReader(`{"name":"k","kind":"endpoint_down"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d, want 400", resp.StatusCode)
	}
}

// TestAlertsRulePartialUpdatePreservesFields: a partial PUT must not reset a
// rule's thresholds to defaults nor re-enable a disabled rule. Both were
// silently clobbered because empty/absent values were treated as "clear".
func TestAlertsRulePartialUpdatePreservesFields(t *testing.T) {
	_, _, srv := startAPITest(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/alerts/rules", "application/json",
		strings.NewReader(`{"name":"keep","kind":"service_restarting","selector":"role:db","severity":"critical","enabled":false,"thresholds":{"service_restart_rate_per_hour":42}}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var created map[string]any
	_ = json.Unmarshal(body, &created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("no id in %s", body)
	}

	// Rename only: everything else must survive.
	req, _ := http.NewRequest("PUT", srv.URL+"/api/v1/alerts/rules/"+id,
		strings.NewReader(`{"name":"renamed"}`))
	req.Header.Set("Content-Type", "application/json")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("put: %d %s", r2.StatusCode, b2)
	}
	var got map[string]any
	if err := json.Unmarshal(b2, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["name"] != "renamed" {
		t.Errorf("name = %v, want renamed", got["name"])
	}
	if got["enabled"] != false {
		t.Errorf("partial update re-enabled the rule: enabled = %v", got["enabled"])
	}
	if got["selector"] != "role:db" || got["severity"] != "critical" {
		t.Errorf("selector/severity lost: %v / %v", got["selector"], got["severity"])
	}
	th, _ := got["thresholds"].(map[string]any)
	if th == nil || th["service_restart_rate_per_hour"] != float64(42) {
		t.Errorf("thresholds reset to defaults: %v", got["thresholds"])
	}
}

// TestAlertsRuleThresholdValidation: negative/fractional known thresholds are
// rejected at the API (a negative rate silently inverts the rule's condition).
func TestAlertsRuleThresholdValidation(t *testing.T) {
	_, _, srv := startAPITest(t)
	defer srv.Close()
	bad := []string{
		`{"name":"n","kind":"service_restarting","thresholds":{"service_restart_rate_per_hour":-1}}`,
		`{"name":"n","kind":"cert_expiring","thresholds":{"cert_days_remaining":-5}}`,
		`{"name":"n","kind":"service_failed","thresholds":{"service_failed_minutes":-1}}`,
		`{"name":"n","kind":"config_drift","thresholds":{"config_drift_tolerance":-1}}`,
		`{"name":"n","kind":"cert_expiring","thresholds":{"cert_days_remaining":1.5}}`,
		`{"name":"n","kind":"cert_expiring","thresholds":{"cert_days_remaining":"soon"}}`,
	}
	for _, payload := range bad {
		resp, err := http.Post(srv.URL+"/api/v1/alerts/rules", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("payload %s: %d, want 400", payload, resp.StatusCode)
		}
	}
	// A valid zero and a valid positive still work.
	for _, ok := range []string{
		`{"name":"z","kind":"service_restarting","thresholds":{"service_restart_rate_per_hour":0}}`,
		`{"name":"p","kind":"cert_expiring","thresholds":{"cert_days_remaining":30}}`,
	} {
		resp, err := http.Post(srv.URL+"/api/v1/alerts/rules", "application/json", strings.NewReader(ok))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("payload %s: %d, want 201", ok, resp.StatusCode)
		}
	}
}

// TestAlertsE2EFiresAndResolvesViaSSE: seed a failing service fact, tick the
// engine, verify the alert is listed and SSE emitted alert.firing; then
// recovery → alert.resolved.
func TestAlertsE2EFiresAndResolvesViaSSE(t *testing.T) {
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

	if err := st.UpsertAgent(store.Agent{ID: "ag_alert", UUID: "u-alert"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAlertRule(&store.AlertRule{
		ID: "rule_e2e", Name: "e2e", Kind: "service_failed", Selector: "all",
		Thresholds: `{"service_failed_minutes":0}`, Severity: "critical",
		Enabled: true, CreatedAt: time.Now().Unix(), UpdatedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}

	// SSE client connected BEFORE the engine fires.
	sseResp, err := http.Get(srv.URL + "/api/v1/events")
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer sseResp.Body.Close()
	if ct := sseResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("SSE content type: %q", ct)
	}
	sc := bufio.NewScanner(sseResp.Body)
	readEvent := func() (string, bool) {
		for {
			if !sc.Scan() {
				return "", false
			}
			if line := sc.Text(); strings.HasPrefix(line, "event: ") {
				return strings.TrimPrefix(line, "event: "), true
			}
		}
	}
	if kind, ok := readEvent(); !ok || kind != "connected" {
		t.Fatalf("first SSE event = %q (ok=%v), want connected", kind, ok)
	}
	time.Sleep(50 * time.Millisecond) // subscription live

	eng := observe.New(st, sseB, log.New(io.Discard, "obs: ", 0), time.Hour)

	// Unit fails → tick → alert.firing.
	if err := st.UpsertHostFactsJSON("ag_alert",
		`{"services_detailed":{"units":[{"name":"myapp","state":"failed","sub_state":"running"}]}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.EvaluateOnce(); err != nil {
		t.Fatal(err)
	}
	if kind, ok := readEvent(); !ok || kind != "alert.firing" {
		t.Fatalf("SSE after failure: %q (ok=%v), want alert.firing", kind, ok)
	}

	// Alert visible on GET /alerts.
	resp, err := http.Get(srv.URL + "/api/v1/alerts?state=firing")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var page struct {
		Alerts []map[string]any `json:"alerts"`
	}
	_ = json.Unmarshal(b, &page)
	if len(page.Alerts) != 1 || page.Alerts[0]["kind"] != "service_failed" {
		t.Fatalf("GET /alerts: %s", b)
	}

	// Recovery → tick → alert.resolved.
	if err := st.UpsertHostFactsJSON("ag_alert",
		`{"services_detailed":{"units":[{"name":"myapp","state":"active","sub_state":"running"}]}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.EvaluateOnce(); err != nil {
		t.Fatal(err)
	}
	if kind, ok := readEvent(); !ok || kind != "alert.resolved" {
		t.Fatalf("SSE after recovery: %q (ok=%v), want alert.resolved", kind, ok)
	}
}
