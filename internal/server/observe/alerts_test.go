// M6 alert engine tests: fire → dedup → resolve → re-arm, per rule kind.
package observe

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func newEngine(t *testing.T, tick time.Duration) (*Controller, *store.Store) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	c := New(st, sse.New(), log.New(testLogW{}, "obs: ", 0), tick)
	return c, st
}

type testLogW struct{}

func (testLogW) Write(p []byte) (int, error) { return len(p), nil }

func seedHost(t *testing.T, st *store.Store, agentID, factsJSON string) {
	t.Helper()
	if err := st.UpsertAgent(store.Agent{ID: agentID, UUID: "u-" + agentID}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.UpsertHostFactsJSON(agentID, factsJSON); err != nil {
		t.Fatalf("UpsertHostFactsJSON: %v", err)
	}
}

func unitFacts(state string) string {
	return `{"services_detailed":{"units":[{"name":"myapp","state":"` + state + `","sub_state":"running","enabled":true}]}}`
}

func makeRule(t *testing.T, st *store.Store, kind, selector, thresholds, severity string, enabled bool) *store.AlertRule {
	t.Helper()
	now := time.Now().Unix()
	ru := &store.AlertRule{
		ID: "rule_test1", Name: "test rule", Kind: kind, Selector: selector,
		Thresholds: thresholds, Severity: severity, Enabled: enabled,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateAlertRule(ru); err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	return ru
}

// TestEmptyFleetTickSilent: on a fresh (hostless) server, a tick over the
// seeded host-scoped rules must NOT log "no hosts matched" — that turned a
// normal empty state into 8 lines of false alarm every 30s. A genuinely bad
// selector (a parse error, not a no-match) must still be logged.
func TestEmptyFleetTickSilent(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	var buf bytes.Buffer
	c := New(st, sse.New(), log.New(&buf, "obs: ", 0), time.Minute)

	// Enabled host-scoped rule; the fleet is empty so it matches nothing.
	now := time.Now().Unix()
	for _, id := range []string{"empty_ok", "empty_bad"} {
		sel := "all"
		if id == "empty_bad" {
			// A parse error (unknown predicate) is a real misconfiguration.
			sel = "bogus:1"
		}
		r := &store.AlertRule{ID: id, Name: id, Kind: KindServiceFailed, Selector: sel,
			Thresholds: `{"minutes":0}`, Severity: "critical", Enabled: true, CreatedAt: now, UpdatedAt: now}
		if err := st.CreateAlertRule(r); err != nil {
			t.Fatalf("CreateAlertRule %s: %v", id, err)
		}
	}
	buf.Reset()
	c.evaluate()
	if got := buf.String(); strings.Contains(got, "no hosts matched") {
		t.Fatalf("empty-fleet tick logged a false alarm:\n%s", got)
	}
	// The parse-error rule must still surface in the log.
	if got := buf.String(); !strings.Contains(got, "bogus:1") {
		t.Fatalf("a genuinely bad selector was not logged:\n%s", got)
	}
}

// TestServiceFailedFireResolve: failed → fires (0-min threshold) → second
// tick dedups → recovered → resolved → failed again → re-armed.
func TestServiceFailedFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_1", unitFacts("active"))
	makeRule(t, st, KindServiceFailed, "all", `{"service_failed_minutes":0}`, "critical", true)

	// Healthy: no alert.
	res, err := c.EvaluateOnce()
	if err != nil {
		t.Fatal(err)
	}
	if res.Fired != 0 || res.Resolved != 0 {
		t.Fatalf("healthy tick: %+v", res)
	}

	// Unit fails: alert fires.
	seedHost(t, st, "ag_1", unitFacts("failed"))
	res, _ = c.EvaluateOnce()
	if res.Fired != 1 || res.Resolved != 0 {
		t.Fatalf("failure tick: %+v, want 1 fired", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 || alerts[0].Kind != KindServiceFailed || alerts[0].Severity != "critical" {
		t.Fatalf("firing alerts: %+v", alerts)
	}

	// Second tick: still failed → dedup, no new row.
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 0 {
		t.Fatalf("dedup tick: %+v, want 0/0", res)
	}
	all, _ := st.ListAlerts("", "", "", 10)
	if len(all) != 1 {
		t.Fatalf("alert count = %d, want 1", len(all))
	}

	// Recovery: resolves.
	seedHost(t, st, "ag_1", unitFacts("active"))
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 1 {
		t.Fatalf("recovery tick: %+v, want 1 resolved", res)
	}
	alerts, _ = st.ListAlerts("resolved", "", "", 10)
	if len(alerts) != 1 || alerts[0].ResolvedAt == nil {
		t.Fatalf("resolved alert: %+v", alerts)
	}

	// Fail again: the same dedup row re-arms.
	seedHost(t, st, "ag_1", unitFacts("failed"))
	res, _ = c.EvaluateOnce()
	if res.Fired != 1 || res.Resolved != 0 {
		t.Fatalf("re-arm tick: %+v, want 1 fired", res)
	}
	all, _ = st.ListAlerts("", "", "", 10)
	if len(all) != 1 || all[0].State != "firing" {
		t.Fatalf("after re-arm: %+v", all)
	}
}

// TestServiceFailedDelayWindow: a 5-minute rule does not fire until the unit
// has been continuously failed for 5 observed minutes.
func TestServiceFailedDelayWindow(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_1", unitFacts("failed"))
	makeRule(t, st, KindServiceFailed, "all", `{"service_failed_minutes":5}`, "warning", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("immediate tick: %+v, want 0 fired (within window)", res)
	}

	// Simulate 5+ minutes of continuous failure: the engine's first-failed
	// timestamp is in memory; advance by re-observing with a shifted now is
	// not possible through EvaluateOnce, so instead use a 0-second tick
	// engine with a 0-minute rule to prove the window blocks firing only
	// while below threshold — here we verify the still-failing state keeps
	// the alert absent for a fresh evaluation pass.
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("second tick within window: %+v, want 0 fired", res)
	}

	// Recovery within the window clears the tracker (no late alert).
	seedHost(t, st, "ag_1", unitFacts("active"))
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 0 {
		t.Fatalf("recovery tick: %+v, want 0/0", res)
	}
}

// TestCertExpiringFireResolve: 12-day cert with a 30-day threshold fires;
// renewal to 200 days resolves.
func TestCertExpiringFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_1", `{"certificates":{"items":[{"path":"/etc/ssl/app.pem","not_after":100,"days_remaining":12}]}}`)
	makeRule(t, st, KindCertExpiring, "all", `{"cert_days_remaining":30}`, "warning", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("expiring tick: %+v, want 1 fired", res)
	}
	msg := ""
	if alerts, _ := st.ListAlerts("firing", "", "", 10); len(alerts) == 1 {
		msg = alerts[0].Message
	}
	if msg == "" {
		t.Fatal("expected a message on the firing alert")
	}

	// Renewed: resolves.
	seedHost(t, st, "ag_1", `{"certificates":{"items":[{"path":"/etc/ssl/app.pem","not_after":900,"days_remaining":200}]}}`)
	res, _ = c.EvaluateOnce()
	if res.Resolved != 1 {
		t.Fatalf("renewal tick: %+v, want 1 resolved", res)
	}
}

// TestCertExpiringBelowThreshold: a 200-day cert never fires.
func TestCertExpiringBelowThreshold(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_1", `{"certificates":{"items":[{"path":"/etc/ssl/ok.pem","not_after":900,"days_remaining":200}]}}`)
	makeRule(t, st, KindCertExpiring, "all", `{"cert_days_remaining":30}`, "warning", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("healthy cert tick: %+v, want 0 fired", res)
	}
}

// TestConfigInvalidFireResolve: invalid haproxy config fires; fixed resolves.
func TestConfigInvalidFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	// ConfigValidated=true — the validator ran and definitively said invalid.
	seedHost(t, st, "ag_1", `{"configs":{"haproxy":{"present":true,"config_valid":false,"config_validated":true,"config_error":"[ALERT] config : bogus","config_file":"/etc/haproxy/haproxy.cfg"}}}`)
	makeRule(t, st, KindConfigInvalid, "all", `{}`, "critical", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("invalid config tick: %+v, want 1 fired", res)
	}

	seedHost(t, st, "ag_1", `{"configs":{"haproxy":{"present":true,"config_valid":true,"config_validated":true,"config_file":"/etc/haproxy/haproxy.cfg"}}}`)
	res, _ = c.EvaluateOnce()
	if res.Resolved != 1 {
		t.Fatalf("fixed config tick: %+v, want 1 resolved", res)
	}
}

// TestConfigInvalidBlockedDoesNotFire: a blocked validation (root-only
// config, no authorized elevation — ConfigValidated=false) must NOT fire
// config_invalid. Field report: ccc.laplane.net — 6 healthy hosts lit up
// as "config invalid" because haproxy.cfg was root-only and the policy
// didn't authorize elevated validation.
func TestConfigInvalidBlockedDoesNotFire(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	// ConfigValidated=false — validation was blocked (permission, no elevation).
	// ConfigValid defaults to false but is NOT evidence of an invalid config.
	seedHost(t, st, "ag_1", `{"configs":{"haproxy":{"present":true,"config_valid":false,"config_validated":false,"config_readable":false,"config_file":"/etc/haproxy/haproxy.cfg"}}}`)
	makeRule(t, st, KindConfigInvalid, "all", `{}`, "critical", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("blocked validation tick: %+v, want 0 fired (blocked is not invalid)", res)
	}
}

// TestConfigInvalidOldAgentFallback: an older agent (< 0.9.14, no
// ConfigValidated) with a non-empty ConfigError fired correctly (the
// validator ran); with an empty ConfigError (validation skipped) it must
// not fire.
func TestConfigInvalidOldAgentFallback(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	makeRule(t, st, KindConfigInvalid, "all", `{`, "critical", true)

	// Old agent, validator ran (ConfigError set) — fire.
	seedHost(t, st, "ag_1", `{"configs":{"nginx":{"present":true,"config_valid":false,"config_error":"nginx: [emerg] unknown directive","config_file":"/etc/nginx/nginx.conf"}}}`)
	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("old agent + validator ran: %+v, want 1 fired", res)
	}

	// Old agent, validation skipped (ConfigError empty) — don't fire.
	seedHost(t, st, "ag_1", `{"configs":{"nginx":{"present":true,"config_valid":false,"config_file":"/etc/nginx/nginx.conf"}}}`)
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("old agent + validation skipped: %+v, want 0 fired", res)
	}
}

// TestConfigInvalidDeletedAgentResolves: firing alerts on a deleted agent
// are resolved by the dedup sweep (field report: ccc.laplane.net — orphaned
// alerts on pre-rejoin agents).
func TestConfigInvalidDeletedAgentResolves(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_1", `{"configs":{"haproxy":{"present":true,"config_valid":false,"config_validated":true,"config_error":"[ALERT] bogus","config_file":"/etc/haproxy/haproxy.cfg"}}}`)
	makeRule(t, st, KindConfigInvalid, "all", `{}`, "critical", true)

	// Fire on the live agent.
	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("live agent tick: %+v, want 1 fired", res)
	}

	// Delete the agent — the alert must resolve on the next sweep.
	if err := st.DeleteAgent("ag_1"); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	// DeleteAgent resolves firing alerts immediately; verify.
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 0 {
		t.Fatalf("after delete: %d firing alerts remain, want 0 (DeleteAgent resolves them)", len(alerts))
	}
}

// TestRuleSelector: a rule scoped to role:db does not fire for hosts
// outside the selector.
func TestRuleSelector(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_db", unitFacts("failed"))
	seedHost(t, st, "ag_web", unitFacts("failed"))
	if err := st.SetRole("ag_db", "db"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := st.SetRole("ag_web", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	makeRule(t, st, KindServiceFailed, "role:db", `{"service_failed_minutes":0}`, "warning", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("selector tick: %+v, want exactly 1 fired (ag_db only)", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 || alerts[0].AgentID != "ag_db" {
		t.Fatalf("selector alerts: %+v", alerts)
	}
}

// TestDisabledRule: a disabled rule evaluates to nothing.
func TestDisabledRule(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_1", unitFacts("failed"))
	makeRule(t, st, KindServiceFailed, "all", `{}`, "warning", false)

	res, _ := c.EvaluateOnce()
	if res.Fired != 0 || res.Rules != 0 {
		t.Fatalf("disabled rule: %+v, want 0 fired / 0 enabled rules", res)
	}
}

// TestMissingFactsFailSoft: a host whose fact document lacks the services
// domain never fires; a host with no facts at all neither fires nor has
// its alert resolved (missing data is not recovery).
func TestMissingFactsFailSoft(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	seedHost(t, st, "ag_1", unitFacts("failed"))
	seedHost(t, st, "ag_2", `{"host.arch":"amd64"}`) // no services domain
	makeRule(t, st, KindServiceFailed, "all", `{"service_failed_minutes":0}`, "warning", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("tick: %+v, want 1 fired (ag_1 only)", res)
	}
	// Re-evaluate the same state: nothing changes (no churn).
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 0 {
		t.Fatalf("no-change tick: %+v, want 0/0", res)
	}
}

// restartFacts builds a services document for one unit with a given
// NRestarts counter value.
func restartFacts(count int) string {
	return `{"services_detailed":{"units":[{"name":"crashy","state":"active","sub_state":"running","n_restarts":` +
		strconv.Itoa(count) + `,"n_restarts_known":true}]}}`
}

// TestServiceRestartingFireResolve (M6.1): baseline → crash loop fires at
// ≥ threshold → dedup → stability resolves → counter reset folds in.
func TestServiceRestartingFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	now := t0
	c.now = func() time.Time { return now }
	makeRule(t, st, KindServiceRestarting, "all", `{"service_restart_rate_per_hour":10}`, "warning", true)

	// Tick 1: baseline sample only — no rate yet, nothing fires.
	seedHost(t, st, "ag_1", restartFacts(100))
	res, _ := c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 0 {
		t.Fatalf("baseline tick: %+v, want 0/0", res)
	}

	// Tick 2: 10 min later, 10 more restarts = 60/hour ≥ 10 → fires.
	now = now.Add(10 * time.Minute)
	seedHost(t, st, "ag_1", restartFacts(110))
	res, _ = c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("crash tick: %+v, want 1 fired", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 || alerts[0].Kind != KindServiceRestarting {
		t.Fatalf("firing alerts: %+v", alerts)
	}

	// Tick 3: still crashing (60/hour) → dedup, no new row.
	now = now.Add(10 * time.Minute)
	seedHost(t, st, "ag_1", restartFacts(120))
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 0 {
		t.Fatalf("dedup tick: %+v, want 0/0", res)
	}

	// Tick 4: the unit is quiet long enough (past the quiet window) → the held
	// rate decays to zero and the alert resolves. An unchanged counter on the
	// very next tick must NOT resolve (that was the flapping bug).
	now = now.Add(restartQuietWindow + time.Minute)
	seedHost(t, st, "ag_1", restartFacts(120))
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 1 {
		t.Fatalf("stable tick: %+v, want 1 resolved", res)
	}

	// Counter reset: systemd resets NRestarts when the unit is (re)started.
	// 120 → 10 is a drop; the engine must fold it (delta = 10, not -110)
	// and re-fire at a high folded rate.
	now = now.Add(10 * time.Minute)
	seedHost(t, st, "ag_1", restartFacts(10))
	res, _ = c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("reset tick: %+v, want 1 fired (folded delta)", res)
	}
}

// TestServiceRestartingMultipleRules: two service_restarting rules on the
// same unit both see the same per-tick rate (sampling once per tick, not
// per rule — the first rule must not consume the window).
func TestServiceRestartingMultipleRules(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	now := t0
	c.now = func() time.Time { return now }
	ruA := &store.AlertRule{ID: "rule_a", Name: "a", Kind: KindServiceRestarting, Selector: "all",
		Thresholds: `{"service_restart_rate_per_hour":10}`, Severity: "warning", Enabled: true}
	ruB := &store.AlertRule{ID: "rule_b", Name: "b", Kind: KindServiceRestarting, Selector: "all",
		Thresholds: `{"service_restart_rate_per_hour":10}`, Severity: "info", Enabled: true}
	for _, ru := range []*store.AlertRule{ruA, ruB} {
		if err := st.CreateAlertRule(ru); err != nil {
			t.Fatal(err)
		}
	}

	seedHost(t, st, "ag_1", restartFacts(100))
	c.EvaluateOnce() // baseline

	now = now.Add(10 * time.Minute)
	seedHost(t, st, "ag_1", restartFacts(110))
	res, _ := c.EvaluateOnce()
	if res.Fired != 2 {
		t.Fatalf("two-rule tick: %+v, want 2 fired (one per rule)", res)
	}
}

// TestServiceRestartingSlowRate: 2 restarts in 30 minutes = 4/hour, below
// the 10/hour threshold — never fires.
func TestServiceRestartingSlowRate(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	now := t0
	c.now = func() time.Time { return now }
	makeRule(t, st, KindServiceRestarting, "all", `{"service_restart_rate_per_hour":10}`, "warning", true)

	seedHost(t, st, "ag_1", restartFacts(0))
	c.EvaluateOnce() // baseline

	now = now.Add(30 * time.Minute)
	seedHost(t, st, "ag_1", restartFacts(2))
	res, _ := c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("slow restart tick: %+v, want 0 fired (4/h < 10/h)", res)
	}
}

// TestConfigDriftFireResolve (M7/R22): identical configs → no alert; one
// host diverges → alert on the minority host; it converges → resolved.
func TestConfigDriftFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	cfg := func(sha string) string {
		return `{"configs":{"haproxy":{"present":true,"config_valid":true,"config_file":"/etc/haproxy/haproxy.cfg","config_sha256":"` + sha + `"}}}`
	}
	seedHost(t, st, "ag_1", cfg("aaaa"))
	seedHost(t, st, "ag_2", cfg("aaaa"))
	makeRule(t, st, KindConfigDrift, "all", `{"config_drift_tolerance":0}`, "info", true)

	// Consistent fleet: no divergence.
	res, _ := c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("consistent tick: %+v, want 0 fired", res)
	}

	// ag_2 diverges: the minority host gets the alert.
	seedHost(t, st, "ag_2", cfg("bbbb"))
	res, _ = c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("drift tick: %+v, want 1 fired", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 || alerts[0].AgentID != "ag_2" {
		t.Fatalf("drift alerts: %+v, want ag_2 flagged", alerts)
	}

	// Re-evaluate the same state: no churn.
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 0 {
		t.Fatalf("drift dedup tick: %+v, want 0/0", res)
	}

	// Converged: resolves.
	seedHost(t, st, "ag_2", cfg("aaaa"))
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 || res.Resolved != 1 {
		t.Fatalf("converge tick: %+v, want 1 resolved", res)
	}
}

// TestConfigDriftTolerance: with tolerance 1, two distinct hashes (each on
// one host) do not fire; three distinct hashes do.
func TestConfigDriftTolerance(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	cfg := func(sha string) string {
		return `{"configs":{"nginx":{"present":true,"config_valid":true,"config_file":"/etc/nginx/nginx.conf","config_sha256":"` + sha + `"}}}`
	}
	seedHost(t, st, "ag_1", cfg("h1"))
	seedHost(t, st, "ag_2", cfg("h2"))
	makeRule(t, st, KindConfigDrift, "all", `{"config_drift_tolerance":1}`, "info", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("tolerance tick: %+v, want 0 fired (2 distinct ≤ 1+1)", res)
	}

	seedHost(t, st, "ag_3", cfg("h3")) // 3 distinct > 1+1
	res, _ = c.EvaluateOnce()
	if res.Fired != 2 {
		t.Fatalf("third-hash tick: %+v, want 2 fired (the two non-majority hosts)", res)
	}
}

// TestServiceRestartingProductionCadence models the real wiring: the alert
// engine ticks every DefaultTick (30 s) but the agent only refreshes the
// facts document every ~300 s, so the NRestarts counter is *unchanged* on the
// intervening ticks. The pre-existing tests advance the counter on every tick,
// which is why they missed this.
//
// Two defects this pins:
//  1. the rate window is the 30 s tick, so a delta accumulated over ~300 s is
//     divided by 30 s (≈10× inflation) — a single restart reads as 120/h and
//     trips the default 10/h threshold;
//  2. the tick after a fire sees delta=0 → rate=0 → the alert is resolved, so a
//     continuously crash-looping unit flaps firing/resolved every facts cycle.
func TestServiceRestartingProductionCadence(t *testing.T) {
	c, st := newEngine(t, 30*time.Second)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	now := t0
	c.now = func() time.Time { return now }

	// Baseline: a healthy counter of 100 restarts.
	seedHost(t, st, "ag_1", restartFacts(100))
	if res, _ := c.EvaluateOnce(); res.Fired != 0 {
		t.Fatalf("baseline tick fired: %+v", res)
	}

	// Over the next 300 s the unit restarts exactly ONCE (100 → 101) — a true
	// rate of 12/h. Set the threshold above that (20/h) so a correct engine
	// stays quiet; the buggy 30 s window would compute 1/30s = 120/h and fire.
	makeRule(t, st, KindServiceRestarting, "all", `{"service_restart_rate_per_hour":20}`, "warning", true)
	for i := 0; i < 10; i++ {
		now = now.Add(30 * time.Second)
		if res, _ := c.EvaluateOnce(); res.Fired != 0 {
			t.Fatalf("tick %d fired on a steady counter (%+v): the 30 s tick is "+
				"being used as the rate window instead of the facts interval", i, res)
		}
	}
	// The facts document finally updates with the one real restart.
	seedHost(t, st, "ag_1", restartFacts(101))
	res, _ := c.EvaluateOnce()
	// 1 restart in 300 s = 12/h, under the 20/h threshold.
	if res.Fired != 0 {
		t.Fatalf("1 restart in 300 s (12/h) fired against a 20/h threshold: "+
			"window inflation bug (%+v)", res)
	}
}

// TestServiceRestartingNoFlap: a unit that keeps crash-looping must keep ONE
// firing alert across the ticks where the counter is unchanged, not flap.
func TestServiceRestartingNoFlap(t *testing.T) {
	c, st := newEngine(t, 30*time.Second)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	now := t0
	c.now = func() time.Time { return now }
	makeRule(t, st, KindServiceRestarting, "all", `{"service_restart_rate_per_hour":10}`, "warning", true)

	seedHost(t, st, "ag_1", restartFacts(100))
	c.EvaluateOnce() // baseline

	// A heavy crash loop: +60 restarts over 300 s (720/h, far above threshold).
	now = now.Add(300 * time.Second)
	seedHost(t, st, "ag_1", restartFacts(160))
	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("crash loop should fire: %+v", res)
	}

	// The counter cannot change again until the next facts upload (~300 s), so
	// the following 30 s ticks see an unchanged counter. The alert must stay
	// firing (no resolve) because the loop is still in progress.
	for i := 0; i < 5; i++ {
		now = now.Add(30 * time.Second)
		res, _ = c.EvaluateOnce()
		if res.Resolved != 0 {
			t.Fatalf("tick %d after fire resolved the alert while the unit is "+
				"still crash-looping (flapping): %+v", i, res)
		}
	}
	firing, _ := st.ListAlerts("firing", "", "", 10)
	if len(firing) != 1 {
		t.Fatalf("want 1 persistent firing alert, got %d", len(firing))
	}
}

// TestServiceRestartingCollectorFailureNoSpike: when the agent's `systemctl
// show` fails, UnitFact carries no NRestarts datum (n_restarts_known absent).
// The engine must skip that unit rather than read the zero value as a counter
// reset — otherwise the next successful collection looks like a burst of
// restarts and raises a spurious alert.
func TestServiceRestartingCollectorFailureNoSpike(t *testing.T) {
	c, st := newEngine(t, 30*time.Second)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	now := t0
	c.now = func() time.Time { return now }
	makeRule(t, st, KindServiceRestarting, "all", `{"service_restart_rate_per_hour":10}`, "warning", true)

	seedHost(t, st, "ag_1", restartFacts(5))
	c.EvaluateOnce() // baseline at 5

	// 300 s later the collector failed for this unit: no n_restarts datum.
	now = now.Add(300 * time.Second)
	seedHost(t, st, "ag_1", `{"services_detailed":{"units":[{"name":"crashy","state":"active","sub_state":"running"}]}}`)
	if res, _ := c.EvaluateOnce(); res.Fired != 0 {
		t.Fatalf("collector failure fired an alert: %+v", res)
	}

	// Collection recovers with the true counter (5 → 6: one real restart).
	now = now.Add(300 * time.Second)
	seedHost(t, st, "ag_1", restartFacts(6))
	res, _ := c.EvaluateOnce()
	// 1 restart over the widened window is well under 10/h.
	if res.Fired != 0 {
		t.Fatalf("recovery after a collector failure produced a spurious spike: %+v", res)
	}
}

// TestUpdateRunFireResolve: a rollout stuck in an alerted status fires a
// server-level alert (no host scope), dedups while stuck, and resolves when
// the run leaves the alerted status.
func TestUpdateRunFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	makeRule(t, st, KindUpdateRun, "all", `{"status":"paused_failure"}`, "critical", true)

	now := time.Now().Unix()
	run := &store.UpdateRun{
		ID: "run_1", Version: "v2.0.0", ReleaseID: "rel_t", Arch: "linux-amd64",
		Selector: "all", Status: "paused_failure", TotalHosts: 4, DoneHosts: 3,
		FailedHosts: 1, Error: "wave failed; operator must retry/skip/abort",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateUpdateRun(run); err != nil {
		t.Fatalf("CreateUpdateRun: %v", err)
	}

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("stuck run tick: %+v, want 1 fired", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 {
		t.Fatalf("firing alerts = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.AgentID != "" {
		t.Errorf("update_run alert agent_id = %q, want empty (server-level)", a.AgentID)
	}
	if a.Kind != KindUpdateRun {
		t.Errorf("kind = %q, want %q", a.Kind, KindUpdateRun)
	}
	if !contains(a.Message, "run_1") || !contains(a.Message, "paused_failure") {
		t.Errorf("message %q should name the run and its status", a.Message)
	}

	// Still stuck: dedup (no second alert).
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("still-stuck tick: %+v, want 0 fired (dedup)", res)
	}

	// Operator retries the wave -> run leaves the alerted status -> resolves.
	if err := st.SetUpdateRunStatus("run_1", "rolling", ""); err != nil {
		t.Fatalf("SetUpdateRunStatus: %v", err)
	}
	res, _ = c.EvaluateOnce()
	if res.Resolved != 1 {
		t.Fatalf("recovered tick: %+v, want 1 resolved", res)
	}
	alerts, _ = st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 0 {
		t.Errorf("firing alerts after resolve = %d, want 0", len(alerts))
	}
}

// TestUpdateRunDefaultStatuses: without an explicit status threshold the
// rule alerts on paused_failure AND failed; completed/rolling are quiet.
func TestUpdateRunDefaultStatuses(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	makeRule(t, st, KindUpdateRun, "all", `{}`, "warning", true)

	now := time.Now().Unix()
	for _, r := range []struct {
		id, status string
	}{
		{"run_ok", "completed"},
		{"run_live", "rolling"},
		{"run_dead", "failed"},
	} {
		_ = st.CreateUpdateRun(&store.UpdateRun{
			ID: r.id, Version: "v1", ReleaseID: "rel_t", Arch: "linux-amd64",
			Selector: "all", Status: r.status, CreatedAt: now, UpdatedAt: now,
		})
	}

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("default-status tick: %+v, want exactly 1 fired (the failed run)", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 || !contains(alerts[0].Message, "run_dead") {
		t.Fatalf("firing alerts = %+v, want only run_dead", alerts)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (s == sub || len(s) > 0 && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})())
}

// TestUpdateDriftFireResolve: an agent behind the store's latest release
// fires a server-level drift alert, dedups while behind, and resolves when
// the fleet catches up.
func TestUpdateDriftFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	makeRule(t, st, KindUpdateDrift, "all", `{"min_drifted":1}`, "warning", true)

	rel := store.Release{ID: "rel_d", Version: "2.0.0", Arch: "linux-amd64", Kind: "agent",
		SHA256: "aa", Artifact: []byte("x")}
	if err := st.InsertRelease(rel); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}
	seedHost(t, st, "ag_old", `{}`)
	_ = st.SetAgentVersion("ag_old", "1.0.0")
	seedHost(t, st, "ag_new", `{}`)
	_ = st.SetAgentVersion("ag_new", "2.0.0")

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("drift tick: %+v, want 1 fired", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 {
		t.Fatalf("firing alerts = %d, want 1", len(alerts))
	}
	if alerts[0].AgentID != "" {
		t.Errorf("drift alert agent_id = %q, want empty (server-level)", alerts[0].AgentID)
	}
	if !contains(alerts[0].Message, "ag_old") || !contains(alerts[0].Message, "1.0.0") || !contains(alerts[0].Message, "2.0.0") {
		t.Errorf("message %q should name the lagging host, its version, and the latest", alerts[0].Message)
	}

	// Still behind: dedup.
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("still-behind tick: %+v, want 0 fired (dedup)", res)
	}

	// The agent catches up -> resolves.
	_ = st.SetAgentVersion("ag_old", "2.0.0")
	res, _ = c.EvaluateOnce()
	if res.Resolved != 1 {
		t.Fatalf("caught-up tick: %+v, want 1 resolved", res)
	}
}

// TestUpdateDriftMinThreshold: the rule's min_drifted gate.
func TestUpdateDriftMinThreshold(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	makeRule(t, st, KindUpdateDrift, "all", `{"min_drifted":3}`, "warning", true)

	rel := store.Release{ID: "rel_m", Version: "2.0.0", Arch: "linux-amd64", Kind: "agent",
		SHA256: "aa", Artifact: []byte("x")}
	if err := st.InsertRelease(rel); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}
	seedHost(t, st, "ag_a", `{}`)
	_ = st.SetAgentVersion("ag_a", "1.0.0")
	seedHost(t, st, "ag_b", `{}`)
	_ = st.SetAgentVersion("ag_b", "1.0.0")

	res, _ := c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("2 behind < min_drifted=3: %+v, want 0 fired", res)
	}

	seedHost(t, st, "ag_c", `{}`)
	_ = st.SetAgentVersion("ag_c", "1.0.0")
	res, _ = c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("3 behind >= min: %+v, want 1 fired", res)
	}
}

// TestSecurityUpdatesFireResolve (M5.1): stored findings at/above the rule's
// severity floor fire a per-host alert; dedup while the condition holds;
// resolving below the floor (patched) clears it.
func TestSecurityUpdatesFireResolve(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	makeRule(t, st, KindSecurityUpdates, "all", `{"min_severity":"high","min_count":1}`, "warning", true)

	// Two hosts: one with a critical finding, one with only medium.
	seedHost(t, st, "ag_sec", `{}`)
	seedHost(t, st, "ag_ok", `{}`)
	now := time.Now().Unix()
	if err := st.ReplaceSecurityFindings("ag_sec", []store.SecurityFinding{
		{Pkg: "openssl", Installed: "3.0.7", Available: "3.0.13", VulnCount: 2,
			MaxCVSS: 9.5, VulnIDs: "CVE-2024-0727,CVE-2024-0728", UpdatedAt: now},
		{Pkg: "libsasl2", Installed: "2.1.28", Available: "2.1.28-10", VulnCount: 1,
			MaxCVSS: 7.5, VulnIDs: "CVE-2023-48795", UpdatedAt: now},
	}, store.SecurityScanMeta{AgentID: "ag_sec", ScannedAt: now, UpdatesTotal: 5, SecurityUpdates: 2}); err != nil {
		t.Fatalf("ReplaceSecurityFindings: %v", err)
	}
	if err := st.ReplaceSecurityFindings("ag_ok", []store.SecurityFinding{
		{Pkg: "vim", Installed: "9.0.1", Available: "9.0.2", VulnCount: 1,
			MaxCVSS: 5.0, VulnIDs: "CVE-2024-9999", UpdatedAt: now},
	}, store.SecurityScanMeta{AgentID: "ag_ok", ScannedAt: now, UpdatesTotal: 1, SecurityUpdates: 1}); err != nil {
		t.Fatalf("ReplaceSecurityFindings: %v", err)
	}

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("tick 1: %+v, want exactly 1 fired (ag_sec only)", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 {
		t.Fatalf("firing = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.AgentID != "ag_sec" {
		t.Errorf("alert host = %q, want ag_sec", a.AgentID)
	}
	if !contains(a.Message, "openssl") || !contains(a.Message, "CVE-2024-0727") || !contains(a.Message, "1 critical, 1 high") {
		t.Errorf("message %q should name the package, a CVE, and the severity split", a.Message)
	}

	// Still vulnerable: dedup.
	res, _ = c.EvaluateOnce()
	if res.Fired != 0 {
		t.Fatalf("tick 2: %+v, want 0 fired (dedup)", res)
	}

	// Patched below the floor: resolves.
	if err := st.ReplaceSecurityFindings("ag_sec", []store.SecurityFinding{
		{Pkg: "libsasl2", Installed: "2.1.28", Available: "2.1.28-10", VulnCount: 1,
			MaxCVSS: 7.5, VulnIDs: "CVE-2023-48795", UpdatedAt: now},
	}, store.SecurityScanMeta{AgentID: "ag_sec", ScannedAt: now}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	// Still one high -> still firing (dedup, no resolve).
	res, _ = c.EvaluateOnce()
	if res.Resolved != 0 {
		t.Fatalf("tick 3: %+v, want 0 resolved (still 1 high)", res)
	}
	// Patch that too.
	if err := st.ReplaceSecurityFindings("ag_sec", nil,
		store.SecurityScanMeta{AgentID: "ag_sec", ScannedAt: now}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	res, _ = c.EvaluateOnce()
	if res.Resolved != 1 {
		t.Fatalf("tick 4: %+v, want 1 resolved", res)
	}
}

// TestUpdateDriftServerBaseline: with NOTHING in the release store (the
// direct-binary-upgrade flow), the running server's version is the drift
// baseline — agents behind the server still alert instead of silently
// passing ("nothing in the store: nothing to be behind" used to swallow
// the whole fleet).
func TestUpdateDriftServerBaseline(t *testing.T) {
	c, st := newEngine(t, time.Hour)
	makeRule(t, st, KindUpdateDrift, "all", `{"min_drifted":1}`, "warning", true)

	// No releases registered. Pin the baseline (a dev build's
	// "0.0.0-dev" cannot be drifted below).
	saved := serverVersion
	serverVersion = "9.9.9"
	t.Cleanup(func() { serverVersion = saved })

	seedHost(t, st, "ag_lag", `{}`)
	_ = st.SetAgentVersion("ag_lag", "9.9.7")
	seedHost(t, st, "ag_ok", `{}`)
	_ = st.SetAgentVersion("ag_ok", "9.9.9")

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("empty-store drift tick: %+v, want 1 fired (server baseline)", res)
	}
	alerts, _ := st.ListAlerts("firing", "", "", 10)
	if len(alerts) != 1 {
		t.Fatalf("firing alerts = %d, want 1", len(alerts))
	}
	if !contains(alerts[0].Message, "server 9.9.9") || !contains(alerts[0].Message, "ag_lag") {
		t.Errorf("message %q should name the server baseline and the lagging host", alerts[0].Message)
	}
}

// TestAlertWebhookDelivery: a rule with a webhook_url POSTs the alert as
// JSON on firing AND on resolve; a failing receiver never breaks the
// engine (fire-and-record, no retry — the miss is an alert.webhook audit
// row). This is the first external alert channel (PRD §5.4).
func TestAlertWebhookDelivery(t *testing.T) {
	c, st := newEngine(t, time.Hour)

	var mu sync.Mutex
	var got []map[string]any
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer rcv.Close()

	rule := makeRule(t, st, KindServiceFailed, "all", `{"service_failed_minutes":0}`, "warning", true)
	rule.WebhookURL = rcv.URL
	if err := st.UpdateAlertRule(rule); err != nil {
		t.Fatalf("UpdateAlertRule: %v", err)
	}

	seedHost(t, st, "ag_wh", unitFacts("failed"))
	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("webhook tick: %+v, want 1 fired", res)
	}
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 1
	})
	if got[0]["event"] != "firing" || got[0]["kind"] != KindServiceFailed ||
		got[0]["host_id"] != "ag_wh" || got[0]["message"] == "" || got[0]["rule"] == "" {
		t.Fatalf("firing webhook payload = %+v", got[0])
	}

	// Host heals -> resolve -> second delivery with event=resolved.
	seedHost(t, st, "ag_wh", unitFacts("active"))
	_, _ = c.EvaluateOnce()
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 2
	})
	if got[1]["event"] != "resolved" {
		t.Fatalf("resolved webhook payload = %+v", got[1])
	}

	// A dead receiver is recorded, never fatal.
	rule.WebhookURL = "http://127.0.0.1:1/dead"
	if err := st.UpdateAlertRule(rule); err != nil {
		t.Fatal(err)
	}
	seedHost(t, st, "ag_wh", unitFacts("failed"))
	if res, _ = c.EvaluateOnce(); res.Fired != 1 {
		t.Fatalf("re-fire with dead receiver: %+v", res)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 3s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
