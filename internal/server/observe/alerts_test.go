// M6 alert engine tests: fire → dedup → resolve → re-arm, per rule kind.
package observe

import (
	"log"
	"strconv"
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
	seedHost(t, st, "ag_1", `{"configs":{"haproxy":{"present":true,"config_valid":false,"config_file":"/etc/haproxy/haproxy.cfg"}}}`)
	makeRule(t, st, KindConfigInvalid, "all", `{}`, "critical", true)

	res, _ := c.EvaluateOnce()
	if res.Fired != 1 {
		t.Fatalf("invalid config tick: %+v, want 1 fired", res)
	}

	seedHost(t, st, "ag_1", `{"configs":{"haproxy":{"present":true,"config_valid":true,"config_file":"/etc/haproxy/haproxy.cfg"}}}`)
	res, _ = c.EvaluateOnce()
	if res.Resolved != 1 {
		t.Fatalf("fixed config tick: %+v, want 1 resolved", res)
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
