// Package observe: M6 alert engine (PRD R23/R25, arch §7.5–7.6).
//
// The engine is SERVER-SIDE ONLY (PRD Decision 16): agents upload facts,
// this controller evaluates threshold rules over the stored fact documents,
// transitions alerts firing→resolved with per-condition dedup, and fans out
// `alert.firing` / `alert.resolved` SSE events on the shared broker.
package observe

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// DefaultTick is the evaluation cadence (PARTOUT_ALERT_TICK_S).
const DefaultTick = 30 * time.Second

// Supported rule kinds (M6 + M6.1).
const (
	KindServiceFailed     = "service_failed"
	KindServiceRestarting = "service_restarting" // M6.1 (NRestarts rate)
	KindCertExpiring      = "cert_expiring"
	KindConfigInvalid     = "config_invalid"
	KindConfigDrift       = "config_drift" // M7: cross-host hash divergence
)

// Controller evaluates alert rules on a tick.
type Controller struct {
	st   *store.Store
	sse  *sse.Broker
	log  *log.Logger
	tick time.Duration

	stop chan struct{}
	wg   sync.WaitGroup

	mu          sync.Mutex
	firstFailed map[string]time.Time   // "agentID|unit" -> first time observed failed
	restartSamp map[string]restartSamp // "agentID|unit" -> last (count, time) sample
	now         func() time.Time       // injectable clock (tests)
}

// restartSamp is one sample of a unit's systemd NRestarts counter, used to
// compute the restart rate over the window since the previous sample.
type restartSamp struct {
	count int64
	at    time.Time
}

// minRateWindow bounds how short the sample window may be before a restart
// rate is computed (avoids divide-by-near-zero on back-to-back ticks).
const minRateWindow = 30 * time.Second

// New builds the controller. tick <= 0 → DefaultTick.
func New(st *store.Store, sseB *sse.Broker, lg *log.Logger, tick time.Duration) *Controller {
	if tick <= 0 {
		tick = DefaultTick
	}
	return &Controller{
		st: st, sse: sseB, log: lg, tick: tick,
		stop:        make(chan struct{}),
		firstFailed: make(map[string]time.Time),
		restartSamp: make(map[string]restartSamp),
		now:         time.Now,
	}
}

// Start launches the tick loop (one immediate evaluation, then every tick).
func (c *Controller) Start() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.evaluate()
		t := time.NewTicker(c.tick)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-t.C:
				c.evaluate()
			}
		}
	}()
}

// Stop halts the tick loop.
func (c *Controller) Stop() {
	close(c.stop)
	c.wg.Wait()
}

// EvalResult summarizes one evaluation pass (for tests + logs).
type EvalResult struct {
	Fired    int
	Resolved int
	Rules    int
	Hosts    int
}

// evaluate runs one pass over all enabled rules × all host facts.
func (c *Controller) evaluate() {
	res, err := c.EvaluateOnce()
	if err != nil && c.log != nil {
		c.log.Printf("observe/alerts: evaluation: %v", err)
	}
	if res.Fired+res.Resolved > 0 && c.log != nil {
		c.log.Printf("observe/alerts: tick: %d rules, %d hosts → %d fired, %d resolved",
			res.Rules, res.Hosts, res.Fired, res.Resolved)
	}
}

// EvaluateOnce runs one synchronous evaluation pass (exported for tests).
func (c *Controller) EvaluateOnce() (EvalResult, error) {
	var res EvalResult
	rules, err := c.st.ListAlertRules()
	if err != nil {
		return res, err
	}
	var enabled []*store.AlertRule
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}

	facts, err := c.st.LatestHostFactsJSONAll()
	if err != nil {
		return res, err
	}
	docs := make(map[string]*Document, len(facts))
	for agID, blob := range facts {
		d, err := ParseDocument(blob)
		if err != nil || blob == "" {
			continue
		}
		docs[agID] = d
	}
	res.Rules = len(enabled)
	res.Hosts = len(docs)

	resolver := store.NewResolver(c.st)
	now := c.now()

	// Restart rates are a property of the host facts, not of any rule: sample
	// once per tick (advancing each counter once) so multiple service_restarting
	// rules all see the same window instead of the first rule consuming it.
	restartRates := c.sampleRestartRates(docs, now)

	for _, r := range enabled {
		hosts, err := c.resolveHosts(resolver, r.Selector)
		if err != nil {
			if c.log != nil {
				c.log.Printf("observe/alerts: rule %s selector %q: %v", r.ID, r.Selector, err)
			}
			continue
		}
		switch r.Kind {
		case KindServiceFailed:
			res.Fired += c.evalServiceFailed(r, hosts, docs, now)
			res.Resolved += c.resolveServiceFailed(r, hosts, docs)
		case KindServiceRestarting:
			res.Fired += c.fireRestarting(r, hosts, restartRates)
			res.Resolved += c.resolveByDedupDiff(r, hosts, c.hotRestartKeys(r, hosts, restartRates))
		case KindCertExpiring:
			res.Fired += c.evalCertExpiring(r, hosts, docs)
			res.Resolved += c.resolveByDedupDiff(r, hosts, c.certConditionKeys(r, docs))
		case KindConfigInvalid:
			res.Fired += c.evalConfigInvalid(r, hosts, docs)
			res.Resolved += c.resolveByDedupDiff(r, hosts, c.configConditionKeys(r, docs))
		case KindConfigDrift:
			hits := c.driftHits(r, hosts, docs)
			res.Fired += c.fireDrift(r, hits)
			res.Resolved += c.resolveByDedupDiff(r, hosts, c.driftConditionKeys(r, hits))
		default:
			if c.log != nil {
				c.log.Printf("observe/alerts: rule %s: unsupported kind %q (skipped)", r.ID, r.Kind)
			}
		}
	}
	return res, nil
}

// resolveHosts resolves a selector expression to agent IDs.
func (c *Controller) resolveHosts(resolver *store.Resolver, expr string) ([]string, error) {
	infos, err := resolver.ResolveSelector(expr)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(infos))
	for _, h := range infos {
		out = append(out, h.ID)
	}
	return out, nil
}

// --- service_failed ---

func (c *Controller) serviceFailedMinutes(r *store.AlertRule) int {
	return int(thresholdInt(r, "service_failed_minutes", 5))
}

func (c *Controller) evalServiceFailed(r *store.AlertRule, hosts []string, docs map[string]*Document, now time.Time) int {
	mins := c.serviceFailedMinutes(r)
	fired := 0
	for _, agID := range hosts {
		doc := docs[agID]
		if doc == nil {
			continue
		}
		sf := doc.Services()
		if sf == nil {
			continue
		}
		for _, u := range sf.Units {
			key := agID + "|" + u.Name
			dedup := r.ID + "|" + agID + "|" + u.Name
			if u.State != "failed" {
				c.clearFirstFailed(key)
				continue
			}
			first := c.markFirstFailed(key, now)
			if now.Sub(first) < time.Duration(mins)*time.Minute {
				continue // still within the threshold window
			}
			if c.fire(r, agID, dedup,
				"unit "+u.Name+" in failed state on host (state="+u.State+", sub="+u.SubState+")") {
				fired++
			}
		}
	}
	return fired
}

func (c *Controller) resolveServiceFailed(r *store.AlertRule, hosts []string, docs map[string]*Document) int {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	firing, err := c.st.FiringAlertKeys(r.ID)
	if err != nil {
		return 0
	}
	var stale []string
	for _, a := range firing {
		if !hostSet[a.AgentID] {
			continue // rule no longer selects this host → leave the alert
		}
		doc := docs[a.AgentID]
		if doc == nil {
			continue // no facts → fail soft, keep firing
		}
		sf := doc.Services()
		if sf == nil {
			continue
		}
		unit := unitFromDedup(a.DedupKey)
		stillFailed := false
		for _, u := range sf.Units {
			if u.Name == unit && u.State == "failed" {
				stillFailed = true
			}
		}
		if !stillFailed {
			stale = append(stale, a.DedupKey)
		}
	}
	return c.resolve(stale)
}

// --- cert_expiring ---

func (c *Controller) certDays(r *store.AlertRule) int64 {
	return thresholdInt(r, "cert_days_remaining", 30)
}

// certConditionKeys returns the dedup keys for currently-expiring certs on
// the rule's hosts (dedup subject = cert path, arch §7.5).
func (c *Controller) certConditionKeys(r *store.AlertRule, docs map[string]*Document) map[string]struct{} {
	limit := c.certDays(r)
	out := make(map[string]struct{})
	for agID, doc := range docs {
		cf := doc.Certificates()
		if cf == nil {
			continue
		}
		for _, cert := range cf.Items {
			if cert.NotAfter == 0 || cert.DaysRemaining > limit {
				continue
			}
			out[r.ID+"|"+agID+"|"+cert.Path] = struct{}{}
		}
	}
	return out
}

func (c *Controller) evalCertExpiring(r *store.AlertRule, hosts []string, docs map[string]*Document) int {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	limit := c.certDays(r)
	fired := 0
	for agID, doc := range docs {
		if !hostSet[agID] {
			continue
		}
		cf := doc.Certificates()
		if cf == nil {
			continue
		}
		for _, cert := range cf.Items {
			if cert.NotAfter == 0 || cert.DaysRemaining > limit {
				continue
			}
			dedup := r.ID + "|" + agID + "|" + cert.Path
			if c.fire(r, agID, dedup,
				"certificate "+cert.Path+" expires in "+strconv.FormatInt(cert.DaysRemaining, 10)+" days") {
				fired++
			}
		}
	}
	return fired
}

// --- config_invalid ---

func (c *Controller) configConditionKeys(r *store.AlertRule, docs map[string]*Document) map[string]struct{} {
	out := make(map[string]struct{})
	for agID, doc := range docs {
		cfg := doc.Configs()
		if cfg == nil {
			continue
		}
		if cfg.HAProxy != nil && cfg.HAProxy.Present && !cfg.HAProxy.ConfigValid {
			out[r.ID+"|"+agID+"|haproxy"] = struct{}{}
		}
		if cfg.Nginx != nil && cfg.Nginx.Present && !cfg.Nginx.ConfigValid {
			out[r.ID+"|"+agID+"|nginx"] = struct{}{}
		}
	}
	return out
}

func (c *Controller) evalConfigInvalid(r *store.AlertRule, hosts []string, docs map[string]*Document) int {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	fired := 0
	for agID, doc := range docs {
		if !hostSet[agID] {
			continue
		}
		cfg := doc.Configs()
		if cfg == nil {
			continue
		}
		if cfg.HAProxy != nil && cfg.HAProxy.Present && !cfg.HAProxy.ConfigValid {
			if c.fire(r, agID, r.ID+"|"+agID+"|haproxy",
				"haproxy config invalid ("+cfg.HAProxy.ConfigFile+")") {
				fired++
			}
		}
		if cfg.Nginx != nil && cfg.Nginx.Present && !cfg.Nginx.ConfigValid {
			if c.fire(r, agID, r.ID+"|"+agID+"|nginx",
				"nginx config invalid ("+cfg.Nginx.ConfigFile+")") {
				fired++
			}
		}
	}
	return fired
}

// --- service_restarting (M6.1: restart rate over the NRestarts counter) ---

func (c *Controller) restartRateThresh(r *store.AlertRule) float64 {
	return float64(thresholdInt(r, "service_restart_rate_per_hour", 10))
}

// sampleRestartRates advances the per-unit restart-counter samples for every
// host with service facts and returns the restart rate (restarts/hour) for
// every unit with a usable window. First sighting of a unit only establishes
// a baseline (no rate); the sample advances once the window since the
// previous sample reaches minRateWindow. A counter reset (NRestarts dropped
// — the unit was stopped/restarted) folds into the new count. The engine's
// in-memory baseline is lost on a server restart; the first post-restart
// tick re-baselines silently.
//
// Returns map "agentID|unit" -> rate.
func (c *Controller) sampleRestartRates(docs map[string]*Document, now time.Time) map[string]float64 {
	out := make(map[string]float64)
	c.mu.Lock()
	defer c.mu.Unlock()
	for agID, doc := range docs {
		sf := doc.Services()
		if sf == nil {
			continue
		}
		for _, u := range sf.Units {
			key := agID + "|" + u.Name
			prev, ok := c.restartSamp[key]
			if !ok {
				c.restartSamp[key] = restartSamp{count: u.NRestarts, at: now}
				continue
			}
			elapsed := now.Sub(prev.at)
			if elapsed < minRateWindow {
				continue // keep the baseline; the window widens over ticks
			}
			delta := u.NRestarts - prev.count
			if delta < 0 {
				delta = u.NRestarts // counter reset (unit stop/restart)
			}
			out[key] = float64(delta) / elapsed.Hours()
			c.restartSamp[key] = restartSamp{count: u.NRestarts, at: now}
		}
	}
	return out
}

// fireRestarting fires one alert per unit whose restart rate meets the
// rule's threshold (dedup subject = unit, like service_failed). Only units
// on the rule's selector hosts fire.
func (c *Controller) fireRestarting(r *store.AlertRule, hosts []string, rates map[string]float64) int {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	thresh := c.restartRateThresh(r)
	fired := 0
	for key, rate := range rates {
		if rate < thresh {
			continue
		}
		parts := strings.SplitN(key, "|", 2)
		agID, unit := parts[0], parts[1]
		if !hostSet[agID] {
			continue
		}
		if c.fire(r, agID, r.ID+"|"+key,
			fmt.Sprintf("unit %s restarting on host (%.0f restarts/hour, threshold %.0f/hour)", unit, rate, thresh)) {
			fired++
		}
	}
	return fired
}

// hotRestartKeys returns the dedup keys of the rule's hosts' units currently
// over threshold — the condition set for resolveByDedupDiff (a sub-threshold
// tick resolves).
func (c *Controller) hotRestartKeys(r *store.AlertRule, hosts []string, rates map[string]float64) map[string]struct{} {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	thresh := c.restartRateThresh(r)
	out := make(map[string]struct{})
	for key, rate := range rates {
		if rate < thresh {
			continue
		}
		if !hostSet[strings.SplitN(key, "|", 2)[0]] {
			continue
		}
		out[r.ID+"|"+key] = struct{}{}
	}
	return out
}

// --- config_drift (M7, R22: cross-host config hash divergence) ---

// driftHit is one host whose config hash diverges from the fleet majority.
type driftHit struct {
	agID, kind, sha, majority string
}

// driftHits reports, per kind (haproxy/nginx), the hosts on the rule's
// selector whose config_sha256 differs from the majority hash. The majority
// is the most frequent non-empty hash (ties break lexicographically for
// determinism). Divergence is only flagged when the number of distinct
// hashes exceeds 1 + config_drift_tolerance (default 0 = any divergence).
func (c *Controller) driftHits(r *store.AlertRule, hosts []string, docs map[string]*Document) []driftHit {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	tol := int(thresholdInt(r, "config_drift_tolerance", 0))
	// perKind[kind][host] = sha; count[kind][sha] = hosts with that sha
	perKind := make(map[string]map[string]string)
	count := make(map[string]map[string]int)
	for agID, doc := range docs {
		if !hostSet[agID] {
			continue
		}
		cf := doc.Configs()
		if cf == nil {
			continue
		}
		if cf.HAProxy != nil && cf.HAProxy.Present && cf.HAProxy.ConfigSHA256 != "" {
			addDriftHash(perKind, count, "haproxy", agID, cf.HAProxy.ConfigSHA256)
		}
		if cf.Nginx != nil && cf.Nginx.Present && cf.Nginx.ConfigSHA256 != "" {
			addDriftHash(perKind, count, "nginx", agID, cf.Nginx.ConfigSHA256)
		}
	}
	var hits []driftHit
	for kind, perHost := range perKind {
		if len(count[kind]) <= 1+tol {
			continue // no divergence beyond tolerance
		}
		majority := majorityHash(count[kind])
		for agID, sha := range perHost {
			if sha != majority {
				hits = append(hits, driftHit{agID: agID, kind: kind, sha: sha, majority: majority})
			}
		}
	}
	return hits
}

func addDriftHash(perKind map[string]map[string]string, count map[string]map[string]int, kind, agID, sha string) {
	if perKind[kind] == nil {
		perKind[kind] = make(map[string]string)
		count[kind] = make(map[string]int)
	}
	perKind[kind][agID] = sha
	count[kind][sha]++
}

// majorityHash: most frequent; ties break on the lexicographically smallest
// hash (deterministic across ticks).
func majorityHash(byHash map[string]int) string {
	best := ""
	for h, n := range byHash {
		if best == "" || n > byHash[best] || (n == byHash[best] && h < best) {
			best = h
		}
	}
	return best
}

func (c *Controller) fireDrift(r *store.AlertRule, hits []driftHit) int {
	fired := 0
	for _, h := range hits {
		if c.fire(r, h.agID, r.ID+"|"+h.agID+"|"+h.kind+"|"+h.sha,
			fmt.Sprintf("%s config diverges from fleet majority on %s (sha256 %s… vs %s…)",
				h.kind, h.agID, shortHash(h.sha), shortHash(h.majority))) {
			fired++
		}
	}
	return fired
}

func (c *Controller) driftConditionKeys(r *store.AlertRule, hits []driftHit) map[string]struct{} {
	out := make(map[string]struct{}, len(hits))
	for _, h := range hits {
		out[r.ID+"|"+h.agID+"|"+h.kind+"|"+h.sha] = struct{}{}
	}
	return out
}

func shortHash(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// --- shared fire/resolve ---

// fire inserts/re-arms a firing alert, emits SSE + audit. Returns true when
// the alert transitioned to firing this pass.
func (c *Controller) fire(r *store.AlertRule, agentID, dedup, message string) bool {
	a := &store.Alert{
		ID:     id.New("al"),
		RuleID: r.ID, AgentID: agentID, Kind: r.Kind, Severity: r.Severity,
		Message: message, State: "firing", DedupKey: dedup,
		StartedAt: time.Now().Unix(),
	}
	got, created, err := c.st.UpsertAlertFiring(a)
	if err != nil {
		if c.log != nil {
			c.log.Printf("observe/alerts: fire %s: %v", dedup, err)
		}
		return false
	}
	if !created {
		return false // already firing (dedup)
	}
	c.emit(got, "alert.firing")
	c.audit(got)
	return true
}

// resolve marks the given dedup keys resolved (if firing), emits SSE + audit.
func (c *Controller) resolve(dedupKeys []string) int {
	n, err := c.st.ResolveAlerts(dedupKeys)
	if err != nil {
		if c.log != nil {
			c.log.Printf("observe/alerts: resolve: %v", err)
		}
		return 0
	}
	for _, k := range dedupKeys {
		if a, err := c.st.GetAlertByDedup(k); err == nil && a != nil {
			c.emit(a, "alert.resolved")
			c.audit(a)
		}
	}
	return n
}

// resolveByDedupDiff resolves firing alerts whose dedup key is no longer in
// the current condition set (certs/configs: no delay window involved).
func (c *Controller) resolveByDedupDiff(r *store.AlertRule, hosts []string, current map[string]struct{}) int {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	firing, err := c.st.FiringAlertKeys(r.ID)
	if err != nil {
		return 0
	}
	var stale []string
	for _, a := range firing {
		if !hostSet[a.AgentID] {
			continue
		}
		if _, ok := current[a.DedupKey]; !ok {
			stale = append(stale, a.DedupKey)
		}
	}
	return c.resolve(stale)
}

func (c *Controller) emit(a *store.Alert, event string) {
	if c.sse == nil {
		return
	}
	p := map[string]any{
		"alert_id": a.ID, "rule_id": a.RuleID, "kind": a.Kind,
		"host_id": a.AgentID, "severity": a.Severity,
	}
	if event == "alert.firing" {
		p["message"] = a.Message
	}
	c.sse.Emit(event, p)
}

func (c *Controller) audit(a *store.Alert) {
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: "alert", AgentID: a.AgentID,
		Payload: `{"alert_id":"` + a.ID + `","rule_id":"` + a.RuleID + `","state":"` + a.State + `","kind":"` + a.Kind + `"}`,
	})
}

// --- first-failed tracking (service_failed delay window) ---

func (c *Controller) markFirstFailed(key string, now time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.firstFailed[key]; ok {
		return t
	}
	c.firstFailed[key] = now
	return now
}

func (c *Controller) clearFirstFailed(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.firstFailed, key)
}

// --- helpers ---

// thresholdInt reads a numeric threshold from the rule's JSON; def if absent.
func thresholdInt(r *store.AlertRule, key string, def int64) int64 {
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Thresholds), &m); err != nil || m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case int:
			return int64(n)
		}
	}
	return def
}

func unitFromDedup(dedup string) string {
	// "ruleID|agentID|unit" → last segment
	i := lastIndexByte(dedup, '|')
	if i < 0 {
		return ""
	}
	return dedup[i+1:]
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
