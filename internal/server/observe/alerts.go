// Package observe: M6 alert engine (PRD R23/R25, arch §7.5–7.6).
//
// The engine is SERVER-SIDE ONLY (PRD Decision 16): agents upload facts,
// this controller evaluates threshold rules over the stored fact documents,
// transitions alerts firing→resolved with per-condition dedup, and fans out
// `alert.firing` / `alert.resolved` SSE events on the shared broker.
package observe

import (
	"encoding/json"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// DefaultTick is the evaluation cadence (PARTOUT_ALERT_TICK_S).
const DefaultTick = 30 * time.Second

// Supported rule kinds (M6). service_restarting is M6.1 (needs a restart
// counter fact the agent doesn't collect yet).
const (
	KindServiceFailed = "service_failed"
	KindCertExpiring  = "cert_expiring"
	KindConfigInvalid = "config_invalid"
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
	firstFailed map[string]time.Time // "agentID|unit" -> first time observed failed
}

// New builds the controller. tick <= 0 → DefaultTick.
func New(st *store.Store, sseB *sse.Broker, lg *log.Logger, tick time.Duration) *Controller {
	if tick <= 0 {
		tick = DefaultTick
	}
	return &Controller{
		st: st, sse: sseB, log: lg, tick: tick,
		stop:        make(chan struct{}),
		firstFailed: make(map[string]time.Time),
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
	now := time.Now()

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
		case KindCertExpiring:
			res.Fired += c.evalCertExpiring(r, hosts, docs)
			res.Resolved += c.resolveByDedupDiff(r, hosts, c.certConditionKeys(r, docs))
		case KindConfigInvalid:
			res.Fired += c.evalConfigInvalid(r, hosts, docs)
			res.Resolved += c.resolveByDedupDiff(r, hosts, c.configConditionKeys(r, docs))
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
