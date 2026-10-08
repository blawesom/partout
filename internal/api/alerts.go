// REST handlers for the M6 alert engine (PRD R23/R25).
//
// Routes (auth: reads = viewer+, rule writes = operator+):
//
//	GET    /api/v1/alerts?state=&severity=&agent_id=&limit=
//	GET    /api/v1/alerts/{id}
//	GET    /api/v1/alerts/rules
//	POST   /api/v1/alerts/rules
//	PUT    /api/v1/alerts/rules/{id}
//	DELETE /api/v1/alerts/rules/{id}
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/server/observe"
	"github.com/blawesom/partout/internal/store"
)

// RegisterAlerts wires the alert REST routes.
func (h *Handler) RegisterAlerts(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/alerts", h.requireRole(roleViewer)(http.HandlerFunc(h.alertsList)))
	mux.Handle("GET /api/v1/alerts/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.alertGet)))
	mux.Handle("GET /api/v1/alerts/rules", h.requireRole(roleViewer)(http.HandlerFunc(h.rulesList)))
	mux.Handle("GET /api/v1/alerts/rules/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.ruleGet)))
	mux.Handle("POST /api/v1/alerts/rules", h.requireRole(roleOperator)(http.HandlerFunc(h.ruleCreate)))
	mux.Handle("PUT /api/v1/alerts/rules/{id}", h.requireRole(roleOperator)(http.HandlerFunc(h.ruleUpdate)))
	mux.Handle("DELETE /api/v1/alerts/rules/{id}", h.requireRole(roleOperator)(http.HandlerFunc(h.ruleDelete)))
}

var validRuleKinds = map[string]bool{
	observe.KindServiceFailed:     true,
	observe.KindServiceRestarting: true,
	observe.KindCertExpiring:      true,
	observe.KindConfigInvalid:     true,
	observe.KindConfigDrift:       true,
	observe.KindUpdateRun:         true,
	observe.KindUpdateDrift:       true,
	observe.KindSecurityUpdates:   true,
	observe.KindElevationDrift:    true,
}

var validSeverities = map[string]bool{"info": true, "warning": true, "critical": true}

func alertJSON(a *store.Alert) map[string]any {
	out := map[string]any{
		"id": a.ID, "rule_id": a.RuleID, "kind": a.Kind, "severity": a.Severity,
		"message": a.Message, "state": a.State,
		"started_at": a.StartedAt,
	}
	if a.AgentID != "" {
		out["agent_id"] = a.AgentID
	}
	if a.ResolvedAt != nil {
		out["resolved_at"] = *a.ResolvedAt
	}
	return out
}

func ruleJSON(r *store.AlertRule) map[string]any {
	var thresholds any
	_ = json.Unmarshal([]byte(r.Thresholds), &thresholds)
	return map[string]any{
		"id": r.ID, "name": r.Name, "kind": r.Kind, "selector": r.Selector,
		"thresholds": thresholds, "severity": r.Severity, "enabled": r.Enabled,
		"webhook_url": r.WebhookURL,
		"created_at":  r.CreatedAt, "updated_at": r.UpdatedAt,
	}
}

func (h *Handler) alertsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	alerts, err := h.st.ListAlerts(
		q.Get("state"), q.Get("severity"), q.Get("agent_id"), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list alerts", nil)
		return
	}
	items := make([]any, 0, len(alerts))
	for _, a := range alerts {
		items = append(items, alertJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": items, "count": len(items)})
}

func (h *Handler) alertGet(w http.ResponseWriter, r *http.Request) {
	a, err := h.st.GetAlert(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get alert", nil)
		return
	}
	if a == nil {
		writeError(w, http.StatusNotFound, "not_found", "alert not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, alertJSON(a))
}

func (h *Handler) ruleGet(w http.ResponseWriter, r *http.Request) {
	ru, err := h.st.GetAlertRule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get rule", nil)
		return
	}
	if ru == nil {
		writeError(w, http.StatusNotFound, "not_found", "rule not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, ruleJSON(ru))
}

func (h *Handler) rulesList(w http.ResponseWriter, r *http.Request) {
	rules, err := h.st.ListAlertRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list rules", nil)
		return
	}
	items := make([]any, 0, len(rules))
	for _, ru := range rules {
		items = append(items, ruleJSON(ru))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": items, "count": len(items)})
}

// existingThresholds decodes a stored thresholds JSON blob so a partial rule
// update can preserve it (invalid/empty blobs degrade to an empty map so the
// engine applies its documented defaults).
func existingThresholds(raw string) map[string]any {
	m := map[string]any{}
	if raw == "" {
		return m
	}
	_ = json.Unmarshal([]byte(raw), &m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

type ruleBody struct {
	Name       string  `json:"name"`
	Kind       string  `json:"kind"`
	Selector   string  `json:"selector"`
	Thresholds any     `json:"thresholds"`
	Severity   string  `json:"severity"`
	Enabled    *bool   `json:"enabled"`
	WebhookURL *string `json:"webhook_url"` // optional external channel (POST on firing + resolved)
}

func (b *ruleBody) validate() error {
	if b.Name == "" {
		return errors.New("name is required")
	}
	if !validRuleKinds[b.Kind] {
		return errors.New("kind must be one of: service_failed, service_restarting, cert_expiring, config_invalid, config_drift, update_run, update_drift, security_updates, elevation_drift")
	}
	if b.Selector == "" {
		b.Selector = "all"
	}
	if b.Severity == "" {
		b.Severity = "warning"
	}
	if !validSeverities[b.Severity] {
		return errors.New("severity must be one of: info, warning, critical")
	}
	if b.WebhookURL != nil && *b.WebhookURL != "" {
		u, err := url.Parse(*b.WebhookURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("webhook_url must be an http(s) URL")
		}
	}
	return validateThresholds(b.Kind, b.Thresholds)
}

// thresholdKeys maps each rule kind to the threshold keys it honours and
// whether a value of 0 is meaningful. Values must be non-negative integers;
// a negative threshold silently inverts a rule's condition (e.g. a negative
// restart rate fires for every unit), so it is rejected at the API boundary
// where the CLI/MCP/UI all funnel through.
var thresholdIntKeys = map[string][]string{
	observe.KindServiceFailed:     {"service_failed_minutes"},
	observe.KindServiceRestarting: {"service_restart_rate_per_hour"},
	observe.KindCertExpiring:      {"cert_days_remaining"},
	observe.KindConfigDrift:       {"config_drift_tolerance"},
	observe.KindUpdateDrift:       {"min_drifted"},
}

func validateThresholds(kind string, t any) error {
	keys, ok := thresholdIntKeys[kind]
	if !ok || t == nil {
		return nil
	}
	m, ok := t.(map[string]any)
	if !ok {
		return errors.New("thresholds must be a JSON object")
	}
	for _, k := range keys {
		v, present := m[k]
		if !present {
			continue
		}
		f, ok := toFloat(v)
		if !ok {
			return fmt.Errorf("threshold %q must be a number", k)
		}
		if f < 0 {
			return fmt.Errorf("threshold %q must be >= 0", k)
		}
		if f != math.Trunc(f) {
			return fmt.Errorf("threshold %q must be a whole number", k)
		}
	}
	return nil
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func (b *ruleBody) toRule(actor string) *store.AlertRule {
	thresholds, _ := json.Marshal(b.Thresholds)
	if b.Thresholds == nil {
		thresholds = []byte("{}")
	}
	enabled := true
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	return &store.AlertRule{
		Name: b.Name, Kind: b.Kind, Selector: b.Selector,
		Thresholds: string(thresholds), Severity: b.Severity,
		Enabled: enabled, CreatedBy: actor,
		WebhookURL: derefStr(b.WebhookURL),
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (h *Handler) ruleCreate(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	if err := b.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	principal, _ := h.actorFor(r)
	ru := b.toRule(principal)
	ru.ID = id.New("rule")
	now := time.Now().Unix()
	ru.CreatedAt = now
	ru.UpdatedAt = now
	if err := h.st.CreateAlertRule(ru); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create rule", nil)
		return
	}
	writeJSON(w, http.StatusCreated, ruleJSON(ru))
}

func (h *Handler) ruleUpdate(w http.ResponseWriter, r *http.Request) {
	existing, err := h.st.GetAlertRule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load rule", nil)
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "not_found", "rule not found", nil)
		return
	}
	var b ruleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	if b.Kind == "" {
		b.Kind = existing.Kind
	}
	if b.Selector == "" {
		b.Selector = existing.Selector
	}
	if b.Severity == "" {
		b.Severity = existing.Severity
	}
	if b.Name == "" {
		b.Name = existing.Name
	}
	// Thresholds and Enabled are presence-sensitive: a partial update (e.g.
	// {"name":"x"}) must not silently reset thresholds to defaults or flip a
	// disabled rule back on. The UI always sends full bodies, but the public
	// API/CLI/MCP callers may not.
	if b.Thresholds == nil {
		b.Thresholds = existingThresholds(existing.Thresholds)
	}
	if b.Enabled == nil {
		enabled := existing.Enabled
		b.Enabled = &enabled
	}
	if b.WebhookURL == nil {
		b.WebhookURL = &existing.WebhookURL
	}
	if err := b.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	ru := b.toRule(existing.CreatedBy)
	ru.ID = existing.ID
	ru.CreatedAt = existing.CreatedAt
	ru.UpdatedAt = time.Now().Unix()
	if err := h.st.UpdateAlertRule(ru); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "not_found", "rule not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to update rule", nil)
		return
	}
	writeJSON(w, http.StatusOK, ruleJSON(ru))
}

func (h *Handler) ruleDelete(w http.ResponseWriter, r *http.Request) {
	if err := h.st.DeleteAlertRule(r.PathValue("id")); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "not_found", "rule not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to delete rule", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
