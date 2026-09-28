// Alert engine store (M6, PRD R23/R25, arch §7).
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AlertRule is one threshold rule over the observe domains.
type AlertRule struct {
	ID         string
	Name       string
	Kind       string // service_failed | service_restarting | cert_expiring | config_invalid | config_drift
	Selector   string
	Thresholds string // JSON
	Severity   string
	Enabled    bool
	CreatedBy  string
	CreatedAt  int64
	UpdatedAt  int64
}

// Alert is one alert row (firing or resolved).
type Alert struct {
	ID         string
	RuleID     string
	AgentID    string
	Kind       string
	Severity   string
	Message    string
	State      string // firing | resolved
	DedupKey   string
	StartedAt  int64
	ResolvedAt *int64
}

// --- rules ---

func (s *Store) CreateAlertRule(r *AlertRule) error {
	_, err := s.db.Exec(
		`INSERT INTO alert_rules (id, name, kind, selector, thresholds, severity, enabled, created_by, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Name, r.Kind, r.Selector, r.Thresholds, r.Severity,
		boolInt(r.Enabled), r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: create alert rule: %w", err)
	}
	return nil
}

func (s *Store) GetAlertRule(id string) (*AlertRule, error) {
	row := s.db.QueryRow(
		`SELECT id, name, kind, selector, thresholds, severity, enabled, created_by, created_at, updated_at
		 FROM alert_rules WHERE id=?`, id)
	return scanAlertRule(row)
}

func (s *Store) ListAlertRules() ([]*AlertRule, error) {
	rows, err := s.db.Query(
		`SELECT id, name, kind, selector, thresholds, severity, enabled, created_by, created_at, updated_at
		 FROM alert_rules ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list alert rules: %w", err)
	}
	defer rows.Close()
	var out []*AlertRule
	for rows.Next() {
		r, err := scanAlertRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAlertRule(r *AlertRule) error {
	res, err := s.db.Exec(
		`UPDATE alert_rules SET name=?, kind=?, selector=?, thresholds=?, severity=?, enabled=?, updated_at=?
		 WHERE id=?`,
		r.Name, r.Kind, r.Selector, r.Thresholds, r.Severity,
		boolInt(r.Enabled), r.UpdatedAt, r.ID)
	if err != nil {
		return fmt.Errorf("store: update alert rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("store: alert rule not found")
	}
	return nil
}

func (s *Store) DeleteAlertRule(id string) error {
	res, err := s.db.Exec(`DELETE FROM alert_rules WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: delete alert rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("store: alert rule not found")
	}
	return nil
}

func scanAlertRule(row scanRow) (*AlertRule, error) {
	var r AlertRule
	var enabled int
	err := row.Scan(&r.ID, &r.Name, &r.Kind, &r.Selector, &r.Thresholds,
		&r.Severity, &enabled, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: scan alert rule: %w", err)
	}
	r.Enabled = enabled != 0
	return &r, nil
}

// --- alerts ---

// UpsertAlertFiring inserts a firing alert; if a row with the same dedup key
// exists (e.g. previously resolved), it re-arms it: state=firing, fresh
// started_at, resolved_at cleared. Returns (alert, created) where created is
// false when the alert was already firing (dedup no-op).
func (s *Store) UpsertAlertFiring(a *Alert) (*Alert, bool, error) {
	existing, err := s.GetAlertByDedup(a.DedupKey)
	if err != nil {
		return nil, false, err
	}
	if existing != nil && existing.State == "firing" {
		return existing, false, nil // already firing: dedup no-op
	}
	_, err = s.db.Exec(
		`INSERT INTO alerts (id, rule_id, agent_id, kind, severity, message, state, dedup_key, started_at, resolved_at)
		 VALUES (?,?,?,?,?,?, 'firing',?,?,NULL)
		 ON CONFLICT(dedup_key) DO UPDATE SET
			state='firing', started_at=excluded.started_at, resolved_at=NULL,
			message=excluded.message, severity=excluded.severity`,
		a.ID, a.RuleID, nullStr(a.AgentID), a.Kind, a.Severity,
		a.Message, a.DedupKey, a.StartedAt)
	if err != nil {
		return nil, false, fmt.Errorf("store: upsert alert: %w", err)
	}
	got, err := s.GetAlertByDedup(a.DedupKey)
	if err != nil {
		return nil, false, err
	}
	return got, true, nil
}

// GetAlertByDedup returns the alert row for a dedup key (nil if absent).
func (s *Store) GetAlertByDedup(dedupKey string) (*Alert, error) {
	row := s.db.QueryRow(
		`SELECT id, rule_id, agent_id, kind, severity, message, state, dedup_key, started_at, resolved_at
		 FROM alerts WHERE dedup_key=?`, dedupKey)
	return scanAlert(row)
}

// GetAlert returns one alert by id.
func (s *Store) GetAlert(id string) (*Alert, error) {
	row := s.db.QueryRow(
		`SELECT id, rule_id, agent_id, kind, severity, message, state, dedup_key, started_at, resolved_at
		 FROM alerts WHERE id=?`, id)
	return scanAlert(row)
}

// ResolveAlerts marks firing alerts (by dedup key) resolved. Returns the
// number resolved.
func (s *Store) ResolveAlerts(dedupKeys []string) (int, error) {
	if len(dedupKeys) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(dedupKeys)+1)
	args = append(args, time.Now().Unix()) // resolved_at
	for _, k := range dedupKeys {
		args = append(args, k)
	}
	res, err := s.db.Exec(
		`UPDATE alerts SET state='resolved', resolved_at=?
		 WHERE state='firing' AND dedup_key IN (`+strings.Repeat("?,", len(dedupKeys)-1)+`?)`, args...)
	if err != nil {
		return 0, fmt.Errorf("store: resolve alerts: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// FiringAlertKeys returns the dedup keys of currently firing alerts for one
// rule (so the engine can diff against the current condition set).
func (s *Store) FiringAlertKeys(ruleID string) ([]*Alert, error) {
	rows, err := s.db.Query(
		`SELECT id, rule_id, agent_id, kind, severity, message, state, dedup_key, started_at, resolved_at
		 FROM alerts WHERE rule_id=? AND state='firing'`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("store: firing alerts: %w", err)
	}
	defer rows.Close()
	var out []*Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAlerts returns alerts, newest first. state: "" | firing | resolved.
func (s *Store) ListAlerts(state, severity, agentID string, limit int) ([]*Alert, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	q := `SELECT id, rule_id, agent_id, kind, severity, message, state, dedup_key, started_at, resolved_at
		  FROM alerts WHERE 1=1`
	var args []any
	if state != "" {
		q += ` AND state=?`
		args = append(args, state)
	}
	if severity != "" {
		q += ` AND severity=?`
		args = append(args, severity)
	}
	if agentID != "" {
		q += ` AND agent_id=?`
		args = append(args, agentID)
	}
	q += ` ORDER BY started_at DESC, id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list alerts: %w", err)
	}
	defer rows.Close()
	var out []*Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanAlert(row scanRow) (*Alert, error) {
	var a Alert
	var agentID *string
	var resolvedAt *int64
	err := row.Scan(&a.ID, &a.RuleID, &agentID, &a.Kind, &a.Severity,
		&a.Message, &a.State, &a.DedupKey, &a.StartedAt, &resolvedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: scan alert: %w", err)
	}
	if agentID != nil {
		a.AgentID = *agentID
	}
	a.ResolvedAt = resolvedAt
	return &a, nil
}

// --- bulk facts (alert engine tick: one query, not per-host) ---

// LatestHostFactsJSONAll returns the latest host_facts document per agent
// (single query; the alert engine's DB cache per arch §7.5).
func (s *Store) LatestHostFactsJSONAll() (map[string]string, error) {
	rows, err := s.db.Query(
		`SELECT agent_id, data FROM host_facts
		 WHERE ts = (SELECT MAX(ts) FROM host_facts hf2 WHERE hf2.agent_id = host_facts.agent_id)`)
	if err != nil {
		return nil, fmt.Errorf("store: host facts all: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var agentID, doc string
		if err := rows.Scan(&agentID, &doc); err != nil {
			return nil, fmt.Errorf("store: scan host facts: %w", err)
		}
		out[agentID] = doc
	}
	return out, rows.Err()
}
