// Package store — policy rule persistence and bundle construction.
//
// The store persists declarative policy rules (architecture §5.2) and serves
// them as a versioned, content-hashed bundle for the guardrail (arch §5.3).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/blawesom/partout/internal/policy"
)

// PolicyRule is one stored declarative rule.
type PolicyRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	MatchJSON   json.RawMessage `json:"match"`
	Effect      string          `json:"effect"`
	Priority    int             `json:"priority"`
	CreatedUnix int64           `json:"created_unix"`
}

// CreatePolicy inserts a new rule.
func (s *Store) CreatePolicy(id, name string, match policy.Match, effect string, priority int) error {
	matchJSON, err := json.Marshal(match)
	if err != nil {
		return fmt.Errorf("store: marshal match: %w", err)
	}
	if _, err := s.db.Exec(`
		INSERT INTO policies (id, name, match_json, effect, priority, created_unix)
		VALUES (?,?,?,?,?,?)
	`, id, name, string(matchJSON), effect, priority, now()); err != nil {
		return fmt.Errorf("store: create policy: %w", err)
	}
	// Bump the bundle version so agents pick up the change.
	return s.bumpPolicyVersion()
}

// ListPolicies returns all rules, ordered by priority then id.
func (s *Store) ListPolicies() ([]PolicyRule, error) {
	rows, err := s.db.Query(`
		SELECT id, name, match_json, effect, priority, created_unix
		FROM policies ORDER BY priority ASC, id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list policies: %w", err)
	}
	defer rows.Close()
	var out []PolicyRule
	for rows.Next() {
		var p PolicyRule
		var matchJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &matchJSON, &p.Effect, &p.Priority, &p.CreatedUnix); err != nil {
			return nil, fmt.Errorf("store: scan policy: %w", err)
		}
		p.MatchJSON = matchJSON
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPolicyRules decodes stored rules into policy.Rule for evaluation.
func (s *Store) GetPolicyRules() ([]policy.Rule, error) {
	stored, err := s.ListPolicies()
	if err != nil {
		return nil, err
	}
	rules := make([]policy.Rule, 0, len(stored))
	for _, sp := range stored {
		var m policy.Match
		if err := json.Unmarshal(sp.MatchJSON, &m); err != nil {
			return nil, fmt.Errorf("store: decode rule %s match: %w", sp.ID, err)
		}
		rules = append(rules, policy.Rule{
			ID:       sp.ID,
			Name:     sp.Name,
			Match:    m,
			Effect:   sp.Effect,
			Priority: sp.Priority,
		})
	}
	return rules, nil
}

// DeletePolicy removes a rule by id. Returns rows affected.
func (s *Store) DeletePolicy(id string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM policies WHERE id=?`, id)
	if err != nil {
		return 0, fmt.Errorf("store: delete policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n > 0 {
		if err := s.bumpPolicyVersion(); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// PolicyBundleVersion returns the current bundle version counter.
func (s *Store) PolicyBundleVersion() (uint64, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key='policy_bundle_version'`).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: read bundle version: %w", err)
	}
	var n uint64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return 0, fmt.Errorf("store: parse bundle version: %w", err)
	}
	return n, nil
}

// bumpPolicyVersion increments the bundle version counter.
func (s *Store) bumpPolicyVersion() error {
	cur, err := s.PolicyBundleVersion()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO meta (key, value) VALUES ('policy_bundle_version', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value
	`, fmt.Sprint(cur+1))
	if err != nil {
		return fmt.Errorf("store: bump bundle version: %w", err)
	}
	return nil
}

// BuildPolicyBundle builds the current bundle (version, hash, rules JSON).
func (s *Store) BuildPolicyBundle() (version uint64, contentHash string, rulesJSON string, err error) {
	rules, err := s.GetPolicyRules()
	if err != nil {
		return 0, "", "", err
	}
	v, hash, j := policy.BuildBundle(rules)
	// Prefer the persisted version counter (survives across the same rule
	// set being recreated); if zero, fall back to the derived version.
	stored, err := s.PolicyBundleVersion()
	if err != nil {
		return 0, "", "", err
	}
	if stored > 0 {
		v = stored
	}
	return v, hash, j, nil
}
