package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// PkgAction is one package operation's server-side record (PRD §5.6).
type PkgAction struct {
	ID           string
	AgentID      string
	Kind         string // list | dry_run | apply
	Status       string // running | succeeded | failed
	DrySummary   string
	BeforeJSON   string // JSON []PkgUpdateJSON (before-state journal)
	AfterJSON    string // JSON []PkgUpdateJSON (after-state journal)
	AppliedCount int64
	Error        string
	Created      int64
}

// NewPkgActionID builds a new package-action ID.
func NewPkgActionID() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		// Fallback to a time-based ID (should never happen).
		return "pkg_" + hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return "pkg_" + hex.EncodeToString(raw)
}

// InsertPkgAction records a new package action (status "running").
func (s *Store) InsertPkgAction(a *PkgAction) error {
	if a.Created == 0 {
		a.Created = time.Now().Unix()
	}
	_, err := s.db.Exec(`
		INSERT INTO package_actions
		 (id, agent_id, kind, status, dry_summary, before_json, after_json,
			 applied_count, error, created)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AgentID, a.Kind, a.Status, a.DrySummary, a.BeforeJSON,
		a.AfterJSON, a.AppliedCount, a.Error, a.Created)
	if err != nil {
		return fmt.Errorf("store: insert pkg_action: %w", err)
	}
	return nil
}

// FinalizePkgAction updates the terminal state of a package action.
func (s *Store) FinalizePkgAction(id, status, drySummary, beforeJSON, afterJSON string, applied int64, errMsg string) error {
	_, err := s.db.Exec(`
		UPDATE package_actions
		SET status=?, dry_summary=?, before_json=?, after_json=?, applied_count=?, error=?
		WHERE id=?`,
		status, drySummary, beforeJSON, afterJSON, applied, errMsg, id)
	if err != nil {
		return fmt.Errorf("store: finalize pkg_action: %w", err)
	}
	return nil
}

// GetPkgAction fetches one package action by ID.
func (s *Store) GetPkgAction(id string) (*PkgAction, error) {
	row := s.db.QueryRow(`
		SELECT id, agent_id, kind, status, dry_summary, before_json,
		       after_json, applied_count, error, created
		FROM package_actions WHERE id=?`, id)
	var a PkgAction
	if err := row.Scan(&a.ID, &a.AgentID, &a.Kind, &a.Status, &a.DrySummary,
		&a.BeforeJSON, &a.AfterJSON, &a.AppliedCount, &a.Error, &a.Created); err != nil {
		return nil, fmt.Errorf("store: get pkg_action: %w", err)
	}
	return &a, nil
}

// ListPkgActions returns recent package actions, most recent first.
func (s *Store) ListPkgActions(limit int) ([]*PkgAction, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := s.db.Query(`
		SELECT id, agent_id, kind, status, dry_summary, before_json,
		       after_json, applied_count, error, created
		FROM package_actions ORDER BY created DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list pkg_actions: %w", err)
	}
	defer rows.Close()
	var out []*PkgAction
	for rows.Next() {
		var a PkgAction
		if err := rows.Scan(&a.ID, &a.AgentID, &a.Kind, &a.Status, &a.DrySummary,
			&a.BeforeJSON, &a.AfterJSON, &a.AppliedCount, &a.Error, &a.Created); err != nil {
			return nil, fmt.Errorf("store: scan pkg_action: %w", err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// PkgUpdateJSON is the wire form of a before/after journal entry.
type PkgUpdateJSON struct {
	Name        string `json:"name"`
	Installed   string `json:"installed,omitempty"`
	Available   string `json:"available,omitempty"`
	VulnCount   int64  `json:"vuln_count,omitempty"`
	MaxSeverity string `json:"max_severity,omitempty"`
	IsSecurity  bool   `json:"is_security,omitempty"`
}

// MarshalPkgUpdates encodes a before/after journal to JSON for storage.
func MarshalPkgUpdates(ups []PkgUpdateJSON) (string, error) {
	b, err := json.Marshal(ups)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalPkgUpdates decodes a stored journal.
func UnmarshalPkgUpdates(s string) ([]PkgUpdateJSON, error) {
	if s == "" {
		return nil, nil
	}
	var ups []PkgUpdateJSON
	if err := json.Unmarshal([]byte(s), &ups); err != nil {
		return nil, err
	}
	return ups, nil
}