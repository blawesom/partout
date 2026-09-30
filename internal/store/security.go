package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SecurityFinding is one package on one host with known unpatched
// vulnerabilities (M5.1). Derived server-side from the agent's update list
// correlated against OSV; never agent-asserted.
type SecurityFinding struct {
	AgentID   string
	Pkg       string
	Installed string
	Available string
	VulnCount int
	MaxCVSS   float64
	VulnIDs   string // comma-joined, capped
	UpdatedAt int64
}

// SecurityScanMeta is the per-host bookkeeping row for the security scan.
type SecurityScanMeta struct {
	AgentID         string
	ScannedAt       int64
	UpdatesTotal    int
	SecurityUpdates int
}

// ReplaceSecurityFindings atomically replaces one host's finding set
// (delete + insert in a tx) and upserts its scan meta row.
func (s *Store) ReplaceSecurityFindings(agentID string, findings []SecurityFinding, meta SecurityScanMeta) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM security_findings WHERE agent_id = ?`, agentID); err != nil {
		return fmt.Errorf("store: clear findings: %w", err)
	}
	for _, f := range findings {
		if f.AgentID == "" {
			f.AgentID = agentID
		}
		if f.UpdatedAt == 0 {
			f.UpdatedAt = time.Now().Unix()
		}
		if _, err := tx.Exec(`INSERT INTO security_findings
			(agent_id, pkg, installed, available, vuln_count, max_cvss, vuln_ids, updated_at)
			VALUES(?,?,?,?,?,?,?,?)`,
			f.AgentID, f.Pkg, f.Installed, f.Available, f.VulnCount, f.MaxCVSS, f.VulnIDs, f.UpdatedAt); err != nil {
			return fmt.Errorf("store: insert finding %s/%s: %w", agentID, f.Pkg, err)
		}
	}
	if meta.ScannedAt == 0 {
		meta.ScannedAt = time.Now().Unix()
	}
	if _, err := tx.Exec(`INSERT INTO security_scan_meta
		(agent_id, scanned_at, updates_total, security_updates) VALUES(?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET
		scanned_at=excluded.scanned_at,
		updates_total=excluded.updates_total,
		security_updates=excluded.security_updates`,
		meta.AgentID, meta.ScannedAt, meta.UpdatesTotal, meta.SecurityUpdates); err != nil {
		return fmt.Errorf("store: scan meta: %w", err)
	}
	return tx.Commit()
}

// SecurityFindingsFor returns one host's findings, highest CVSS first.
func (s *Store) SecurityFindingsFor(agentID string) ([]SecurityFinding, error) {
	rows, err := s.db.Query(`SELECT agent_id, pkg, installed, available, vuln_count, max_cvss, vuln_ids, updated_at
		FROM security_findings WHERE agent_id = ? ORDER BY max_cvss DESC, pkg`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecurityFinding
	for rows.Next() {
		var f SecurityFinding
		if err := rows.Scan(&f.AgentID, &f.Pkg, &f.Installed, &f.Available,
			&f.VulnCount, &f.MaxCVSS, &f.VulnIDs, &f.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SecurityScanMetaFor returns the scan meta row for one host.
func (s *Store) SecurityScanMetaFor(agentID string) (SecurityScanMeta, error) {
	var m SecurityScanMeta
	err := s.db.QueryRow(`SELECT agent_id, scanned_at, updates_total, security_updates
		FROM security_scan_meta WHERE agent_id = ?`, agentID).
		Scan(&m.AgentID, &m.ScannedAt, &m.UpdatesTotal, &m.SecurityUpdates)
	if errors.Is(err, sql.ErrNoRows) {
		return SecurityScanMeta{}, ErrNotFound
	}
	return m, err
}

// AllSecurityScanMeta lists scan meta for hosts that have ever been scanned.
func (s *Store) AllSecurityScanMeta() ([]SecurityScanMeta, error) {
	rows, err := s.db.Query(`SELECT agent_id, scanned_at, updates_total, security_updates
		FROM security_scan_meta ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecurityScanMeta
	for rows.Next() {
		var m SecurityScanMeta
		if err := rows.Scan(&m.AgentID, &m.ScannedAt, &m.UpdatesTotal, &m.SecurityUpdates); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteSecurityDataFor removes a host's findings + scan meta (host delete).
func (s *Store) DeleteSecurityDataFor(agentID string) error {
	if _, err := s.db.Exec(`DELETE FROM security_findings WHERE agent_id = ?`, agentID); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM security_scan_meta WHERE agent_id = ?`, agentID)
	return err
}
