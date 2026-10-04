package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/blawesom/partout/internal/id"
)

// ---- Elevation policies (server-side store, PRD Decision 3 onboarding) ----
//
// The elevation policy is host-owned (the sudoers wall must never be
// widenable from the server), but the CANONICAL source the operator
// manages is server-side: named, versioned-on-update policy documents that
// provisioning ships to hosts (with sha256 verification) and that drift
// detection (`partout ctl elevation check`) can be compared against fleet
// wide — each agent reports its effective policy hash as the
// partout.elevation fact.

// ElevationPolicy is one named elevation policy document.
type ElevationPolicy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	RulesJSON   string `json:"rules_json"` // canonical rules array
	PolicySHA   string `json:"policy_sha256"`
	Created     int64  `json:"created"`
	Updated     int64  `json:"updated"`
}

// ErrElevationPolicyNotFound is returned by id-or-name lookups that match
// nothing.
var ErrElevationPolicyNotFound = errors.New("store: elevation policy not found")

// CreateElevationPolicy inserts a new named policy.
func (s *Store) CreateElevationPolicy(p *ElevationPolicy) error {
	if p.ID == "" {
		p.ID = id.New("epl")
	}
	now := time.Now().Unix()
	p.Created, p.Updated = now, now
	_, err := s.db.Exec(`INSERT INTO elevation_policies (id, name, description, rules_json, policy_sha256, created, updated)
		VALUES (?,?,?,?,?,?,?)`,
		p.ID, p.Name, p.Description, p.RulesJSON, p.PolicySHA, p.Created, p.Updated)
	if err != nil {
		return err
	}
	return nil
}

// UpdateElevationPolicy replaces the rules/description of an existing
// policy (by id or name), recomputing nothing — the caller supplies the
// canonical rules + hash.
func (s *Store) UpdateElevationPolicy(idOrName, description, rulesJSON, policySHA string) (*ElevationPolicy, error) {
	p, err := s.ElevationPolicy(idOrName)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(`UPDATE elevation_policies SET description=?, rules_json=?, policy_sha256=?, updated=? WHERE id=?`,
		description, rulesJSON, policySHA, time.Now().Unix(), p.ID); err != nil {
		return nil, err
	}
	return s.ElevationPolicy(p.ID)
}

// ElevationPolicy fetches one policy by id or name.
func (s *Store) ElevationPolicy(idOrName string) (*ElevationPolicy, error) {
	row := s.db.QueryRow(`SELECT id, name, description, rules_json, policy_sha256, created, updated
		FROM elevation_policies WHERE id=? OR name=?`, idOrName, idOrName)
	return scanElevationPolicy(row)
}

// ElevationPolicies lists all policies, name-ordered.
func (s *Store) ElevationPolicies() ([]*ElevationPolicy, error) {
	rows, err := s.db.Query(`SELECT id, name, description, rules_json, policy_sha256, created, updated
		FROM elevation_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ElevationPolicy
	for rows.Next() {
		p, err := scanElevationPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteElevationPolicy removes a policy by id or name. Hosts already
// provisioned with it keep running their installed copy (the wall is
// host-owned); re-provision (join mode) or config management updates them.
func (s *Store) DeleteElevationPolicy(idOrName string) error {
	res, err := s.db.Exec(`DELETE FROM elevation_policies WHERE id=? OR name=?`, idOrName, idOrName)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrElevationPolicyNotFound
	}
	return nil
}

func scanElevationPolicy(row interface{ Scan(...any) error }) (*ElevationPolicy, error) {
	p := &ElevationPolicy{}
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.RulesJSON, &p.PolicySHA, &p.Created, &p.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrElevationPolicyNotFound
	}
	return p, err
}
