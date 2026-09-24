package store

import (
	"database/sql"
	"errors"

	"github.com/blawesom/partout/internal/id"
)

// ---- Secrets (M3, PRD §5.7) -----------------------------------------------

// Secret is a named, versioned secret bound to a selector. Values live only
// in secret_versions.ciphertext (encrypted at rest); this row never carries
// a plaintext value.
type Secret struct {
	ID         string
	Name       string
	Selector   string
	OfflineTTL int64 // agent-side encrypted cache window, seconds (0 = never)
	Created    int64
	Updated    int64
}

// SecretVersion is one ciphertext under the secret's HKDF-derived key.
type SecretVersion struct {
	ID        string
	SecretID  string
	Version   int64
	Ciphertext []byte
	Created   int64
	Revoked   bool
}

// SecretBinding records that a run materialized a specific version on a host
// (PRD §5.7: "audit records which version was used").
type SecretBinding struct {
	ID      string
	SecretID string
	Version int64
	AgentID string
	Ref     string // task-run / execution id that declared the secret
	Ts      int64
}

// CreateSecret inserts a secret and its first version (v1).
func (s *Store) CreateSecret(sec Secret, v1 SecretVersion) error {
	if sec.ID == "" || sec.Name == "" {
		return errors.New("store: secret id and name required")
	}
	if v1.ID == "" || len(v1.Ciphertext) == 0 {
		return errors.New("store: first version ciphertext required")
	}
	if v1.Version != 1 {
		return errors.New("store: first version must be 1")
	}
	if sec.Created == 0 {
		sec.Created = now()
	}
	sec.Updated = sec.Created
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		INSERT INTO secrets (id, name, selector, offline_ttl, created, updated)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sec.ID, sec.Name, sec.Selector, sec.OfflineTTL, sec.Created, sec.Updated); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO secret_versions (id, secret_id, version, ciphertext, created, revoked)
		VALUES (?, ?, 1, ?, ?, 0)`, v1.ID, sec.ID, v1.Ciphertext, v1.Created); err != nil {
		return err
	}
	return tx.Commit()
}

// GetSecret returns secret metadata (never the value).
func (s *Store) GetSecret(idOrName string) (*Secret, error) {
	row := s.db.QueryRow(`
		SELECT id, name, selector, offline_ttl, created, updated
		FROM secrets WHERE id = ? OR name = ?`, idOrName, idOrName)
	var sec Secret
	if err := row.Scan(&sec.ID, &sec.Name, &sec.Selector, &sec.OfflineTTL, &sec.Created, &sec.Updated); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &sec, nil
}

// ListSecrets returns all secrets (metadata only), newest first.
func (s *Store) ListSecrets() ([]*Secret, error) {
	rows, err := s.db.Query(`
		SELECT id, name, selector, offline_ttl, created, updated
		FROM secrets ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Secret
	for rows.Next() {
		var sec Secret
		if err := rows.Scan(&sec.ID, &sec.Name, &sec.Selector, &sec.OfflineTTL, &sec.Created, &sec.Updated); err != nil {
			return nil, err
		}
		out = append(out, &sec)
	}
	return out, rows.Err()
}

// DeleteSecret removes a secret and all its versions (cascade).
func (s *Store) DeleteSecret(idOrName string) error {
	res, err := s.db.Exec(`DELETE FROM secrets WHERE id = ? OR name = ?`, idOrName, idOrName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RotateSecret adds a new version and revokes all prior versions (PRD §5.7:
// a new version invalidates prior bindings). Returns the new version number.
func (s *Store) RotateSecret(secretID string, ciphertext []byte) (int64, error) {
	if len(ciphertext) == 0 {
		return 0, errors.New("store: rotate requires ciphertext")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	row := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE secret_id = ?`, secretID)
	var next int64
	if err := row.Scan(&next); err != nil {
		return 0, err
	}
	next++
	if _, err := tx.Exec(`
		INSERT INTO secret_versions (id, secret_id, version, ciphertext, created, revoked)
		VALUES (?, ?, ?, ?, ?, 0)`, id.New("secv"), secretID, next, ciphertext, now()); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE secret_versions SET revoked = 1 WHERE secret_id = ? AND version < ?`, secretID, next); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE secrets SET updated = ? WHERE id = ?`, now(), secretID); err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

// RevokeSecretVersion marks a single version revoked (rotation-by-revoke).
// Revoking an already-revoked version is an error (idempotency-safe API).
func (s *Store) RevokeSecretVersion(secretID string, version int64) error {
	res, err := s.db.Exec(`UPDATE secret_versions SET revoked = 1 WHERE secret_id = ? AND version = ? AND revoked = 0`,
		secretID, version)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = s.db.Exec(`UPDATE secrets SET updated = ? WHERE id = ?`, now(), secretID)
	return err
}

// UpdateSecretMeta updates selector / offline_ttl on a secret.
func (s *Store) UpdateSecretMeta(idOrName, selector string, offlineTTL int64) error {
	res, err := s.db.Exec(`
		UPDATE secrets SET selector = ?, offline_ttl = ?, updated = ?
		WHERE id = ? OR name = ?`, selector, offlineTTL, now(), idOrName, idOrName)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetLatestSecretVersion returns the newest non-revoked version, or
// ErrNotFound when every version is revoked.
func (s *Store) GetLatestSecretVersion(secretID string) (*SecretVersion, error) {
	row := s.db.QueryRow(`
		SELECT id, secret_id, version, ciphertext, created, revoked
		FROM secret_versions WHERE secret_id = ? AND revoked = 0
		ORDER BY version DESC LIMIT 1`, secretID)
	return scanSecretVersion(row)
}

// GetSecretVersion fetches one version (revoked or not).
func (s *Store) GetSecretVersion(secretID string, version int64) (*SecretVersion, error) {
	row := s.db.QueryRow(`
		SELECT id, secret_id, version, ciphertext, created, revoked
		FROM secret_versions WHERE secret_id = ? AND version = ?`, secretID, version)
	return scanSecretVersion(row)
}

// RecordSecretBinding records a materialization (audit).
func (s *Store) RecordSecretBinding(b SecretBinding) error {
	if b.ID == "" {
		b.ID = id.New("secb")
	}
	if b.Ts == 0 {
		b.Ts = now()
	}
	_, err := s.db.Exec(`
		INSERT INTO secret_bindings (id, secret_id, version, agent_id, ref, ts)
		VALUES (?, ?, ?, ?, ?, ?)`,
		b.ID, b.SecretID, b.Version, b.AgentID, b.Ref, b.Ts)
	return err
}

// ListSecretBindings returns materialization audit rows for a secret.
func (s *Store) ListSecretBindings(secretID string, limit int) ([]*SecretBinding, error) {
	rows, err := s.db.Query(`
		SELECT id, secret_id, version, agent_id, ref, ts
		FROM secret_bindings WHERE secret_id = ? ORDER BY ts DESC LIMIT ?`, secretID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SecretBinding
	for rows.Next() {
		var b SecretBinding
		if err := rows.Scan(&b.ID, &b.SecretID, &b.Version, &b.AgentID, &b.Ref, &b.Ts); err != nil {
			return nil, err
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

func scanSecretVersion(row interface{ Scan(...any) error }) (*SecretVersion, error) {
	var v SecretVersion
	var revoked int
	err := row.Scan(&v.ID, &v.SecretID, &v.Version, &v.Ciphertext, &v.Created, &revoked)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	v.Revoked = revoked == 1
	return &v, nil
}