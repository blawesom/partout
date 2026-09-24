package store

import (
	"database/sql"
	"errors"
	"time"
)

// Principal is a local user (PRD Decision 6, arch §9.2): username,
// argon2id password hash (per-user pepper embedded in the PHC string),
// RBAC role, disabled flag.
type Principal struct {
	Username     string
	PasswordHash string
	Role         string
	Disabled     bool
	CreatedUnix  int64
}

var ErrNoPrincipal = errors.New("store: no such principal")

// CreatePrincipal inserts a user. Fails on duplicate username.
func (s *Store) CreatePrincipal(username, passwordHash, role string) error {
	_, err := s.db.Exec(
		`INSERT INTO principals(username, password_hash, role, disabled, created_unix)
		 VALUES(?, ?, ?, 0, ?)`,
		username, passwordHash, role, time.Now().Unix())
	return err
}

// Principal returns one user by name (ErrNoPrincipal if absent).
func (s *Store) Principal(username string) (*Principal, error) {
	p := &Principal{}
	err := s.db.QueryRow(
		`SELECT username, password_hash, role, disabled, created_unix
		 FROM principals WHERE username = ?`, username).
		Scan(&p.Username, &p.PasswordHash, &p.Role, &p.Disabled, &p.CreatedUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoPrincipal
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListPrincipals returns all users (never called for token validation;
// admin UI listing only).
func (s *Store) ListPrincipals() ([]*Principal, error) {
	rows, err := s.db.Query(
		`SELECT username, password_hash, role, disabled, created_unix
		 FROM principals ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Principal
	for rows.Next() {
		p := &Principal{}
		if err := rows.Scan(&p.Username, &p.PasswordHash, &p.Role, &p.Disabled, &p.CreatedUnix); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AnyPrincipal reports whether at least one user exists (gates the
// first-run admin bootstrap and the local-mode auth exemption).
func (s *Store) AnyPrincipal() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM principals`).Scan(&n)
	return n > 0, err
}

// SetPrincipalRole changes a user's role.
func (s *Store) SetPrincipalRole(username, role string) error {
	res, err := s.db.Exec(`UPDATE principals SET role = ? WHERE username = ?`, role, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoPrincipal
	}
	return nil
}

// SetPrincipalPassword replaces a user's password hash.
func (s *Store) SetPrincipalPassword(username, passwordHash string) error {
	res, err := s.db.Exec(
		`UPDATE principals SET password_hash = ? WHERE username = ?`, passwordHash, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoPrincipal
	}
	return nil
}

// SetPrincipalDisabled toggles the disabled flag (disabled users cannot
// log in; existing sessions are invalidated by the auth controller).
func (s *Store) SetPrincipalDisabled(username string, disabled bool) error {
	d := 0
	if disabled {
		d = 1
	}
	res, err := s.db.Exec(`UPDATE principals SET disabled = ? WHERE username = ?`, d, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoPrincipal
	}
	return nil
}

// DeletePrincipal removes a user.
func (s *Store) DeletePrincipal(username string) error {
	res, err := s.db.Exec(`DELETE FROM principals WHERE username = ?`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoPrincipal
	}
	return nil
}

// CountActiveAdmins counts non-disabled admin users (last-admin guard).
func (s *Store) CountActiveAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM principals WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}
