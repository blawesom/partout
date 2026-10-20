// Short-lived SSE-scoped tokens (PRD R10). EventSource cannot set headers,
// so the web UI opens /api/v1/events with ?token=<sse-token>; the token is
// accepted ONLY there (never as a general bearer) and is stored hashed
// (SHA-256 hex) like every other credential.
package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// SSEToken is an issued SSE-scoped token row (hashed at rest).
type SSEToken struct {
	TokenHash string
	Principal string
	Role      string
	Created   int64
	Expires   int64
}

// InsertSSEToken stores an SSE-scoped token (hash, principal, role, expiry).
func (s *Store) InsertSSEToken(t *SSEToken) error {
	_, err := s.db.Exec(
		`INSERT INTO sse_tokens (token_hash, principal, role, created, expires)
		 VALUES(?,?,?,?,?)`,
		t.TokenHash, t.Principal, t.Role, t.Created, t.Expires)
	if err != nil {
		return fmt.Errorf("store: insert sse token: %w", err)
	}
	return nil
}

// GetSSETokenByHash resolves an SSE-scoped token by hash (nil if unknown).
func (s *Store) GetSSETokenByHash(tokenHash string) (*SSEToken, error) {
	row := s.db.QueryRow(
		`SELECT token_hash, principal, role, created, expires
		 FROM sse_tokens WHERE token_hash=?`, tokenHash)
	t := &SSEToken{}
	err := row.Scan(&t.TokenHash, &t.Principal, &t.Role, &t.Created, &t.Expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get sse token: %w", err)
	}
	return t, nil
}

// DeleteExpiredSSETokens removes expired SSE tokens, returning how many.
func (s *Store) DeleteExpiredSSETokens(now int64) (int, error) {
	res, err := s.db.Exec(`DELETE FROM sse_tokens WHERE expires <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: sweep sse tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
