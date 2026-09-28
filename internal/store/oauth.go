// OAuth2 (PKCE) + MCP client store (M4, PRD R11).
package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// MCPClient is one registered MCP client (admin-managed).
type MCPClient struct {
	ID      string
	Name    string
	Scope   string
	Created int64
}

// OAuthCode is a one-time authorization code (PKCE-bound).
type OAuthCode struct {
	ID        string
	CodeHash  string
	ClientID  string
	Principal string
	Role      string
	Scope     string
	Challenge string
	Expires   int64
	Used      bool
	Created   int64
}

// OAuthToken is an issued access token (hashed at rest).
type OAuthToken struct {
	TokenHash string
	ClientID  string
	Principal string
	Role      string
	Scope     string
	Created   int64
	Expires   int64
}

// --- MCP clients ---

func (s *Store) CreateMCPClient(c *MCPClient) error {
	_, err := s.db.Exec(`INSERT INTO mcp_clients (id, name, scope, created) VALUES (?,?,?,?)`,
		c.ID, c.Name, c.Scope, c.Created)
	if err != nil {
		return fmt.Errorf("store: create mcp client: %w", err)
	}
	return nil
}

func (s *Store) GetMCPClient(id string) (*MCPClient, error) {
	row := s.db.QueryRow(`SELECT id, name, scope, created FROM mcp_clients WHERE id=?`, id)
	c := &MCPClient{}
	if err := row.Scan(&c.ID, &c.Name, &c.Scope, &c.Created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get mcp client: %w", err)
	}
	return c, nil
}

func (s *Store) ListMCPClients() ([]*MCPClient, error) {
	rows, err := s.db.Query(`SELECT id, name, scope, created FROM mcp_clients ORDER BY created`)
	if err != nil {
		return nil, fmt.Errorf("store: list mcp clients: %w", err)
	}
	defer rows.Close()
	var out []*MCPClient
	for rows.Next() {
		c := &MCPClient{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Scope, &c.Created); err != nil {
			return nil, fmt.Errorf("store: scan mcp client: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- authorization codes ---

func (s *Store) InsertOAuthCode(c *OAuthCode) error {
	_, err := s.db.Exec(
		`INSERT INTO oauth_codes (id, code_hash, client_id, principal, role, scope, challenge, expires, used, created)
		 VALUES (?,?,?,?,?,?,?,?,0,?)`,
		c.ID, c.CodeHash, c.ClientID, c.Principal, c.Role, c.Scope,
		c.Challenge, c.Expires, c.Created)
	if err != nil {
		return fmt.Errorf("store: insert oauth code: %w", err)
	}
	return nil
}

func (s *Store) GetOAuthCodeByHash(codeHash string) (*OAuthCode, error) {
	row := s.db.QueryRow(
		`SELECT id, code_hash, client_id, principal, role, scope, challenge, expires, used, created
		 FROM oauth_codes WHERE code_hash=?`, codeHash)
	c := &OAuthCode{}
	err := row.Scan(&c.ID, &c.CodeHash, &c.ClientID, &c.Principal, &c.Role,
		&c.Scope, &c.Challenge, &c.Expires, &c.Used, &c.Created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get oauth code: %w", err)
	}
	return c, nil
}

func (s *Store) MarkOAuthCodeUsed(id string) error {
	res, err := s.db.Exec(`UPDATE oauth_codes SET used=1 WHERE id=? AND used=0`, id)
	if err != nil {
		return fmt.Errorf("store: mark oauth code used: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("store: oauth code not found or already used")
	}
	return nil
}

// --- access tokens ---

func (s *Store) InsertOAuthToken(t *OAuthToken) error {
	_, err := s.db.Exec(
		`INSERT INTO oauth_tokens (token_hash, client_id, principal, role, scope, created, expires)
		 VALUES (?,?,?,?,?,?,?)`,
		t.TokenHash, t.ClientID, t.Principal, t.Role, t.Scope, t.Created, t.Expires)
	if err != nil {
		return fmt.Errorf("store: insert oauth token: %w", err)
	}
	return nil
}

func (s *Store) GetOAuthTokenByHash(tokenHash string) (*OAuthToken, error) {
	row := s.db.QueryRow(
		`SELECT token_hash, client_id, principal, role, scope, created, expires
		 FROM oauth_tokens WHERE token_hash=?`, tokenHash)
	t := &OAuthToken{}
	err := row.Scan(&t.TokenHash, &t.ClientID, &t.Principal, &t.Role,
		&t.Scope, &t.Created, &t.Expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get oauth token: %w", err)
	}
	return t, nil
}
