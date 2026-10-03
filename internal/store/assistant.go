// Package store — assistant (R26, M9) config + transcript persistence.
// The transcript is the split-store accountability record (PRD Decision 18):
// full prompts + replies here; the audit log carries only the action half
// (session id, model, tool calls, prompt hash).
package store

import (
	"database/sql"
)

// AssistantConfig is the single operator-configured endpoint row (id=1).
// APIKeySealed is the AES-GCM sealed endpoint API key — never returned by
// read APIs (the API layer keeps it write-only, like secret values).
type AssistantConfig struct {
	BaseURL        string
	Model          string
	APIKeySealed   []byte
	MaxToolCalls   int
	TimeoutS       int
	DefaultProfile string
	Enabled        bool
	Updated        int64
}

// AssistantSession is one chat session, owned by a principal.
type AssistantSession struct {
	ID      string
	UserID  string
	Profile string
	Created int64
	Updated int64
}

// AssistantMessage is one transcript row: user prompt, assistant prose, or
// a tool call/result (role=tool, ToolName + ToolArgs set).
type AssistantMessage struct {
	ID        int64
	SessionID string
	Role      string // user|assistant|tool
	Content   string
	ToolName  string
	ToolArgs  string
	Created   int64
}

// GetAssistantConfig returns the endpoint config row (never absent — a
// zero-value row is inserted on first read).
func (s *Store) GetAssistantConfig() (*AssistantConfig, error) {
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO assistant_config (id) VALUES (1)`); err != nil {
		return nil, err
	}
	var c AssistantConfig
	var sealed []byte
	var enabled int
	err := s.db.QueryRow(`
		SELECT base_url, model, api_key_sealed, max_tool_calls, timeout_s,
		       default_profile, enabled, updated
		FROM assistant_config WHERE id=1
	`).Scan(&c.BaseURL, &c.Model, &sealed, &c.MaxToolCalls, &c.TimeoutS,
		&c.DefaultProfile, &enabled, &c.Updated)
	if err != nil {
		return nil, err
	}
	c.APIKeySealed = sealed
	c.Enabled = enabled != 0
	return &c, nil
}

// SaveAssistantConfig updates the endpoint config row. A nil APIKeySealed
// keeps the existing sealed key (the API layer treats the key as write-only:
// a config PUT without a new key does not clear it — ResetAssistantKey does).
func (s *Store) SaveAssistantConfig(c *AssistantConfig) error {
	// Ensure the single row exists (fresh DB): UPDATE alone is a no-op then.
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO assistant_config (id) VALUES (1)`); err != nil {
		return err
	}
	_, err := s.db.Exec(`
		UPDATE assistant_config
		SET base_url=?, model=?, max_tool_calls=?, timeout_s=?, default_profile=?,
		    enabled=?, updated=?
		WHERE id=1
	`, c.BaseURL, c.Model, c.MaxToolCalls, c.TimeoutS, c.DefaultProfile,
		boolToInt(c.Enabled), now())
	return err
}

// SetAssistantKey seals+stores the endpoint API key (nil clears it).
func (s *Store) SetAssistantKey(sealed []byte) error {
	_, err := s.db.Exec(`UPDATE assistant_config SET api_key_sealed=?, updated=? WHERE id=1`, sealed, now())
	return err
}

// CreateAssistantSession inserts a session.
func (s *Store) CreateAssistantSession(ss *AssistantSession) error {
	if ss.Created == 0 {
		ss.Created = now()
	}
	ss.Updated = ss.Created
	_, err := s.db.Exec(`
		INSERT INTO assistant_sessions (id, user_id, profile, created, updated)
		VALUES (?,?,?,?,?)
	`, ss.ID, ss.UserID, ss.Profile, ss.Created, ss.Updated)
	return err
}

// GetAssistantSession fetches a session by id.
func (s *Store) GetAssistantSession(id string) (*AssistantSession, error) {
	var ss AssistantSession
	err := s.db.QueryRow(`
		SELECT id, user_id, profile, created, updated FROM assistant_sessions WHERE id=?
	`, id).Scan(&ss.ID, &ss.UserID, &ss.Profile, &ss.Created, &ss.Updated)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return &ss, err
}

// ListAssistantSessions returns a user's sessions, newest first (admin may
// pass any user id; the API layer owns the authz).
func (s *Store) ListAssistantSessions(userID string, limit int) ([]*AssistantSession, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, profile, created, updated FROM assistant_sessions
		WHERE user_id=? ORDER BY created DESC LIMIT ?
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AssistantSession
	for rows.Next() {
		var ss AssistantSession
		if err := rows.Scan(&ss.ID, &ss.UserID, &ss.Profile, &ss.Created, &ss.Updated); err != nil {
			return nil, err
		}
		out = append(out, &ss)
	}
	return out, rows.Err()
}

// TouchAssistantSession bumps a session's updated timestamp.
func (s *Store) TouchAssistantSession(id string) error {
	_, err := s.db.Exec(`UPDATE assistant_sessions SET updated=? WHERE id=?`, now(), id)
	return err
}

// AppendAssistantMessage adds one transcript row.
func (s *Store) AppendAssistantMessage(m *AssistantMessage) (int64, error) {
	if m.Created == 0 {
		m.Created = now()
	}
	res, err := s.db.Exec(`
		INSERT INTO assistant_messages (session_id, role, content, tool_name, tool_args, created)
		VALUES (?,?,?,?,?,?)
	`, m.SessionID, m.Role, m.Content, m.ToolName, m.ToolArgs, m.Created)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	_ = s.TouchAssistantSession(m.SessionID)
	return id, nil
}

// ListAssistantMessages returns a session's transcript, oldest first.
func (s *Store) ListAssistantMessages(sessionID string) ([]*AssistantMessage, error) {
	rows, err := s.db.Query(`
		SELECT id, session_id, role, content, tool_name, tool_args, created
		FROM assistant_messages WHERE session_id=? ORDER BY id
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AssistantMessage
	for rows.Next() {
		var m AssistantMessage
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Role, &m.Content, &m.ToolName, &m.ToolArgs, &m.Created); err != nil {
			return nil, err
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

// AssistantRetention purges transcripts older than the retention window
// (sessions cascade to their messages). Returns purged session count.
func (s *Store) AssistantRetention(days int64) (int64, error) {
	cutoff := now() - days*86400
	if _, err := s.db.Exec(`
		DELETE FROM assistant_messages WHERE session_id IN
		  (SELECT id FROM assistant_sessions WHERE updated < ?)
	`, cutoff); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM assistant_sessions WHERE updated < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// boolToInt is SQLite's INTEGER encoding of a bool.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
