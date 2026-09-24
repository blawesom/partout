package store

import (
	"database/sql"
	"errors"
)

// ---- Files (M2, PRD §5.3) -------------------------------------------------

// FileAction is an audit row for one file operation (PRD §5.3, §10).
type FileAction struct {
	ID      string
	AgentID string
	Op      string // stat|list|download|upload|edit|perm (column: kind)
	OpID    string // agent-side op id(s); joined with "+" for uploads
	Path    string
	Actor   string
	State   string // ok|denied|error
	Code    int32
	Size    sql.NullInt64
	SHA256  string
	Error   string
	Created int64
}

// InsertFileAction records one file operation.
func (s *Store) InsertFileAction(f FileAction) error {
	if f.ID == "" {
		return errors.New("store: file action id required")
	}
	if f.Created == 0 {
		f.Created = now()
	}
	_, err := s.db.Exec(`
		INSERT INTO files_actions (id, agent_id, kind, op_id, path, actor, state, code, size, sha256, error, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.AgentID, f.Op, f.OpID, f.Path, f.Actor, f.State, f.Code, f.Size, f.SHA256, f.Error, f.Created,
	)
	return err
}

// ---- Sessions (M2, PRD §5.2.2) --------------------------------------------

// Session is an interactive PTY session (PRD §5.2.2).
type Session struct {
	ID       string
	AgentID  string
	Cmd      string
	ArgsJSON string
	Cols     int32
	Rows     int32
	Record   bool
	State    string // open|closed|interrupted|denied|failed
	ExitCode sql.NullInt32
	Error    string
	Actor    string
	Opened   int64
	Closed   sql.NullInt64
}

// CreateSession inserts a new session row (state=open).
func (s *Store) CreateSession(sess Session) error {
	if sess.ID == "" {
		return errors.New("store: session id required")
	}
	if sess.Opened == 0 {
		sess.Opened = now()
	}
	if sess.State == "" {
		sess.State = "open"
	}
	_, err := s.db.Exec(`
		INSERT INTO sessions (id, agent_id, cmd, args_json, cols, rows, record, state, exit_code, error, actor, opened, closed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		sess.ID, sess.AgentID, sess.Cmd, sess.ArgsJSON, sess.Cols, sess.Rows,
		boolInt(sess.Record), sess.State, sess.ExitCode, sess.Error, sess.Actor, sess.Opened,
	)
	return err
}

// UpdateSessionState sets a session's terminal state + exit code + closed ts.
func (s *Store) UpdateSessionState(id, state string, exitCode int32, errMsg string) error {
	closed := now()
	_, err := s.db.Exec(`
		UPDATE sessions SET state = ?, exit_code = ?, error = ?, closed = ? WHERE id = ?`,
		state, exitCode, errMsg, closed, id,
	)
	return err
}

// GetSession fetches a session by id.
func (s *Store) GetSession(id string) (*Session, error) {
	row := s.db.QueryRow(`
		SELECT id, agent_id, cmd, args_json, cols, rows, record, state, exit_code, error, actor, opened, closed
		FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

// ListSessions returns sessions for an agent (newest first), or all if agentID is "".
func (s *Store) ListSessions(agentID string, limit int) ([]*Session, error) {
	q := `SELECT id, agent_id, cmd, args_json, cols, rows, record, state, exit_code, error, actor, opened, closed
	      FROM sessions`
	var args []any
	if agentID != "" {
		q += ` WHERE agent_id = ?`
		args = append(args, agentID)
	}
	q += ` ORDER BY opened DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// AppendSessionRecord stores one PTY output chunk for replay (PRD §9: 30 d).
func (s *Store) AppendSessionRecord(sessionID string, seq int, data []byte) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO session_records (session_id, seq, data) VALUES (?, ?, ?)`,
		sessionID, seq, data,
	)
	return err
}

// ListSessionRecords returns recorded chunks in seq order (replay).
func (s *Store) ListSessionRecords(sessionID string) ([]SessionRecord, error) {
	rows, err := s.db.Query(`
		SELECT seq, data FROM session_records WHERE session_id = ? ORDER BY seq ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRecord
	for rows.Next() {
		var r SessionRecord
		if err := rows.Scan(&r.Seq, &r.Data); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SessionRecord is one captured PTY chunk.
type SessionRecord struct {
	Seq  int
	Data []byte
}

// DeleteSessionRecordsOlderThan purges recordings past the retention window
// (PRD §9: 30 days). Returns the number of rows removed.
func (s *Store) DeleteSessionRecordsOlderThan(before int64) (int64, error) {
	res, err := s.db.Exec(`
		DELETE FROM session_records WHERE session_id IN (
			SELECT id FROM sessions WHERE closed IS NOT NULL AND closed < ?
		)`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InterruptAgentSessions marks all open sessions for an agent as interrupted
// (D2: stream disconnect kills the PTY; server records it).
func (s *Store) InterruptAgentSessions(agentID string) (int64, error) {
	closed := now()
	res, err := s.db.Exec(`
		UPDATE sessions SET state = 'interrupted', closed = ?
		WHERE agent_id = ? AND state = 'open'`, closed, agentID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- helpers ---------------------------------------------------------------

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var record int
	var closed sql.NullInt64
	err := row.Scan(&s.ID, &s.AgentID, &s.Cmd, &s.ArgsJSON, &s.Cols, &s.Rows, &record,
		&s.State, &s.ExitCode, &s.Error, &s.Actor, &s.Opened, &closed)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.Record = record == 1
	s.Closed = closed
	return &s, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}