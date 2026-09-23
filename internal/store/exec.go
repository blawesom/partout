package store

import (
	"database/sql"
	"errors"
)

// ---- Executions -----------------------------------------------------------

// Execution is a dispatched command or job run across hosts.
type Execution struct {
	ID        string
	Selector  string
	Cmd       string
	ArgsJSON  string // JSON array or ""
	Created   int64
	CreatedBy string
	State     string // pending|dispatching|running|succeeded|failed|partial|cancelled
}

// ExecutionRun is a single-host outcome for an execution.
type ExecutionRun struct {
	ID          string
	ExecutionID string
	AgentID     string
	State       string // queued|delivered|running|succeeded|failed|timed_out|cancelled|interrupted|not_delivered
	ExitCode    sql.NullInt32
	DurationMS  sql.NullInt64
	Created     int64
	Updated     int64
}

// OutputChunk is a streamed stdout/stderr chunk for a run.
type OutputChunk struct {
	RunID    string
	ChunkSeq int
	Stream   string // "stdout" | "stderr"
	Data     []byte
}

// ---- Audit ----------------------------------------------------------------

// AuditEvent is an append-only log entry.
type AuditEvent struct {
	TS      int64
	Kind    string
	Actor   string
	AgentID string
	Payload string // JSON
}

// ---- Execution CRUD -------------------------------------------------------

// CreateExecution creates a new execution row.
func (s *Store) CreateExecution(e Execution) error {
	if e.ID == "" {
		return errors.New("store: execution id required")
	}
	if e.Created == 0 {
		e.Created = now()
	}
	_, err := s.db.Exec(`
		INSERT INTO executions(id, selector, cmd, args_json, created, created_by, state)
		VALUES(?,?,?,?,?,?,?)
	`, e.ID, e.Selector, e.Cmd, e.ArgsJSON, e.Created, e.CreatedBy, e.State)
	return err
}

// GetExecution returns an execution by id.
func (s *Store) GetExecution(id string) (*Execution, error) {
	row := s.db.QueryRow(`
		SELECT id, selector, cmd, args_json, created, created_by, state
		FROM executions WHERE id = ?
	`, id)
	return scanExecution(row)
}

// ListExecutions returns recent executions (order: newest first).
func (s *Store) ListExecutions(limit int) ([]*Execution, error) {
	rows, err := s.db.Query(`
		SELECT id, selector, cmd, args_json, created, created_by, state
		FROM executions ORDER BY created DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Execution
	for rows.Next() {
		e, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateExecutionState updates an execution's state.
func (s *Store) UpdateExecutionState(id, state string) error {
	_, err := s.db.Exec(`UPDATE executions SET state=? WHERE id=?`, state, id)
	return err
}

func scanExecution(row interface{ Scan(...any) error }) (*Execution, error) {
	var e Execution
	var args sql.NullString
	if err := row.Scan(&e.ID, &e.Selector, &e.Cmd, &args, &e.Created,
		&sqlNullString{&e.CreatedBy}, &e.State); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	e.ArgsJSON = args.String
	return &e, nil
}

// ---- ExecutionRuns CRUD ---------------------------------------------------

// CreateExecutionRun creates a run row linked to an execution.
func (s *Store) CreateExecutionRun(r ExecutionRun) error {
	if r.ID == "" {
		return errors.New("store: execution_run id required")
	}
	if r.Created == 0 {
		r.Created = now()
	}
	r.Updated = r.Created
	_, err := s.db.Exec(`
		INSERT INTO execution_runs(id, execution_id, agent_id, state, exit_code, duration_ms, created, updated)
		VALUES(?,?,?,?,?,?,?,?)
	`, r.ID, r.ExecutionID, r.AgentID, r.State, r.ExitCode, r.DurationMS, r.Created, r.Updated)
	return err
}

// UpdateRunState sets a run's state, exit code, and duration.
func (s *Store) UpdateRunState(id, state string, exitCode int32, durationMS int64) error {
	// Guarded (architecture §3.3): a run in a terminal state other than
	// "interrupted" is not overwritten by a (possibly stale) update; "interrupted"
	// runs may be re-finalized by a replayed result after a disconnect. A
	// duplicate update with the same state is a no-op.
	_, err := s.db.Exec(`
		UPDATE execution_runs
		SET state=?, exit_code=?, duration_ms=?, updated=?
		WHERE id=? AND (state IN ('queued','delivered','running','interrupted') OR state=?)
	`, state, exitCode, durationMS, now(), id, state)
	return err
}

// InterruptAgentRuns marks the agent's in-flight runs (delivered/running)
// as interrupted (architecture §3.4: disconnect mid-command). Returns the
// distinct execution ids of affected runs, for aggregate recomputation.
func (s *Store) InterruptAgentRuns(agentID string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT id, execution_id FROM execution_runs
		WHERE agent_id=? AND state IN ('delivered','running')
	`, agentID)
	if err != nil {
		return nil, err
	}
	type ref struct{ runID, execID string }
	var refs []ref
	seen := make(map[string]bool)
	var execs []string
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.runID, &r.execID); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, r)
		if !seen[r.execID] {
			seen[r.execID] = true
			execs = append(execs, r.execID)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(refs) == 0 {
		return nil, nil
	}
	if _, err := s.db.Exec(`
		UPDATE execution_runs SET state='interrupted', updated=?
		WHERE agent_id=? AND state IN ('delivered','running')
	`, now(), agentID); err != nil {
		return nil, err
	}
	return execs, nil
}

// ExecutionIDForRun returns the execution id a run belongs to.
func (s *Store) ExecutionIDForRun(runID string) (string, error) {
	var execID string
	err := s.db.QueryRow(
		`SELECT execution_id FROM execution_runs WHERE id=?`, runID,
	).Scan(&execID)
	if err != nil {
		return "", err
	}
	return execID, nil
}

// ListRunsForExecution returns all runs for an execution, ordered by agent_id.
func (s *Store) ListRunsForExecution(executionID string) ([]*ExecutionRun, error) {
	rows, err := s.db.Query(`
		SELECT id, execution_id, agent_id, state, exit_code, duration_ms, created, updated
		FROM execution_runs WHERE execution_id = ? ORDER BY agent_id
	`, executionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ExecutionRun
	for rows.Next() {
		r := &ExecutionRun{}
		if err := rows.Scan(&r.ID, &r.ExecutionID, &r.AgentID, &r.State,
			&r.ExitCode, &r.DurationMS, &r.Created, &r.Updated); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Output chunks --------------------------------------------------------

// AppendOutput appends an output chunk to a run. Idempotent: replayed chunks
// (same run_id, chunk_seq) are no-ops (architecture §3.3: at-least-once up
// delivery, deduped by (run_id, chunk_seq)).
func (s *Store) AppendOutput(c OutputChunk) error {
	_, err := s.db.Exec(`
		INSERT INTO output_chunks(run_id, chunk_seq, stream, data, ts)
		VALUES(?,?,?,?,?)
		ON CONFLICT(run_id, chunk_seq) DO NOTHING
	`, c.RunID, c.ChunkSeq, c.Stream, c.Data, now())
	return err
}

// ListOutput returns all chunks for a run, ordered by seq.
func (s *Store) ListOutput(runID string) ([]*OutputChunk, error) {
	rows, err := s.db.Query(`
		SELECT chunk_seq, stream, data
		FROM output_chunks WHERE run_id=? ORDER BY chunk_seq
	`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OutputChunk
	for rows.Next() {
		c := &OutputChunk{RunID: runID}
		if err := rows.Scan(&c.ChunkSeq, &c.Stream, &c.Data); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- Audit ----------------------------------------------------------------

// AppendAudit appends an audit event (append-only, never updated).
func (s *Store) AppendAudit(a AuditEvent) error {
	_, err := s.db.Exec(`
		INSERT INTO audit_events(ts, kind, actor, agent_id, payload)
		VALUES(?,?,?,?,?)
	`, a.TS, a.Kind, a.Actor, a.AgentID, a.Payload)
	return err
}

// ListAudit returns audit events, optionally filtered by kind.
func (s *Store) ListAudit(kind string, limit int) ([]*AuditEvent, error) {
	var rows *sql.Rows
	var err error
	if kind == "" {
		rows, err = s.db.Query(`
			SELECT ts, kind, actor, agent_id, payload
			FROM audit_events ORDER BY ts DESC LIMIT ?
		`, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT ts, kind, actor, agent_id, payload
			FROM audit_events WHERE kind=? ORDER BY ts DESC LIMIT ?
		`, kind, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEvent
	for rows.Next() {
		a := &AuditEvent{}
		if err := rows.Scan(&a.TS, &a.Kind, &a.Actor, &a.AgentID, &a.Payload); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAuditSince returns audit events after the given timestamp.
func (s *Store) ListAuditSince(kind string, since int64, limit int) ([]*AuditEvent, error) {
	var rows *sql.Rows
	var err error
	if kind == "" {
		rows, err = s.db.Query(`
			SELECT ts, kind, actor, agent_id, payload
			FROM audit_events WHERE ts > ? ORDER BY ts DESC LIMIT ?
		`, since, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT ts, kind, actor, agent_id, payload
			FROM audit_events WHERE kind=? AND ts > ? ORDER BY ts DESC LIMIT ?
		`, kind, since, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEvent
	for rows.Next() {
		a := &AuditEvent{}
		if err := rows.Scan(&a.TS, &a.Kind, &a.Actor, &a.AgentID, &a.Payload); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
