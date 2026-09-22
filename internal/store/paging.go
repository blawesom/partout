package store

import (
	"database/sql"
	"errors"
	"strings"
)

// ---- Keyset pagination (cursor = last item id, newest-first) --------------
//
// Conventions (PRD R10 / arch §10.1): list endpoints accept ?cursor= and
// return {items, next_cursor}. Cursor is the id of the last item; the next
// page is WHERE id < cursor ORDER BY id DESC LIMIT n.

// HostPage is a page of agents.
func (s *Store) HostsPage(limit int, cursor string) ([]*Agent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, uuid, ed25519_pub, x25519_pub, version, state,
	       COALESCE(first_seen,0), COALESCE(last_seen,0), created
	       FROM agents`
	args := []any{}
	if cursor != "" {
		q += ` WHERE id < ?`
		args = append(args, cursor)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ExecutionsPage is a page of executions.
func (s *Store) ExecutionsPage(limit int, cursor string) ([]*Execution, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, selector, cmd, args_json, created, created_by, state
	       FROM executions`
	args := []any{}
	if cursor != "" {
		q += ` WHERE id < ?`
		args = append(args, cursor)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
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

// AuditPage is a page of audit events (keyset on autoincrement id).
func (s *Store) AuditPage(kind, actor string, since int64, limit int, cursor int64) ([]*AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var conds []string
	var args []any
	if kind != "" {
		conds = append(conds, "kind=?")
		args = append(args, kind)
	}
	if actor != "" {
		conds = append(conds, "actor=?")
		args = append(args, actor)
	}
	if since > 0 {
		conds = append(conds, "ts > ?")
		args = append(args, since)
	}
	if cursor > 0 {
		conds = append(conds, "id < ?")
		args = append(args, cursor)
	}
	q := `SELECT id, ts, kind, actor, agent_id, payload FROM audit_events`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEvent
	for rows.Next() {
		a := &AuditEvent{}
		var id int64
		var agent sql.NullString
		if err := rows.Scan(&id, &a.TS, &a.Kind, &a.Actor, &agent, &a.Payload); err != nil {
			return nil, err
		}
		a.AgentID = agent.String
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- Run lifecycle helpers -------------------------------------------------

// PromoteRunToRunning moves a run from "delivered" to "running" (idempotent).
func (s *Store) PromoteRunToRunning(id string) error {
	_, err := s.db.Exec(`
		UPDATE execution_runs SET state='running', updated=?
		WHERE id=? AND state='delivered'
	`, now(), id)
	return err
}

// CancelNonTerminalRuns marks all non-terminal runs of an execution as
// cancelled. Returns the count of runs changed.
func (s *Store) CancelNonTerminalRuns(executionID string) (int64, error) {
	res, err := s.db.Exec(`
		UPDATE execution_runs SET state='cancelled', updated=?
		WHERE execution_id=? AND state IN ('queued','delivered','running')
	`, now(), executionID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// TerminalStates are run states that will not change further.
var terminalStates = map[string]bool{
	"succeeded": true, "failed": true, "timed_out": true,
	"cancelled": true, "interrupted": true, "not_delivered": true,
	"denied": true,
}

// IsTerminalRun reports whether a run state is final.
func IsTerminalRun(state string) bool { return terminalStates[state] }

var _ = errors.New
