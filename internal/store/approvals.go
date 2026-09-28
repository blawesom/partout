package store

import (
	"database/sql"
	"fmt"
)

// ---------------------------------------------------------------------------
// Approval requests (M4, PRD §5.8)
// ---------------------------------------------------------------------------

// ApprovalRequest is one pending (or decided) human approval for an exact
// action payload. Approvals are scoped to the exact payload, not a blanket
// allow: the payload JSON carries the full action (cmd+args+env for exec,
// the pkg op for packages, etc.) and only that action may ride on it.
type ApprovalRequest struct {
	ID             string `json:"id"`
	ActionClass    string `json:"action_class"`
	PayloadJSON    string `json:"payload_json"`
	AgentID        string `json:"agent_id"`
	ExecutionID    string `json:"execution_id,omitempty"`
	RunID          string `json:"run_id,omitempty"`
	Actor          string `json:"actor"`
	ActorRole      string `json:"actor_role"`
	MatchedRules   string `json:"matched_rules"` // comma-joined rule IDs
	State          string `json:"state"`         // pending | approved | denied | expired
	CreatedUnix    int64  `json:"created_unix"`
	ExpiresUnix    int64  `json:"expires_unix"`
	DecidedUnix    int64  `json:"decided_unix,omitempty"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecisionReason string `json:"decision_reason,omitempty"`
}

// CreateApprovalRequest inserts one pending approval request.
func (s *Store) CreateApprovalRequest(r *ApprovalRequest) error {
	if r.State == "" {
		r.State = "pending"
	}
	if r.CreatedUnix == 0 {
		r.CreatedUnix = now()
	}
	if _, err := s.db.Exec(`
		INSERT INTO approval_requests
		(id, action_class, payload_json, agent_id, execution_id, run_id,
		 actor, actor_role, matched_rules, state, created_unix, expires_unix)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
	`, r.ID, r.ActionClass, r.PayloadJSON, r.AgentID, r.ExecutionID, r.RunID,
		r.Actor, r.ActorRole, r.MatchedRules, r.State, r.CreatedUnix, r.ExpiresUnix); err != nil {
		return fmt.Errorf("store: create approval request: %w", err)
	}
	return nil
}

// GetApprovalRequest returns one request by ID (nil when absent).
func (s *Store) GetApprovalRequest(id string) (*ApprovalRequest, error) {
	row := s.db.QueryRow(`
		SELECT id, action_class, payload_json, agent_id, execution_id, run_id,
			actor, actor_role, matched_rules, state, created_unix, expires_unix,
			decided_unix, decided_by, decision_reason
		FROM approval_requests WHERE id=?`, id)
	r, err := scanApprovalRequest(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get approval request: %w", err)
	}
	return r, nil
}

// scanApprovalRequest scans one approval row (decided_* columns may be NULL
// for pending requests).
func scanApprovalRequest(row interface{ Scan(...any) error }) (*ApprovalRequest, error) {
	var r ApprovalRequest
	var decidedUnix sql.NullInt64
	var decidedBy, reason sql.NullString
	if err := row.Scan(&r.ID, &r.ActionClass, &r.PayloadJSON, &r.AgentID,
		&r.ExecutionID, &r.RunID, &r.Actor, &r.ActorRole, &r.MatchedRules,
		&r.State, &r.CreatedUnix, &r.ExpiresUnix, &decidedUnix,
		&decidedBy, &reason); err != nil {
		return nil, err
	}
	if decidedUnix.Valid {
		r.DecidedUnix = decidedUnix.Int64
	}
	if decidedBy.Valid {
		r.DecidedBy = decidedBy.String
	}
	if reason.Valid {
		r.DecisionReason = reason.String
	}
	return &r, nil
}

// ListApprovalRequests lists requests, optionally filtered by state
// ("" = all), most recent first. Pending requests past their expiry are
// lazily marked expired before listing.
func (s *Store) ListApprovalRequests(state string, limit int) ([]*ApprovalRequest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if _, err := s.ExpireApprovalRequests(); err != nil {
		return nil, err
	}
	query := `
		SELECT id, action_class, payload_json, agent_id, execution_id, run_id,
			actor, actor_role, matched_rules, state, created_unix, expires_unix,
			decided_unix, decided_by, decision_reason
		FROM approval_requests`
	var args []any
	if state != "" {
		query += ` WHERE state=?`
		args = append(args, state)
	}
	query += ` ORDER BY created_unix DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list approval requests: %w", err)
	}
	defer rows.Close()
	var out []*ApprovalRequest
	for rows.Next() {
		r, err := scanApprovalRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan approval request: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ExpireApprovalRequests marks pending requests past their expiry as
// expired and returns the expired rows (so callers can finalize parked
// runs). Returns nil when nothing expired.
func (s *Store) ExpireApprovalRequests() ([]*ApprovalRequest, error) {
	rows, err := s.db.Query(`
		SELECT id, action_class, payload_json, agent_id, execution_id, run_id,
			actor, actor_role, matched_rules, created_unix, expires_unix
		FROM approval_requests WHERE state='pending' AND expires_unix <= ?`, now())
	if err != nil {
		return nil, fmt.Errorf("store: select expired approvals: %w", err)
	}
	var pending []*ApprovalRequest
	for rows.Next() {
		var r ApprovalRequest
		if err := rows.Scan(&r.ID, &r.ActionClass, &r.PayloadJSON, &r.AgentID,
			&r.ExecutionID, &r.RunID, &r.Actor, &r.ActorRole, &r.MatchedRules,
			&r.CreatedUnix, &r.ExpiresUnix); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan expired approval: %w", err)
		}
		pending = append(pending, &r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store: iterate expired approvals: %w", err)
	}
	rows.Close()
	if len(pending) == 0 {
		return nil, nil
	}
	// Update after the rows are fully consumed and closed (single-connection
	// SQLite cannot interleave Exec with an open result set).
	var out []*ApprovalRequest
	for _, r := range pending {
		if _, err := s.db.Exec(`
			UPDATE approval_requests
			SET state='expired', decided_unix=?, decision_reason='expired before decision'
			WHERE id=? AND state='pending'
		`, now(), r.ID); err != nil {
			return nil, fmt.Errorf("store: expire approval %s: %w", r.ID, err)
		}
		r.State = "expired"
		out = append(out, r)
	}
	return out, nil
}

// DecideApprovalRequest transitions a pending request to approved/denied.
// It is a no-op error when the request is not pending (already decided or
// expired) — an expired approval can never be retroactively honored.
func (s *Store) DecideApprovalRequest(id, state, decidedBy, reason string) error {
	if state != "approved" && state != "denied" {
		return fmt.Errorf("store: invalid approval state %q", state)
	}
	res, err := s.db.Exec(`
		UPDATE approval_requests
		SET state=?, decided_unix=?, decided_by=?, decision_reason=?
		WHERE id=? AND state='pending'
	`, state, now(), decidedBy, reason, id)
	if err != nil {
		return fmt.Errorf("store: decide approval request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: approval request %s not pending (already decided or expired)", id)
	}
	return nil
}

// SetApprovalExpiryForTest moves a request's expiry to an absolute unix time
// (tests only: fast-forward expiry without sleeping).
func (s *Store) SetApprovalExpiryForTest(id string, expiresUnix int64) error {
	res, err := s.db.Exec(`UPDATE approval_requests SET expires_unix=? WHERE id=?`, expiresUnix, id)
	if err != nil {
		return fmt.Errorf("store: set approval expiry: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: approval request %s not found", id)
	}
	return nil
}
