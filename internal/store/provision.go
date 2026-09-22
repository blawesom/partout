package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// ProvisionRun is one host-provisioning attempt (architecture §3.5).
type ProvisionRun struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Mode        string `json:"mode"` // fresh | update
	State       string `json:"state"`
	KeyType     string `json:"key_type,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyLine     string `json:"-"` // host key material — never serialized
	TokenHash   string `json:"-"` // enrollment token hash — never serialized
	AgentID     string `json:"agent_id,omitempty"`
	Step        string `json:"step,omitempty"`
	Error       string `json:"error,omitempty"`
	Created     int64  `json:"created"`
	Updated     int64  `json:"updated"`
}

// ProvisionStep is one step within a run.
type ProvisionStep struct {
	RunID         string `json:"run_id"`
	Seq           int    `json:"seq"`
	Name          string `json:"name"`
	State         string `json:"state"`
	StdoutExcerpt string `json:"stdout_excerpt,omitempty"`
	StderrExcerpt string `json:"stderr_excerpt,omitempty"`
	Started       int64  `json:"started,omitempty"`
	Finished      int64  `json:"finished,omitempty"`
}

// ExcerptCap bounds captured output stored per step (arch §3.5: "bounded
// output excerpt").
const ExcerptCap = 4096

// CapExcerpt truncates a string to ExcerptCap, appending a marker.
func CapExcerpt(s string) string {
	if len(s) <= ExcerptCap {
		return s
	}
	return s[:ExcerptCap] + "…[truncated]"
}

// CreateProvisionRun inserts a new run (already in queued state).
func (s *Store) CreateProvisionRun(r ProvisionRun) error {
	_, err := s.db.Exec(
		`INSERT INTO provision_runs(id, host, mode, state, key_type, fingerprint, key_line, token_hash, agent_id, step, error, created, updated)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Host, r.Mode, r.State, nullStr(r.KeyType), nullStr(r.Fingerprint), nullStr(r.KeyLine), nullStr(r.TokenHash), nullStr(r.AgentID), nullStr(r.Step), nullStr(r.Error), r.Created, r.Updated,
	)
	return err
}

// SetProvisionRunState sets state (and optionally step/error) and bumps updated.
func (s *Store) SetProvisionRunState(id, state, step, errText string) error {
	res, err := s.db.Exec(
		`UPDATE provision_runs SET state=?, step=COALESCE(?, step), error=COALESCE(?, error), updated=? WHERE id=?`,
		state, nullStrOrNil(step), nullStrOrNil(errText), now(), id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("provision: run %s not found", id)
	}
	return nil
}

// SetProvisionRunKey stores the captured host key material for a run.
func (s *Store) SetProvisionRunKey(id, keyType, fingerprint, keyLine string) error {
	_, err := s.db.Exec(
		`UPDATE provision_runs SET key_type=?, fingerprint=?, key_line=?, updated=? WHERE id=?`,
		keyType, fingerprint, keyLine, now(), id,
	)
	return err
}

// SetProvisionRunToken links a one-time enrollment token to a run.
func (s *Store) SetProvisionRunToken(runID, tokenHash string) error {
	_, err := s.db.Exec(`UPDATE provision_runs SET token_hash=?, updated=? WHERE id=?`, tokenHash, now(), runID)
	return err
}

// LinkProvisionRunAgent records the agent id a run produced.
func (s *Store) LinkProvisionRunAgent(runID, agentID string) error {
	_, err := s.db.Exec(`UPDATE provision_runs SET agent_id=?, updated=? WHERE id=?`, agentID, now(), runID)
	return err
}

// ProvisionRunForToken returns the run id that owns the given token hash
// (used by the enroll handler to link a fresh agent to its run).
func (s *Store) ProvisionRunForToken(tokenHash string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM provision_runs WHERE token_hash=?`, tokenHash).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

// ProvisionRun returns one run by id.
func (s *Store) ProvisionRun(id string) (*ProvisionRun, error) {
	return scanProvisionRun(s.db.QueryRow(
		`SELECT id, host, mode, state, key_type, fingerprint, key_line, token_hash, agent_id, step, error, created, updated
		 FROM provision_runs WHERE id=?`, id))
}

// ProvisionRuns lists runs, newest first.
func (s *Store) ProvisionRuns(limit int) ([]*ProvisionRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, host, mode, state, key_type, fingerprint, key_line, token_hash, agent_id, step, error, created, updated
		 FROM provision_runs ORDER BY created DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProvisionRun
	for rows.Next() {
		r, err := scanProvisionRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ProvisionRunSteps returns the steps for a run in sequence order.
func (s *Store) ProvisionRunSteps(runID string) ([]*ProvisionStep, error) {
	rows, err := s.db.Query(
		`SELECT run_id, seq, name, state, stdout_excerpt, stderr_excerpt, started, finished
		 FROM provision_steps WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProvisionStep
	for rows.Next() {
		st := &ProvisionStep{}
		var stdout, stderr sql.NullString
		var started, finished sql.NullInt64
		if err := rows.Scan(&st.RunID, &st.Seq, &st.Name, &st.State, &stdout, &stderr, &started, &finished); err != nil {
			return nil, err
		}
		st.StdoutExcerpt = stdout.String
		st.StderrExcerpt = stderr.String
		if started.Valid {
			st.Started = started.Int64
		}
		if finished.Valid {
			st.Finished = finished.Int64
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// CreateProvisionStep inserts a step in pending state.
func (s *Store) CreateProvisionStep(runID string, seq int, name string) error {
	_, err := s.db.Exec(
		`INSERT INTO provision_steps(run_id, seq, name, state) VALUES(?,?,?,?)`,
		runID, seq, name, "pending",
	)
	return err
}

// StartProvisionStep marks a step running with a start timestamp.
func (s *Store) StartProvisionStep(runID string, seq int) error {
	_, err := s.db.Exec(`UPDATE provision_steps SET state='running', started=? WHERE run_id=? AND seq=?`, now(), runID, seq)
	return err
}

// FinishProvisionStep marks a step done/failed with bounded excerpts and end ts.
func (s *Store) FinishProvisionStep(runID string, seq int, state, stdoutExcerpt, stderrExcerpt string) error {
	_, err := s.db.Exec(
		`UPDATE provision_steps SET state=?, stdout_excerpt=?, stderr_excerpt=?, finished=? WHERE run_id=? AND seq=?`,
		state, CapExcerpt(stdoutExcerpt), CapExcerpt(stderrExcerpt), now(), runID, seq,
	)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanProvisionRun(r rowScanner) (*ProvisionRun, error) {
	pr := &ProvisionRun{}
	var keyType, fingerprint, keyLine, tokenHash, agentID, step, errText sql.NullString
	if err := r.Scan(&pr.ID, &pr.Host, &pr.Mode, &pr.State, &keyType, &fingerprint, &keyLine, &tokenHash, &agentID, &step, &errText, &pr.Created, &pr.Updated); err != nil {
		return nil, err
	}
	pr.KeyType = keyType.String
	pr.Fingerprint = fingerprint.String
	pr.KeyLine = keyLine.String
	pr.TokenHash = tokenHash.String
	pr.AgentID = agentID.String
	pr.Step = step.String
	pr.Error = errText.String
	return pr, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullStrOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// NewEnrollmentToken generates a one-time enrollment token, stores its hash,
// and returns the cleartext (shown/used once). The plaintext is never stored.
func (s *Store) NewEnrollmentToken(ttlS int) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plain := "par_enr_" + hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plain))
	hashHex := hex.EncodeToString(hash[:])
	mask := plain[:14]
	if err := s.CreateEnrollmentToken(hashHex, mask, ttlS); err != nil {
		return "", err
	}
	return plain, nil
}
