// tasks.go — M3 tasks, task versions, runs, steps, and playbooks
// (PRD §5.5). Versioned, idempotent step lists; run state machine
// pending→running→{ok,changed,failed,skipped} per step; run-level
// running→{succeeded,failed,interrupted}.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Task is the server-side record for a task (ordered, idempotent step list).
type Task struct {
	ID          string
	Name        string
	Description string
	Created     int64
	Updated     int64
}

// TaskVersion is one immutable version of a task's step list.
type TaskVersion struct {
	TaskID    string
	Version   int
	StepsJSON string // JSON []TaskStep
	Created   int64
}

// TaskRun is one execution of a task version on one host.
type TaskRun struct {
	ID          string
	TaskID      string
	TaskVersion int
	AgentID     string
	State       string // running | succeeded | failed | interrupted
	Started     int64
	Finished    int64
	Error       string
}

// TaskRunStep is one step within a task run.
type TaskRunStep struct {
	RunID    string
	StepIdx  int
	Kind     string // command|file|package|service|user|group|template|assert|reboot
	Name     string
	State    string // pending|running|ok|changed|failed|skipped
	Detail   string
	Started  int64
	Finished int64
}

// Playbook is a named (task, version, selector) triple.
type Playbook struct {
	ID          string
	Name        string
	TaskID      string
	TaskVersion int
	Selector    string
	Created     int64
}

// --- tasks ---

// CreateTask inserts a new task.
func (s *Store) CreateTask(t *Task) error {
	if t.Created == 0 {
		t.Created = time.Now().Unix()
	}
	t.Updated = t.Created
	_, err := s.db.Exec(`INSERT INTO tasks (id, name, description, created, updated) VALUES (?,?,?,?,?)`,
		t.ID, t.Name, t.Description, t.Created, t.Updated)
	if err != nil {
		return fmt.Errorf("store: create task: %w", err)
	}
	return nil
}

// Task returns a task by ID.
func (s *Store) Task(id string) (*Task, error) {
	row := s.db.QueryRow(`SELECT id, name, description, created, updated FROM tasks WHERE id=?`, id)
	return scanTask(row)
}

// TaskByName returns a task by name.
func (s *Store) TaskByName(name string) (*Task, error) {
	row := s.db.QueryRow(`SELECT id, name, description, created, updated FROM tasks WHERE name=?`, name)
	return scanTask(row)
}

// ListTasks lists tasks, newest first.
func (s *Store) ListTasks(limit int) ([]*Task, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, name, description, created, updated FROM tasks ORDER BY updated DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list tasks: %w", err)
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanTask(row scanRow) (*Task, error) {
	var t Task
	if err := row.Scan(&t.ID, &t.Name, &t.Description, &t.Created, &t.Updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: scan task: %w", err)
	}
	return &t, nil
}

// --- task versions ---

// UpsertTaskVersion inserts a new version (immutable; callers bump version).
func (s *Store) UpsertTaskVersion(v *TaskVersion) error {
	if v.Created == 0 {
		v.Created = time.Now().Unix()
	}
	_, err := s.db.Exec(`INSERT INTO task_versions (task_id, version, steps_json, created) VALUES (?,?,?,?)`,
		v.TaskID, v.Version, v.StepsJSON, v.Created)
	if err != nil {
		return fmt.Errorf("store: upsert task version: %w", err)
	}
	_, _ = s.db.Exec(`UPDATE tasks SET updated=? WHERE id=?`, v.Created, v.TaskID)
	return nil
}

// LatestTaskVersion returns the highest version of a task.
func (s *Store) LatestTaskVersion(taskID string) (*TaskVersion, error) {
	row := s.db.QueryRow(`SELECT task_id, version, steps_json, created FROM task_versions WHERE task_id=? ORDER BY version DESC LIMIT 1`, taskID)
	return scanTaskVersion(row)
}

// TaskVersion returns one specific version of a task (nil, nil if absent).
func (s *Store) TaskVersion(taskID string, version int) (*TaskVersion, error) {
	row := s.db.QueryRow(`SELECT task_id, version, steps_json, created FROM task_versions WHERE task_id=? AND version=?`, taskID, version)
	return scanTaskVersion(row)
}

// TaskVersions returns all versions of a task, ascending.
func (s *Store) TaskVersions(taskID string) ([]*TaskVersion, error) {
	rows, err := s.db.Query(`SELECT task_id, version, steps_json, created FROM task_versions WHERE task_id=? ORDER BY version ASC`, taskID)
	if err != nil {
		return nil, fmt.Errorf("store: task versions: %w", err)
	}
	defer rows.Close()
	var out []*TaskVersion
	for rows.Next() {
		v, err := scanTaskVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanTaskVersion(row scanRow) (*TaskVersion, error) {
	var v TaskVersion
	if err := row.Scan(&v.TaskID, &v.Version, &v.StepsJSON, &v.Created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: scan task version: %w", err)
	}
	return &v, nil
}

// DecodeTaskSteps parses the steps_json of a task version.
func DecodeTaskSteps(stepsJSON string) ([]TaskStep, error) {
	var steps []TaskStep
	if err := json.Unmarshal([]byte(stepsJSON), &steps); err != nil {
		return nil, fmt.Errorf("store: decode task steps: %w", err)
	}
	return steps, nil
}

// TaskStep is one intent-based step in a task (PRD §5.5). It is JSON-encoded
// in task_versions.steps_json. `When` is a constrained fact expression
// (not free-form code); a false guard yields state "skipped".
type TaskStep struct {
	Kind     string            `json:"kind"`               // command|file|package|service|user|group|template|assert|reboot
	Name     string            `json:"name,omitempty"`     // display name
	When     string            `json:"when,omitempty"`     // constrained fact expression
	Command  string            `json:"command,omitempty"`  // for kind=command
	Args     []string          `json:"args,omitempty"`     // for kind=command
	Env      map[string]string `json:"env,omitempty"`      // for kind=command
	Path     string            `json:"path,omitempty"`     // for kind=file|template
	Content  string            `json:"content,omitempty"`  // for kind=file
	Template string            `json:"template,omitempty"` // for kind=template
	Vars     map[string]string `json:"vars,omitempty"`     // for kind=template
	Mode     string            `json:"mode,omitempty"`     // for kind=file
	Package  string            `json:"package,omitempty"`  // for kind=package
	State    string            `json:"state,omitempty"`    // for kind=package|service|user|group (installed|absent, running|stopped)
	Service  string            `json:"service,omitempty"`  // for kind=service
	User     string            `json:"user,omitempty"`     // for kind=user
	Group    string            `json:"group,omitempty"`    // for kind=group
	Expr     string            `json:"expr,omitempty"`     // for kind=assert (fact expression)
}

// --- task runs ---

// CreateTaskRun inserts a new task run (state=running).
func (s *Store) CreateTaskRun(r *TaskRun) error {
	if r.Started == 0 {
		r.Started = time.Now().Unix()
	}
	_, err := s.db.Exec(`INSERT INTO task_runs (id, task_id, task_version, agent_id, state, started, error) VALUES (?,?,?,?,?,?,?)`,
		r.ID, r.TaskID, r.TaskVersion, r.AgentID, "running", r.Started, r.Error)
	if err != nil {
		return fmt.Errorf("store: create task run: %w", err)
	}
	return nil
}

// FinalizeTaskRun marks a run succeeded/failed/interrupted.
func (s *Store) FinalizeTaskRun(id, state, errMsg string, finished int64) error {
	if finished == 0 {
		finished = time.Now().Unix()
	}
	res, err := s.db.Exec(`UPDATE task_runs SET state=?, error=?, finished=? WHERE id=?`,
		state, errMsg, finished, id)
	if err != nil {
		return fmt.Errorf("store: finalize task run: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("store: task run not found")
	}
	return nil
}

// TaskRun returns one run by ID.
func (s *Store) TaskRun(id string) (*TaskRun, error) {
	row := s.db.QueryRow(`SELECT id, task_id, task_version, agent_id, state, started, finished, error FROM task_runs WHERE id=?`, id)
	return scanTaskRun(row)
}

// TaskRunsForHost returns recent runs for one host.
func (s *Store) TaskRunsForHost(agentID string, limit int) ([]*TaskRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT id, task_id, task_version, agent_id, state, started, finished, error FROM task_runs WHERE agent_id=? ORDER BY started DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: task runs for host: %w", err)
	}
	defer rows.Close()
	var out []*TaskRun
	for rows.Next() {
		r, err := scanTaskRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanTaskRun(row scanRow) (*TaskRun, error) {
	var r TaskRun
	var finished int64
	var errMsg *string
	if err := row.Scan(&r.ID, &r.TaskID, &r.TaskVersion, &r.AgentID, &r.State, &r.Started, &finished, &errMsg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: scan task run: %w", err)
	}
	r.Finished = finished
	if errMsg != nil {
		r.Error = *errMsg
	}
	return &r, nil
}

// ListTaskRuns lists task runs across all hosts, most recent first.
func (s *Store) ListTaskRuns(limit int) ([]*TaskRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, task_id, task_version, agent_id, state, started, finished, error FROM task_runs ORDER BY started DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list task runs: %w", err)
	}
	defer rows.Close()
	var out []*TaskRun
	for rows.Next() {
		r, err := scanTaskRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordTaskRunStep inserts or replaces one step result.
func (s *Store) RecordTaskRunStep(step *TaskRunStep) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO task_run_steps (run_id, step_index, kind, name, state, detail, started, finished) VALUES (?,?,?,?,?,?,?,?)`,
		step.RunID, step.StepIdx, step.Kind, step.Name, step.State, step.Detail, step.Started, step.Finished)
	if err != nil {
		return fmt.Errorf("store: record task run step: %w", err)
	}
	return nil
}

// TaskRunSteps returns all steps for a run, in order.
func (s *Store) TaskRunSteps(runID string) ([]*TaskRunStep, error) {
	rows, err := s.db.Query(`SELECT run_id, step_index, kind, name, state, detail, started, finished FROM task_run_steps WHERE run_id=? ORDER BY step_index ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("store: task run steps: %w", err)
	}
	defer rows.Close()
	var out []*TaskRunStep
	for rows.Next() {
		s2, err := scanTaskRunStep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s2)
	}
	return out, rows.Err()
}

func scanTaskRunStep(row scanRow) (*TaskRunStep, error) {
	var s TaskRunStep
	if err := row.Scan(&s.RunID, &s.StepIdx, &s.Kind, &s.Name, &s.State, &s.Detail, &s.Started, &s.Finished); err != nil {
		return nil, fmt.Errorf("store: scan task run step: %w", err)
	}
	return &s, nil
}

// --- playbooks ---

// CreatePlaybook inserts a playbook.
func (s *Store) CreatePlaybook(p *Playbook) error {
	if p.Created == 0 {
		p.Created = time.Now().Unix()
	}
	_, err := s.db.Exec(`INSERT INTO playbooks (id, name, task_id, task_version, selector, created) VALUES (?,?,?,?,?,?)`,
		p.ID, p.Name, p.TaskID, p.TaskVersion, p.Selector, p.Created)
	if err != nil {
		return fmt.Errorf("store: create playbook: %w", err)
	}
	return nil
}

// ListPlaybooks lists all playbooks.
func (s *Store) Playbook(id string) (*Playbook, error) {
	row := s.db.QueryRow(`SELECT id, name, task_id, task_version, selector, created FROM playbooks WHERE id = ?`, id)
	var p Playbook
	if err := row.Scan(&p.ID, &p.Name, &p.TaskID, &p.TaskVersion, &p.Selector, &p.Created); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("store: playbook: %w", err)
	}
	return &p, nil
}

func (s *Store) ListPlaybooks() ([]*Playbook, error) {
	rows, err := s.db.Query(`SELECT id, name, task_id, task_version, selector, created FROM playbooks ORDER BY created DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list playbooks: %w", err)
	}
	defer rows.Close()
	var out []*Playbook
	for rows.Next() {
		var p Playbook
		if err := rows.Scan(&p.ID, &p.Name, &p.TaskID, &p.TaskVersion, &p.Selector, &p.Created); err != nil {
			return nil, fmt.Errorf("store: scan playbook: %w", err)
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// isUniqueErr reports a SQLite/Postgres unique-constraint violation.
func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint") || strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key")
}

// scanRow is satisfied by both *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}
