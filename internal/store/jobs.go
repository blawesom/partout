package store

import (
	"database/sql"
	"fmt"
)

// ---------------------------------------------------------------------------
// Scheduled jobs (M3, PRD §5.4)
// ---------------------------------------------------------------------------

// Job is a scheduled task on one or more hosts.
type Job struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	TaskID        string `json:"task_id"`
	TaskVersion   int    `json:"task_version"`
	Cron          string `json:"cron"`        // cron expression (5 fields) or @daily/@weekly/@monthly
	Selector      string `json:"selector"`    // host selector
	MaxRunSeconds int    `json:"max_run_s"`   // per-run deadline (0 = 30 min)
	Enabled       bool   `json:"enabled"`
	Created       int64  `json:"created"`
	Updated       int64  `json:"updated"`
}

// JobAssignment binds a job to one agent (host).
type JobAssignment struct {
	JobID       string `json:"job_id"`
	AgentID     string `json:"agent_id"`
	AssignedAt  int64  `json:"assigned_at"`
	LastRunAt   int64  `json:"last_run_at"`
	LastRunState string `json:"last_run_state"`
}

// JobRun is one scheduled execution.
type JobRun struct {
	ID          string `json:"id"`
	JobID       string `json:"job_id"`
	AgentID     string `json:"agent_id"`
	TaskID      string `json:"task_id"`
	TaskVersion int    `json:"task_version"`
	ScheduledAt int64  `json:"scheduled_at"`
	StartedAt   int64  `json:"started_at"`
	FinishedAt  int64  `json:"finished_at"`
	State       string `json:"state"` // pending, running, succeeded, failed, timeout
	Trigger     string `json:"trigger"` // cron, manual, resume
	Error       string `json:"error"`
}

// CreateJob inserts a new job.
func (s *Store) CreateJob(j *Job) error {
	if j.Created == 0 {
		j.Created = now()
	}
	j.Updated = now()
	if _, err := s.db.Exec(`
		INSERT INTO jobs (id, name, task_id, task_version, cron, selector, max_run_s, enabled, created, updated)
		VALUES (?,?,?,?,?,?,?,?,?,?)
	`, j.ID, j.Name, j.TaskID, j.TaskVersion, j.Cron, j.Selector, j.MaxRunSeconds, j.Enabled, j.Created, j.Updated); err != nil {
		return fmt.Errorf("store: create job: %w", err)
	}
	return nil
}

// UpdateJob modifies a job.
func (s *Store) UpdateJob(j *Job) error {
	j.Updated = now()
	res, err := s.db.Exec(`
		UPDATE jobs SET name=?, task_id=?, task_version=?, cron=?, selector=?, max_run_s=?, enabled=?
		WHERE id=?
	`, j.Name, j.TaskID, j.TaskVersion, j.Cron, j.Selector, j.MaxRunSeconds, j.Enabled, j.ID)
	if err != nil {
		return fmt.Errorf("store: update job: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: job %s not found", j.ID)
	}
	return nil
}

// GetJob returns one job by ID.
func (s *Store) GetJob(id string) (*Job, error) {
	row := s.db.QueryRow(`SELECT id, name, task_id, task_version, cron, selector, max_run_s, enabled, created, updated FROM jobs WHERE id=?`, id)
	var j Job
	if err := row.Scan(&j.ID, &j.Name, &j.TaskID, &j.TaskVersion, &j.Cron, &j.Selector, &j.MaxRunSeconds, &j.Enabled, &j.Created, &j.Updated); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get job: %w", err)
	}
	return &j, nil
}

// ListJobs lists all jobs.
func (s *Store) ListJobs() ([]*Job, error) {
	rows, err := s.db.Query(`SELECT id, name, task_id, task_version, cron, selector, max_run_s, enabled, created, updated FROM jobs ORDER BY created DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list jobs: %w", err)
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Name, &j.TaskID, &j.TaskVersion, &j.Cron, &j.Selector, &j.MaxRunSeconds, &j.Enabled, &j.Created, &j.Updated); err != nil {
			return nil, fmt.Errorf("store: scan job: %w", err)
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

// DeleteJob removes a job.
func (s *Store) DeleteJob(id string) error {
	res, err := s.db.Exec(`DELETE FROM jobs WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: delete job: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: job %s not found", id)
	}
	return nil
}

// AssignJob binds a job to an agent.
func (s *Store) AssignJob(a *JobAssignment) error {
	if a.AssignedAt == 0 {
		a.AssignedAt = now()
	}
	if _, err := s.db.Exec(`
		INSERT INTO job_assignments (job_id, agent_id, assigned_at, last_run_at, last_run_state)
		VALUES (?,?,?,?,?)
		ON CONFLICT (job_id, agent_id) DO UPDATE SET assigned_at=excluded.assigned_at
	`, a.JobID, a.AgentID, a.AssignedAt, a.LastRunAt, a.LastRunState); err != nil {
		return fmt.Errorf("store: assign job: %w", err)
	}
	return nil
}

// UnassignJob removes a job from an agent.
func (s *Store) UnassignJob(jobID, agentID string) error {
	_, err := s.db.Exec(`DELETE FROM job_assignments WHERE job_id=? AND agent_id=?`, jobID, agentID)
	if err != nil {
		return fmt.Errorf("store: unassign job: %w", err)
	}
	return nil
}

// JobAssignmentsForAgent lists all jobs assigned to an agent.
func (s *Store) JobAssignmentsForAgent(agentID string) ([]*JobAssignment, error) {
	rows, err := s.db.Query(`SELECT job_id, agent_id, assigned_at, last_run_at, last_run_state FROM job_assignments WHERE agent_id=?`, agentID)
	if err != nil {
		return nil, fmt.Errorf("store: job assignments: %w", err)
	}
	defer rows.Close()
	var out []*JobAssignment
	for rows.Next() {
		var a JobAssignment
		if err := rows.Scan(&a.JobID, &a.AgentID, &a.AssignedAt, &a.LastRunAt, &a.LastRunState); err != nil {
			return nil, fmt.Errorf("store: scan assignment: %w", err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// JobAssignmentsForJob lists all agents a job is assigned to.
func (s *Store) JobAssignmentsForJob(jobID string) ([]*JobAssignment, error) {
	rows, err := s.db.Query(`SELECT job_id, agent_id, assigned_at, last_run_at, last_run_state FROM job_assignments WHERE job_id=?`, jobID)
	if err != nil {
		return nil, fmt.Errorf("store: job assignments for job: %w", err)
	}
	defer rows.Close()
	var out []*JobAssignment
	for rows.Next() {
		var a JobAssignment
		if err := rows.Scan(&a.JobID, &a.AgentID, &a.AssignedAt, &a.LastRunAt, &a.LastRunState); err != nil {
			return nil, fmt.Errorf("store: scan assignment: %w", err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// CreateJobRun inserts a new job run.
func (s *Store) CreateJobRun(r *JobRun) error {
	if r.ScheduledAt == 0 {
		r.ScheduledAt = now()
	}
	if _, err := s.db.Exec(`
		INSERT INTO job_runs (id, job_id, agent_id, task_id, task_version, scheduled_at, started_at, finished_at, state, trigger, error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
	`, r.ID, r.JobID, r.AgentID, r.TaskID, r.TaskVersion, r.ScheduledAt, r.StartedAt, r.FinishedAt, r.State, r.Trigger, r.Error); err != nil {
		return fmt.Errorf("store: create job run: %w", err)
	}
	return nil
}

// FinalizeJobRun updates a job run's terminal state.
func (s *Store) FinalizeJobRun(id, state, errMsg string) error {
	_, err := s.db.Exec(`UPDATE job_runs SET state=?, error=?, finished_at=? WHERE id=?`,
		state, errMsg, now(), id)
	if err != nil {
		return fmt.Errorf("store: finalize job run: %w", err)
	}
	return nil
}

// GetJobRun returns one job run.
func (s *Store) GetJobRun(id string) (*JobRun, error) {
	row := s.db.QueryRow(`SELECT id, job_id, agent_id, task_id, task_version, scheduled_at, started_at, finished_at, state, trigger, error FROM job_runs WHERE id=?`, id)
	var r JobRun
	if err := row.Scan(&r.ID, &r.JobID, &r.AgentID, &r.TaskID, &r.TaskVersion, &r.ScheduledAt, &r.StartedAt, &r.FinishedAt, &r.State, &r.Trigger, &r.Error); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get job run: %w", err)
	}
	return &r, nil
}

// JobRunsForJob lists runs for a job.
func (s *Store) JobRunsForJob(jobID string, limit int) ([]*JobRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, job_id, agent_id, task_id, task_version, scheduled_at, started_at, finished_at, state, trigger, error FROM job_runs WHERE job_id=? ORDER BY scheduled_at DESC LIMIT ?`, jobID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: job runs: %w", err)
	}
	defer rows.Close()
	var out []*JobRun
	for rows.Next() {
		var r JobRun
		if err := rows.Scan(&r.ID, &r.JobID, &r.AgentID, &r.TaskID, &r.TaskVersion, &r.ScheduledAt, &r.StartedAt, &r.FinishedAt, &r.State, &r.Trigger, &r.Error); err != nil {
			return nil, fmt.Errorf("store: scan job run: %w", err)
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// ListJobRuns lists recent job runs across all jobs.
func (s *Store) ListJobRuns(limit int) ([]*JobRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, job_id, agent_id, task_id, task_version, scheduled_at, started_at, finished_at, state, trigger, error FROM job_runs ORDER BY scheduled_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list job runs: %w", err)
	}
	defer rows.Close()
	var out []*JobRun
	for rows.Next() {
		var r JobRun
		if err := rows.Scan(&r.ID, &r.JobID, &r.AgentID, &r.TaskID, &r.TaskVersion, &r.ScheduledAt, &r.StartedAt, &r.FinishedAt, &r.State, &r.Trigger, &r.Error); err != nil {
			return nil, fmt.Errorf("store: scan job run: %w", err)
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// UpdateJobAssignmentState records the last run state for an assignment.
func (s *Store) UpdateJobAssignmentState(jobID, agentID, state string, ranAt int64) error {
	if ranAt == 0 {
		ranAt = now()
	}
	_, err := s.db.Exec(`UPDATE job_assignments SET last_run_state=?, last_run_at=? WHERE job_id=? AND agent_id=?`,
		state, ranAt, jobID, agentID)
	return err
}