package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ---- Update releases (M8.1, PRD §11) --------------------------------------

// Release is one signed partout release artifact.
type Release struct {
	ID         string
	Version    string
	Arch       string // e.g. "linux-amd64"
	Kind       string // "agent" | "server"
	SHA256     string // hex, of the artifact
	Signature  string // base64 Ed25519 over "version|arch|kind|sha256"
	Artifact   []byte
	UploadedBy string
	Created    int64
}

// ReleaseMeta is a Release without the artifact blob (list/detail rows).
type ReleaseMeta struct {
	ID         string
	Version    string
	Arch       string
	Kind       string
	SHA256     string
	Signature  string
	Size       int64
	UploadedBy string
	Created    int64
}

// ErrNoRelease is returned when no release row matches.
var ErrNoRelease = errors.New("store: no such release")

func releaseMetaColumns() string {
	return `id, version, arch, kind, sha256, signature, length(artifact) AS size,
		COALESCE(uploaded_by, ''), created_at`
}

func scanReleaseMeta(row interface{ Scan(...any) error }) (ReleaseMeta, error) {
	var m ReleaseMeta
	err := row.Scan(&m.ID, &m.Version, &m.Arch, &m.Kind, &m.SHA256, &m.Signature,
		&m.Size, &m.UploadedBy, &m.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return ReleaseMeta{}, ErrNoRelease
	}
	return m, err
}

// InsertRelease stores one release. (version, arch, kind) is unique;
// re-uploading the same triple is a conflict error.
func (s *Store) InsertRelease(r Release) error {
	if r.ID == "" {
		return fmt.Errorf("store: release id required")
	}
	if r.Created == 0 {
		r.Created = now()
	}
	_, err := s.db.Exec(`
		INSERT INTO update_releases (id, version, arch, kind, sha256, signature, artifact, uploaded_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Version, r.Arch, r.Kind, r.SHA256, r.Signature, r.Artifact, r.UploadedBy, r.Created)
	return err
}

// GetRelease returns one release including its artifact.
func (s *Store) GetRelease(id string) (Release, error) {
	var r Release
	err := s.db.QueryRow(`
		SELECT id, version, arch, kind, sha256, signature, artifact,
		       COALESCE(uploaded_by, ''), created_at
		FROM update_releases WHERE id = ?`, id).
		Scan(&r.ID, &r.Version, &r.Arch, &r.Kind, &r.SHA256, &r.Signature,
			&r.Artifact, &r.UploadedBy, &r.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, ErrNoRelease
	}
	return r, err
}

// GetReleaseByVer looks up a release by (version, arch, kind).
func (s *Store) GetReleaseByVer(version, arch, kind string) (Release, error) {
	var r Release
	err := s.db.QueryRow(`
		SELECT id, version, arch, kind, sha256, signature, artifact,
		       COALESCE(uploaded_by, ''), created_at
		FROM update_releases WHERE version = ? AND arch = ? AND kind = ?`,
		version, arch, kind).
		Scan(&r.ID, &r.Version, &r.Arch, &r.Kind, &r.SHA256, &r.Signature,
			&r.Artifact, &r.UploadedBy, &r.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, ErrNoRelease
	}
	return r, err
}

// ListReleases returns metadata (no artifacts), newest first.
func (s *Store) ListReleases() ([]ReleaseMeta, error) {
	rows, err := s.db.Query(`SELECT ` + releaseMetaColumns() + `
		FROM update_releases ORDER BY created_at DESC, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReleaseMeta
	for rows.Next() {
		m, err := scanReleaseMeta(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteRelease removes a release and its artifact.
func (s *Store) DeleteRelease(id string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM update_releases WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ---- Update runs (M8.1 rollout orchestration) ------------------------------

// UpdateRun is one fleet rollout. Status: pending (awaiting approval) |
// canary | rolling | paused_failure | completed | failed | aborted.
type UpdateRun struct {
	ID           string
	Version      string
	ReleaseID    string
	Arch         string
	Selector     string
	CanaryHosts  string // comma-joined canary cohort
	CanaryCount  int
	WavePct      int
	Status       string
	CurrentWave  int
	TotalHosts   int
	DoneHosts    int
	FailedHosts  int
	SkippedHosts int
	Error        string
	ApprovalID   string
	CreatedBy    string
	CreatedAt    int64
	UpdatedAt    int64
}

// UpdateHost is the per-host state machine for one (run, host).
// Status: queued | dispatching | transferring | swapping | restarting |
// verified | skipped | failed_rollback | timed_out.
type UpdateHost struct {
	ID        string
	RunID     string
	HostID    string
	Status    string
	Version   string
	Error     string
	UpdatedAt int64
}

const updateRunColumns = `id, version, release_id, arch, selector, canary_hosts, canary_count,
wave_pct, status, current_wave, total_hosts, done_hosts, failed_hosts,
skipped_hosts, error, approval_id, created_by, created_at, updated_at`

// TerminalRunHost reports whether a per-host update status is final.
func TerminalRunHost(status string) bool {
	switch status {
	case "verified", "skipped", "failed_rollback", "timed_out":
		return true
	}
	return false
}

// TerminalUpdateRun reports whether a run status is final.
func TerminalUpdateRun(status string) bool {
	switch status {
	case "completed", "failed", "aborted":
		return true
	}
	return false
}

func (s *Store) CreateUpdateRun(r *UpdateRun) error {
	if r.CreatedAt == 0 {
		r.CreatedAt = time.Now().Unix()
	}
	r.UpdatedAt = time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO update_runs (`+updateRunColumns+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Version, r.ReleaseID, r.Arch, r.Selector, r.CanaryHosts, r.CanaryCount,
		r.WavePct, r.Status, r.CurrentWave, r.TotalHosts, r.DoneHosts, r.FailedHosts,
		r.SkippedHosts, r.Error, r.ApprovalID, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return err
}

func scanUpdateRun(row interface{ Scan(...any) error }) (*UpdateRun, error) {
	var r UpdateRun
	err := row.Scan(&r.ID, &r.Version, &r.ReleaseID, &r.Arch, &r.Selector,
		&r.CanaryHosts, &r.CanaryCount, &r.WavePct, &r.Status, &r.CurrentWave,
		&r.TotalHosts, &r.DoneHosts, &r.FailedHosts, &r.SkippedHosts,
		&r.Error, &r.ApprovalID, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) GetUpdateRun(id string) (*UpdateRun, error) {
	row := s.db.QueryRow(`SELECT `+updateRunColumns+` FROM update_runs WHERE id=?`, id)
	return scanUpdateRun(row)
}

func (s *Store) ListUpdateRuns(limit int) ([]*UpdateRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT `+updateRunColumns+`
FROM update_runs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UpdateRun
	for rows.Next() {
		r, err := scanUpdateRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListActiveUpdateRuns returns runs whose status is not terminal (crash-safe
// resume on server restart).
func (s *Store) ListActiveUpdateRuns() ([]*UpdateRun, error) {
	rows, err := s.db.Query(`SELECT ` + updateRunColumns + ` FROM update_runs
WHERE status NOT IN ('completed','failed','aborted') ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UpdateRun
	for rows.Next() {
		r, err := scanUpdateRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetUpdateRunStatus updates status + optional error and bumps updated_at.
func (s *Store) SetUpdateRunStatus(id, status, errMsg string) error {
	_, err := s.db.Exec(`UPDATE update_runs SET status=?, error=?, updated_at=? WHERE id=?`,
		status, errMsg, time.Now().Unix(), id)
	return err
}

// SetUpdateRunCounters updates the wave + progress counters.
func (s *Store) SetUpdateRunCounters(id string, currentWave, total, done, failed, skipped int) error {
	_, err := s.db.Exec(`UPDATE update_runs
SET current_wave=?, total_hosts=?, done_hosts=?, failed_hosts=?, skipped_hosts=?, updated_at=?
WHERE id=?`, currentWave, total, done, failed, skipped, time.Now().Unix(), id)
	return err
}

// SetUpdateRunApproval links a run to its approval request.
func (s *Store) SetUpdateRunApproval(id, approvalID string) error {
	_, err := s.db.Exec(`UPDATE update_runs SET approval_id=?, updated_at=? WHERE id=?`,
		approvalID, time.Now().Unix(), id)
	return err
}

func (s *Store) AddUpdateHosts(runID string, hosts []UpdateHost) error {
	if len(hosts) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	for i := range hosts {
		h := &hosts[i]
		if h.ID == "" {
			return fmt.Errorf("store: update host id required")
		}
		if h.UpdatedAt == 0 {
			h.UpdatedAt = now
		}
		if h.Status == "" {
			h.Status = "queued"
		}
		if _, err := tx.Exec(`INSERT INTO update_hosts
(id, run_id, host_id, status, version, error, updated_at)
VALUES (?,?,?,?,?,?,?)`,
			h.ID, runID, h.HostID, h.Status, h.Version, h.Error, h.UpdatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanUpdateHost(row interface{ Scan(...any) error }) (*UpdateHost, error) {
	var h UpdateHost
	err := row.Scan(&h.ID, &h.RunID, &h.HostID, &h.Status, &h.Version, &h.Error, &h.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (s *Store) ListUpdateHosts(runID string) ([]*UpdateHost, error) {
	rows, err := s.db.Query(`SELECT id, run_id, host_id, status, version, error, updated_at
FROM update_hosts WHERE run_id=? ORDER BY updated_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UpdateHost
	for rows.Next() {
		h, err := scanUpdateHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetUpdateHost returns the single row for (runID, hostID).
func (s *Store) GetUpdateHost(runID, hostID string) (*UpdateHost, error) {
	row := s.db.QueryRow(`SELECT id, run_id, host_id, status, version, error, updated_at
FROM update_hosts WHERE run_id=? AND host_id=?`, runID, hostID)
	return scanUpdateHost(row)
}

// ActiveUpdateHostFor returns the non-terminal update_hosts row for a host
// (the one a just-arrived update result belongs to), newest first.
func (s *Store) ActiveUpdateHostFor(hostID string) (*UpdateHost, error) {
	row := s.db.QueryRow(`SELECT id, run_id, host_id, status, version, error, updated_at
FROM update_hosts WHERE host_id=? AND status NOT IN ('verified','skipped','failed_rollback','timed_out')
ORDER BY updated_at DESC LIMIT 1`, hostID)
	return scanUpdateHost(row)
}

// SetUpdateHostStatus moves one per-host row and bumps updated_at.
func (s *Store) SetUpdateHostStatus(id, status, version, errMsg string) error {
	_, err := s.db.Exec(`UPDATE update_hosts SET status=?, version=?, error=?, updated_at=? WHERE id=?`,
		status, version, errMsg, time.Now().Unix(), id)
	return err
}

// SetUpdateHostsStatusByHost moves every row for a host within a run to a
// terminal status (used by skip/abort).
func (s *Store) SetUpdateHostsStatusByHost(runID, hostID, status string) error {
	_, err := s.db.Exec(`UPDATE update_hosts SET status=?, updated_at=? WHERE run_id=? AND host_id=?`,
		status, time.Now().Unix(), runID, hostID)
	return err
}
