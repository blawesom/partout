package store

import (
	"database/sql"
	"errors"
	"fmt"
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
