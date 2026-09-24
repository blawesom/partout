package store

import (
	"database/sql"
	"time"
)

// ---- External data (M3, PRD §6.3) ------------------------------------------

// EOLRow is one distro release cycle's end-of-support dates (endoflife.date).
type EOLRow struct {
	Distro           string
	Cycle            string
	Codename         string
	ReleaseDate      string
	EOLDate          string
	SupportDate      string
	ExtendedSupport  string
	Latest           string
	FetchedAt        int64
}

// VulnRow is one cached vulnerability affecting (package, ecosystem, version).
type VulnRow struct {
	VulnID    string
	Package   string
	Ecosystem string
	Version   string
	Severity  sql.NullFloat64 // CVSS 0-10; NULL = ungraded
	Summary   string
	URL       string
	FetchedAt int64
}

// SetExternalMeta stores a key/value status row (last refresh, etc.).
func (s *Store) SetExternalMeta(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO external_meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// GetExternalMeta returns one status value ("", nil when absent).
func (s *Store) GetExternalMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM external_meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// ReplaceEOLCache atomically replaces the whole EOL table (all-or-nothing,
// PRD §6.3: a failed fetch leaves the previous cache untouched).
func (s *Store) ReplaceEOLCache(rows []EOLRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM eol_cache`); err != nil {
		return err
	}
	for _, r := range rows {
		if r.FetchedAt == 0 {
			r.FetchedAt = time.Now().Unix()
		}
		if _, err := tx.Exec(`
			INSERT INTO eol_cache (distro, cycle, codename, release_date, eol_date, support_date, extended_support, latest, fetched_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Distro, r.Cycle, r.Codename, r.ReleaseDate, r.EOLDate, r.SupportDate, r.ExtendedSupport, r.Latest, r.FetchedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListEOLCache returns all cached EOL rows (empty when the cache is empty).
func (s *Store) ListEOLCache() ([]EOLRow, error) {
	rows, err := s.db.Query(`
		SELECT distro, cycle, codename, release_date, eol_date, support_date, extended_support, latest, fetched_at
		FROM eol_cache ORDER BY distro, cycle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EOLRow
	for rows.Next() {
		var r EOLRow
		if err := rows.Scan(&r.Distro, &r.Cycle, &r.Codename, &r.ReleaseDate, &r.EOLDate,
			&r.SupportDate, &r.ExtendedSupport, &r.Latest, &r.FetchedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetVulnsForVersion returns cached vulns for (package, ecosystem, version)
// (tombstone rows — vuln_id "-" = known clean — are excluded).
func (s *Store) GetVulnsForVersion(pkgName, ecosystem, version string) ([]VulnRow, error) {
	rows, err := s.db.Query(`
		SELECT vuln_id, package, ecosystem, version, severity, summary, url, fetched_at
		FROM vuln_cache WHERE package = ? AND ecosystem = ? AND version = ? AND vuln_id <> '-'`,
		pkgName, ecosystem, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnRow
	for rows.Next() {
		var r VulnRow
		if err := rows.Scan(&r.VulnID, &r.Package, &r.Ecosystem, &r.Version, &r.Severity,
			&r.Summary, &r.URL, &r.FetchedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountVulnsCached returns the number of cached vuln rows (excluding the
// "clean" tombstone rows).
func (s *Store) CountVulnsCached() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM vuln_cache WHERE vuln_id <> '-'`).Scan(&n)
	return n, err
}

// InsertVulns upserts one batch of vuln rows (OSV query results).
func (s *Store) InsertVulns(rows []VulnRow) error {
	for _, r := range rows {
		if r.FetchedAt == 0 {
			r.FetchedAt = time.Now().Unix()
		}
		if _, err := s.db.Exec(`
			INSERT OR REPLACE INTO vuln_cache (vuln_id, package, ecosystem, version, severity, summary, url, fetched_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			r.VulnID, r.Package, r.Ecosystem, r.Version, r.Severity, r.Summary, r.URL, r.FetchedAt); err != nil {
			return err
		}
	}
	return nil
}