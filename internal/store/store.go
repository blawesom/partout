// Package store is the single data layer for Partout. It wraps
// database/sql over a dialect (sqlite by default, postgres optional) and
// applies one monotonic, forward-only migration on open (PRD R9, arch §9.1).
//
// All entities carry an agent_id (NULL = local/embedded). Keys are opaque
// TEXT ids (ag_..., run_..., exec_...). Timestamps are epoch-second BIGINTs.
// Upserts use ON CONFLICT ... DO UPDATE (PRD §8).
package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers "sqlite"
)

// Store is a dialect-aware database handle.
type Store struct {
	db      *sql.DB
	dialect string // "sqlite" | "postgres"
}

// New opens (or creates) the database at dsn and applies migrations.
//
// dsn formats:
//
//	"sqlite:/var/lib/partout/server/db.partout"
//	"sqlite::memory:"
//
// The DB file is exactly the path in the dsn. Pre-fix versions wrote a file
// named "<path>&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" (the
// pragma suffix had leaked into the filename); such a legacy file is
// transparently renamed to the clean path on open.
func New(dsn string) (*Store, error) {
	dialect, connect, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	if dialect == "postgres" {
		return nil, fmt.Errorf("store: postgres not yet compiled in (SQLite is default for M0)")
	}
	migrateLegacyDBName(dsn)

	db, err := sql.Open("sqlite", connect)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// Single-writer discipline (PRD R9).
	db.SetMaxOpenConns(1)

	s := &Store{db: db, dialect: dialect}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// legacyPragmaSuffix is what pre-fix parseDSN appended to the file path —
// with '&' instead of '?', so it became part of the literal filename.
const legacyPragmaSuffix = "&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"

// migrateLegacyDBName renames a pre-fix DB file (name embedded with the
// pragma suffix) to the clean path, including its -wal/-shm sidecars.
// No-op when the legacy name is absent or the clean path already exists
// (never clobbers an existing database).
func migrateLegacyDBName(dsn string) {
	if len(dsn) < 7 || dsn[:7] != "sqlite:" {
		return
	}
	raw := dsn[7:]
	if raw == "" || raw == ":memory:" || strings.Contains(raw, "?") {
		return
	}
	legacy := raw + legacyPragmaSuffix
	if _, err := os.Stat(legacy); err != nil {
		return
	}
	if _, err := os.Stat(raw); err == nil {
		return // clean path already in use; operator must resolve manually
	}
	_ = os.Rename(legacy, raw)
	for _, ext := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(legacy + ext); err == nil {
			_ = os.Rename(legacy+ext, raw+ext)
		}
	}
}

// parseDSN returns (dialect, connectArg).
func parseDSN(dsn string) (string, string, error) {
	if len(dsn) >= 7 && dsn[:7] == "sqlite:" {
		raw := dsn[7:]
		if raw == ":memory:" || raw == "" {
			return "sqlite", ":memory:?_pragma=foreign_keys(1)", nil
		}
		// File-based: also enable WAL. The pragmas are a query string on the
		// path — '?' when the path has no query yet — so the opened file is
		// exactly `raw` (PRAGMAs apply to every connection; with
		// SetMaxOpenConns(1) that is one stable connection, so
		// foreign_keys(1) persists — required for ON DELETE CASCADE).
		sep := "?"
		if strings.Contains(raw, "?") {
			sep = "&"
		}
		return "sqlite", raw + sep + "_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", nil
	}
	return "", "", fmt.Errorf("store: unknown dsn %q (want sqlite:...)", dsn)
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// BackupTo writes an atomic, consistent snapshot of the database to path
// using SQLite's VACUUM INTO. It is a hot copy: the source may be actively
// served (WAL), and the snapshot reflects the DB as of the statement.
// The parent directory of path must exist; an existing file at path is
// replaced. This is the mechanism the backup timer
// (deploy/systemd/partout-backup.timer) uses.
func (s *Store) BackupTo(path string) error {
	if strings.Contains(path, "'") {
		return fmt.Errorf("store: backup path must not contain a single quote")
	}
	if _, err := s.db.Exec("VACUUM INTO '" + path + "'"); err != nil {
		return fmt.Errorf("store: backup to %s: %w", path, err)
	}
	return nil
}

// DB exposes the raw *sql.DB for tests and advanced use.
func (s *Store) DB() *sql.DB { return s.db }

// Dialect returns the active dialect name.
func (s *Store) Dialect() string { return s.dialect }

// Migrate applies the schema if not already applied (forward-only, PRD R9).
func (s *Store) Migrate() error {
	// Check for version — if table doesn't exist, this errors and triggers
	// a fresh apply.
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	if err != nil {
		// schema_version table missing or corrupt — fresh DB.
		return s.applySchema()
	}
	if v >= currentSchemaVersion {
		return nil
	}
	// Forward upgrade (v < current).
	return s.applySchema()
}

// applySchema runs the idempotent DDL and records the version.
func (s *Store) applySchema() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: apply: %w", err)
	}
	// Ensure columns added after v1 exist on pre-upgrade DBs (CREATE TABLE IF
	// NOT EXISTS skips them). Idempotent: checks PRAGMA table_info first.
	if err := ensureColumns(tx, []columnSpec{
		{table: "agents", column: "tls_pub", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "agents", column: "tls_not_after", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "provision_runs", column: "resolved_host", def: "TEXT"},
		{table: "assistant_messages", column: "meta", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "alert_rules", column: "webhook_url", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "provision_runs", column: "extras_json", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "execution_runs", column: "elevated", def: "INTEGER"},
		{table: "execution_runs", column: "elevation_note", def: "TEXT NOT NULL DEFAULT ''"},
	}); err != nil {
		return fmt.Errorf("store: ensure columns: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO schema_version(version) VALUES(?)`,
		currentSchemaVersion,
	); err != nil {
		return fmt.Errorf("store: version: %w", err)
	}
	return tx.Commit()
}

// now returns current epoch seconds.
func now() int64 { return time.Now().Unix() }

// columnSpec names a column that must exist on a table (forward migration on
// pre-existing databases).
type columnSpec struct {
	table  string
	column string
	def    string // e.g. "TEXT NOT NULL DEFAULT ''"
}

// ensureColumns adds any missing columns (idempotent via PRAGMA table_info).
// Table names are trusted constants, not user input.
func ensureColumns(tx *sql.Tx, cols []columnSpec) error {
	for _, c := range cols {
		rows, err := tx.Query("PRAGMA table_info(" + c.table + ")")
		if err != nil {
			return fmt.Errorf("table_info %s: %w", c.table, err)
		}
		found := false
		for rows.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				rows.Close()
				return err
			}
			if name == c.column {
				found = true
			}
		}
		rows.Close()
		if found {
			continue
		}
		if _, err := tx.Exec("ALTER TABLE " + c.table + " ADD COLUMN " + c.column + " " + c.def); err != nil {
			return fmt.Errorf("add column %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}
