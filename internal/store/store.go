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
func New(dsn string) (*Store, error) {
	dialect, connect, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	if dialect == "postgres" {
		return nil, fmt.Errorf("store: postgres not yet compiled in (SQLite is default for M0)")
	}

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

// parseDSN returns (dialect, connectArg).
func parseDSN(dsn string) (string, string, error) {
	if len(dsn) >= 7 && dsn[:7] == "sqlite:" {
		raw := dsn[7:]
		if raw == ":memory:" || raw == "" {
			return "sqlite", ":memory:", nil
		}
		// Append SQLite PRAGMA for WAL + foreign keys.
		return "sqlite", raw + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", nil
	}
	return "", "", fmt.Errorf("store: unknown dsn %q (want sqlite:...)", dsn)
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

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
