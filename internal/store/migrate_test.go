package store

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// hasColumn reports whether table has column (via PRAGMA table_info).
func hasColumn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("table_info %s: %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return true
		}
	}
	return false
}

// TestMigration_FreshDBHasTLSColumns verifies a brand-new database gets the
// agents.tls_pub / tls_not_after columns.
func TestMigration_FreshDBHasTLSColumns(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	if !hasColumn(t, db.db, "agents", "tls_pub") {
		t.Error("fresh DB: agents.tls_pub missing")
	}
	if !hasColumn(t, db.db, "agents", "tls_not_after") {
		t.Error("fresh DB: agents.tls_not_after missing")
	}
	var v int
	if err := db.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != currentSchemaVersion {
		t.Errorf("schema_version=%d, want %d", v, currentSchemaVersion)
	}
}

// TestMigration_UpgradeV13AddsTLSColumns simulates a pre-rotation database
// (agents table without the TLS columns, schema_version=13) and verifies that
// opening it with New() adds the columns and bumps the version.
func TestMigration_UpgradeV13AddsTLSColumns(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + dir + "/old.db"
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Old agents shape (no tls_pub / tls_not_after).
	stmts := []string{
		`CREATE TABLE schema_version (version INTEGER NOT NULL)`,
		`INSERT INTO schema_version(version) VALUES (13)`,
		`CREATE TABLE agents (
			id TEXT PRIMARY KEY, uuid TEXT NOT NULL UNIQUE,
			ed25519_pub TEXT NOT NULL, x25519_pub TEXT NOT NULL,
			version TEXT, state TEXT NOT NULL DEFAULT 'pending',
			first_seen INTEGER, last_seen INTEGER, created INTEGER NOT NULL)`,
		`INSERT INTO agents(id, uuid, ed25519_pub, x25519_pub, state, created)
		 VALUES ('ag_old','u-old','e','x','connected',0)`,
	}
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			raw.Close()
			t.Fatalf("seed old db: %v", err)
		}
	}
	if hasColumn(t, raw, "agents", "tls_pub") {
		t.Fatal("seed bug: old db already has tls_pub")
	}
	raw.Close()

	// Open with the store; Migrate should add the columns.
	s, err := New("sqlite:" + dir + "/old.db")
	if err != nil {
		t.Fatalf("New (upgrade): %v", err)
	}
	defer s.Close()
	if !hasColumn(t, s.db, "agents", "tls_pub") {
		t.Error("upgrade: agents.tls_pub not added")
	}
	if !hasColumn(t, s.db, "agents", "tls_not_after") {
		t.Error("upgrade: agents.tls_not_after not added")
	}
	var v int
	if err := s.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != currentSchemaVersion {
		t.Errorf("post-upgrade schema_version=%d, want %d", v, currentSchemaVersion)
	}
	// Pre-existing row must survive with the new columns defaulting.
	var pub string
	var na int
	if err := s.db.QueryRow(`SELECT tls_pub, tls_not_after FROM agents WHERE id='ag_old'`).Scan(&pub, &na); err != nil {
		t.Fatal(err)
	}
	if pub != "" || na != 0 {
		t.Errorf("upgraded row defaults = (%q,%d), want ('',0)", pub, na)
	}
}
