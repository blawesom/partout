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

// TestMigration_UpgradeAddsResolvedHost simulates a pre-alias-support
// database (provision_runs without resolved_host) and verifies that opening
// it with New() adds the column and that the run — including its resolved
// target once set — remains readable.
func TestMigration_UpgradeAddsResolvedHost(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/old.db"
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// v0.9.7-era provision_runs (no resolved_host).
	stmts := []string{
		`CREATE TABLE schema_version (version INTEGER NOT NULL)`,
		`INSERT INTO schema_version(version) VALUES (13)`,
		`CREATE TABLE provision_runs (
			id TEXT PRIMARY KEY, host TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'fresh',
			state TEXT NOT NULL DEFAULT 'queued', key_type TEXT, fingerprint TEXT, key_line TEXT,
			token_hash TEXT, agent_id TEXT, step TEXT, error TEXT,
			created INTEGER NOT NULL, updated INTEGER NOT NULL)`,
		`INSERT INTO provision_runs(id, host, mode, state, created, updated)
		 VALUES ('prv_old', 'ai', 'fresh', 'connected', 1, 2)`,
	}
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			raw.Close()
			t.Fatalf("seed old db: %v", err)
		}
	}
	raw.Close()

	st, err := New("sqlite:" + path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer st.Close()

	if !hasColumn(t, st.db, "provision_runs", "resolved_host") {
		t.Fatal("provision_runs.resolved_host missing after migration")
	}
	runs, err := st.ProvisionRuns(10)
	if err != nil {
		t.Fatalf("ProvisionRuns after migration: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != "prv_old" || runs[0].ResolvedHost != "" {
		t.Fatalf("unexpected runs: %+v", runs)
	}
	if err := st.SetProvisionRunResolved("prv_old", "172.16.100.95"); err != nil {
		t.Fatalf("SetProvisionRunResolved: %v", err)
	}
	r, err := st.ProvisionRun("prv_old")
	if err != nil || r.ResolvedHost != "172.16.100.95" {
		t.Fatalf("resolved host not persisted: %+v err=%v", r, err)
	}
}

func TestMigration_UpgradeAddsElevationColumns(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/old.db"
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// v0.9.13-era execution_runs (no elevated / elevation_note).
	stmts := []string{
		`CREATE TABLE schema_version (version INTEGER NOT NULL)`,
		`INSERT INTO schema_version(version) VALUES (23)`,
		`CREATE TABLE agents (id TEXT PRIMARY KEY, uuid TEXT NOT NULL,
			ed25519_pub TEXT NOT NULL DEFAULT '', x25519_pub TEXT NOT NULL DEFAULT '',
			connected INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE executions (id TEXT PRIMARY KEY, selector TEXT NOT NULL,
			cmd TEXT NOT NULL, args_json TEXT NOT NULL DEFAULT '[]',
			created INTEGER NOT NULL DEFAULT 0, created_by TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT 'pending')`,
		`CREATE TABLE execution_runs (
			id TEXT PRIMARY KEY, execution_id TEXT NOT NULL,
			agent_id TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
			exit_code INTEGER, duration_ms INTEGER,
			created INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0)`,
		`INSERT INTO executions(id, selector, cmd, created, state) VALUES ('exec_old', 'all', 'uptime', 1, 'succeeded')`,
		`INSERT INTO execution_runs(id, execution_id, agent_id, state, exit_code, created, updated)
		 VALUES ('run_old', 'exec_old', 'ag_old', 'succeeded', 0, 1, 2)`,
	}
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			raw.Close()
			t.Fatalf("seed old db: %v", err)
		}
	}
	raw.Close()

	st, err := New("sqlite:" + path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer st.Close()

	if !hasColumn(t, st.db, "execution_runs", "elevated") {
		t.Fatal("execution_runs.elevated missing after migration")
	}
	if !hasColumn(t, st.db, "execution_runs", "elevation_note") {
		t.Fatal("execution_runs.elevation_note missing after migration")
	}
	// Pre-existing rows read back with the not-reported default, and the
	// elevation setter works on the migrated table.
	r, err := st.GetExecutionRun("run_old")
	if err != nil || r == nil {
		t.Fatalf("GetExecutionRun: %v %v", r, err)
	}
	if r.Elevated.Valid {
		t.Errorf("pre-existing run reports an elevation decision; want not-reported (NULL)")
	}
	if err := st.SetRunElevation("run_old", true, "policy rule matched: reboot"); err != nil {
		t.Fatalf("SetRunElevation after migration: %v", err)
	}
	r, _ = st.GetExecutionRun("run_old")
	if !r.Elevated.Valid || !r.Elevated.Bool {
		t.Errorf("SetRunElevation did not stick after migration: %+v", r.Elevated)
	}
}
