// doctor DB-pack tests: seed a real store with each symptom class (skewed
// agent versions, actor-less audit rows, stuck executions, expired pending
// approvals, the file-root fact-wipe signature) and assert the read-only
// checks find them — and stay quiet on a healthy database.
package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/store"
)

func seedDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "partout.db")
	st, err := store.New("sqlite:" + path)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return path
}

func TestDoctorFleetVersions(t *testing.T) {
	path := seedDB(t)
	st := mustStore(t, path)

	mustUpsertAgent(t, st, "ag_a", facts.Version)
	mustUpsertAgent(t, st, "ag_b", facts.Version)
	r := &doctorResult{}
	cfg := newTestConfig()
	cfg.DBPath = path
	checkFleetVersions(cfg, r)
	if r.fails != 0 || r.warns != 0 {
		t.Fatalf("matching fleet should be clean, got %+v", r.checks)
	}

	mustUpsertAgent(t, st, "ag_c", "0.0.1-old")
	r2 := &doctorResult{}
	checkFleetVersions(cfg, r2)
	if r2.warns != 1 || r2.fails != 0 {
		t.Fatalf("skewed agent must warn once, got %+v", r2.checks)
	}
	if !strings.Contains(r2.checks[0].detail, "0.0.1-old") {
		t.Fatalf("warning must name the skewed version: %+v", r2.checks)
	}
}

func TestDoctorDBHealth(t *testing.T) {
	path := seedDB(t)
	st := mustStore(t, path)
	now := time.Now().Unix()

	// Healthy baseline: nothing seeded → all ok.
	r := &doctorResult{}
	cfg := newTestConfig()
	cfg.DBPath = path
	checkDBHealth(cfg, r)
	if r.fails != 0 || r.warns != 0 {
		t.Fatalf("empty db should be clean, got %+v", r.checks)
	}

	// Actor-less audit row.
	if _, err := st.DB().Exec(`INSERT INTO audit_events(ts, kind, actor, payload) VALUES (?,?,?,?)`,
		now, "exec.dispatch", "", "{}"); err != nil {
		t.Fatal(err)
	}
	// Stuck execution (running, created 4 days ago).
	if err := st.CreateExecution(store.Execution{
		ID: "exec_stuck", Selector: "all", Cmd: "sleep", Created: now - 4*86400, CreatedBy: "x", State: "running",
	}); err != nil {
		t.Fatal(err)
	}
	// Expired-but-pending approval.
	if err := st.CreateApprovalRequest(&store.ApprovalRequest{
		ID: "apr_old", ActionClass: "exec", State: "pending", CreatedUnix: now - 7200, ExpiresUnix: now - 3600,
	}); err != nil {
		t.Fatal(err)
	}
	// File-root wipe signature: connected 0.9.9 agent, fresh facts, neither key.
	mustUpsertAgent(t, st, "ag_w", "0.9.9")
	if _, err := st.DB().Exec(`UPDATE agents SET last_seen=?, state='connected' WHERE id='ag_w'`, now); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_w", TS: now, Data: map[string]string{"partout.version": "0.9.9"}}); err != nil {
		t.Fatal(err)
	}

	r2 := &doctorResult{}
	checkDBHealth(cfg, r2)
	found := map[string]bool{}
	for _, c := range r2.checks {
		if c.level == dwarn || c.level == dfail {
			found[c.name] = true
		}
	}
	for _, want := range []string{"db audit actors", "db stuck execs", "db approvals", "db file roots"} {
		if !found[want] {
			t.Errorf("%s: symptom not reported — checks: %+v", want, r2.checks)
		}
	}
	if r2.fails != 1 { // only the file-root wipe is a hard fail
		t.Errorf("file-root wipe must be the single hard fail, got %d: %+v", r2.fails, r2.checks)
	}
}

func TestDoctorDBHealthRootReportedIsClean(t *testing.T) {
	path := seedDB(t)
	st := mustStore(t, path)
	now := time.Now().Unix()
	mustUpsertAgent(t, st, "ag_ok", "0.9.9")
	if _, err := st.DB().Exec(`UPDATE agents SET last_seen=? WHERE id='ag_ok'`, now); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_ok", TS: now, Data: map[string]string{"partout.file_root": "/home/partout"}}); err != nil {
		t.Fatal(err)
	}
	r := &doctorResult{}
	cfg := newTestConfig()
	cfg.DBPath = path
	checkDBHealth(cfg, r)
	for _, c := range r.checks {
		if c.name == "db file roots" && c.level != dok {
			t.Fatalf("agent reporting its root must be clean, got %+v", c)
		}
	}
}

func mustStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.New("sqlite:" + path)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustUpsertAgent(t *testing.T, st *store.Store, id, version string) {
	t.Helper()
	if err := st.UpsertAgent(store.Agent{ID: id, UUID: "u-" + id, Version: version}); err != nil {
		t.Fatalf("UpsertAgent %s: %v", id, err)
	}
}
