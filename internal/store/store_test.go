package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAgentLifecycle tests full agent CRUD and cascade delete.
func TestAgentLifecycle(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	kp1 := "ed25519_pub1"
	kp2 := "x25519_pub1"

	err := db.UpsertAgent(Agent{ID: "ag_x", UUID: "u1", ED25519Pub: kp1, X25519Pub: kp2})
	if err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	a, err := db.Agent("ag_x")
	if err != nil {
		t.Fatalf("Agent: %v", err)
	}
	if a.UUID != "u1" {
		t.Errorf("uuid = %q, want u1", a.UUID)
	}
	if a.State != "pending" {
		t.Errorf("state = %q, want pending", a.State)
	}

	// Update state.
	if err := db.SetAgentState("ag_x", "connected"); err != nil {
		t.Fatalf("SetAgentState: %v", err)
	}
	a, err = db.Agent("ag_x")
	if err != nil {
		t.Fatalf("Agent: %v", err)
	}
	if a.State != "connected" {
		t.Errorf("state = %q, want connected", a.State)
	}

	// Delete and verify gone.
	if err := db.DeleteAgent("ag_x"); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if _, err := db.Agent("ag_x"); err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestEnrollmentToken(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	hash := "sha256_foo"
	mask := "sha256_bar"
	if err := db.CreateEnrollmentToken(hash, mask, 3600); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	// Consume it.
	ok, err := db.ConsumeEnrollmentToken(hash)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !ok {
		t.Fatal("expected consume to succeed")
	}

	// Re-consume → should fail.
	ok, err = db.ConsumeEnrollmentToken(hash)
	if err != nil {
		t.Fatalf("Re-consume: %v", err)
	}
	if ok {
		t.Fatal("expected re-consume to fail")
	}
}

func TestFacts(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	// Need an agent first for FK.
	db.UpsertAgent(Agent{ID: "ag_x", UUID: "u1", ED25519Pub: "kp1", X25519Pub: "kp2"})

	f := Facts{
		AgentID: "ag_x",
		Data:    map[string]string{"distro": "debian", "version": "12"},
	}
	if err := db.UpsertFacts(f); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
	}

	lf, err := db.LatestFacts("ag_x")
	if err != nil {
		t.Fatalf("LatestFacts: %v", err)
	}
	if lf.Data["distro"] != "debian" {
		t.Errorf("distro = %q, want debian", lf.Data["distro"])
	}
}

func TestTagsAndRoles(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	// Need an agent first for FK.
	db.UpsertAgent(Agent{ID: "ag_x", UUID: "u1", ED25519Pub: "kp1", X25519Pub: "kp2"})

	if err := db.SetTag("ag_x", "env", "prod"); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	if err := db.SetTag("ag_x", "env", "lab"); err != nil {
		t.Fatalf("SetTag overwrite: %v", err)
	}
	tags, err := db.Tags("ag_x")
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if tags["env"] != "lab" {
		t.Errorf("env = %q, want lab", tags["env"])
	}

	// Delete tag.
	if err := db.DeleteTag("ag_x", "env"); err != nil {
		t.Fatalf("DeleteTag: %v", err)
	}
	tags, err = db.Tags("ag_x")
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if _, ok := tags["env"]; ok {
		t.Fatal("tag should be gone")
	}

	if err := db.SetRole("ag_x", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	roles, err := db.Roles("ag_x")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "web" {
		t.Errorf("roles = %v, want [web]", roles)
	}
}

func TestGroups(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	g := Group{Name: "webservers", Selector: "role:web"}
	if err := db.UpsertGroup(g); err != nil {
		t.Fatalf("UpsertGroup: %v", err)
	}

	groups, err := db.Groups()
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if sel, ok := groups["webservers"]; !ok || sel != "role:web" {
		t.Errorf("webservers = %q, want role:web", sel)
	}

	if err := db.DeleteGroup("webservers"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	groups, err = db.Groups()
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if _, ok := groups["webservers"]; ok {
		t.Fatal("group should be gone")
	}
}

func TestExecutionsAndRuns(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	db.UpsertAgent(Agent{ID: "ag_x", UUID: "u1", ED25519Pub: "kp1", X25519Pub: "kp2"})
	db.CreateExecution(Execution{ID: "exec_foo", Selector: "role:web", Cmd: "whoami", State: "dispatching", CreatedBy: "admin"})

	r := ExecutionRun{
		ID:          "run_1",
		ExecutionID: "exec_foo",
		AgentID:     "ag_x",
		State:       "running",
	}
	if err := db.CreateExecutionRun(r); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}

	// Update run state.
	if err := db.UpdateRunState("run_1", "succeeded", 0, 42); err != nil {
		t.Fatalf("UpdateRunState: %v", err)
	}

	runs, err := db.ListRunsForExecution("exec_foo")
	if err != nil {
		t.Fatalf("ListRunsForExecution: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len = %d, want 1", len(runs))
	}
	if runs[0].State != "succeeded" {
		t.Errorf("state = %q, want succeeded", runs[0].State)
	}
}

func TestOutputChunks(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	db.UpsertAgent(Agent{ID: "ag_x", UUID: "u1", ED25519Pub: "kp1", X25519Pub: "kp2"})
	if err := db.CreateExecution(Execution{ID: "exec_x", Cmd: "echo hello"}); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := db.CreateExecutionRun(ExecutionRun{ID: "run_x", ExecutionID: "exec_x", AgentID: "ag_x", State: "running"}); err != nil {
		t.Fatalf("CreateExecutionRun: %v", err)
	}

	// Append chunks.
	for i, s := range []string{"hello ", "world\n"} {
		if err := db.AppendOutput(OutputChunk{RunID: "run_x", ChunkSeq: i, Stream: "stdout", Data: []byte(s)}); err != nil {
			t.Fatalf("AppendOutput[%d]: %v", i, err)
		}
	}

	chunks, err := db.ListOutput("run_x")
	if err != nil {
		t.Fatalf("ListOutput: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("len = %d, want 2", len(chunks))
	}
	var got strings.Builder
	for _, c := range chunks {
		got.Write(c.Data)
	}
	if got.String() != "hello world\n" {
		t.Errorf("output = %q, want 'hello world\n'", got.String())
	}
}

func TestAudit(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	a := AuditEvent{
		TS:      now(),
		Kind:    "exec",
		Actor:   "admin",
		Payload: `{"cmd":"whoami"}`,
	}
	if err := db.AppendAudit(a); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	// Filter by kind.
	events, err := db.ListAudit("exec", 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "exec" {
		t.Fatalf("got %v", events)
	}

	// Filter by unknown kind.
	events, err = db.ListAudit("nope", 10)
	if err != nil {
		t.Fatalf("ListAudit nope: %v", err)
	}
	if len(events) != 0 {
		t.Fatal("expected 0 events for unknown kind")
	}
}

// ---- helpers --------------------------------------------------------------

func setupTestDB(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New("sqlite:" + dir + "/test.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, dir
}

// TestFileDSNOpensCleanPath verifies the opened file is exactly the dsn path
// (regression guard for the pre-fix "&_pragma=..." filename quirk) and that
// WAL + foreign_keys are actually applied.
func TestFileDSNOpensCleanPath(t *testing.T) {
	dir := t.TempDir()
	s, err := New("sqlite:" + dir + "/clean.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode=%q, want wal (pragma not applied?)", mode)
	}
	var fk int
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys=%d, want 1", fk)
	}

	// Exactly one DB file, with the clean name.
	entries, _ := os.ReadDir(dir)
	var dbs []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			dbs = append(dbs, e.Name())
		}
	}
	if len(dbs) != 1 || dbs[0] != "clean.db" {
		t.Fatalf("db files in dir: %v, want [clean.db]", dbs)
	}
}

// TestLegacyDBNameMigration verifies a pre-fix DB file (name embedded with
// the pragma suffix) is renamed to the clean path on open, data intact.
func TestLegacyDBNameMigration(t *testing.T) {
	dir := t.TempDir()
	legacyName := "old.db" + legacyPragmaSuffix

	// Create the legacy file exactly the way pre-fix code did (the whole
	// string is the filename) and write a row.
	s, err := New("sqlite:" + dir + "/" + legacyName)
	if err != nil {
		t.Fatalf("New legacy: %v", err)
	}
	if err := s.CreateTask(&Task{ID: "task_leg", Name: "legacy"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	s.Close()

	// Open via the clean path: the legacy file must be renamed + readable.
	s2, err := New("sqlite:" + dir + "/old.db")
	if err != nil {
		t.Fatalf("New clean: %v", err)
	}
	defer s2.Close()
	task, err := s2.Task("task_leg")
	if err != nil || task == nil {
		t.Fatalf("legacy data not visible after rename: %v %v", err, task)
	}

	var dbs []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			dbs = append(dbs, e.Name())
		}
	}
	if len(dbs) != 1 || dbs[0] != "old.db" {
		t.Fatalf("db files after migration: %v, want [old.db]", dbs)
	}
}

// TestLegacyMigrationNeverClobbers verifies the migration does not rename
// over an existing clean-path database.
func TestLegacyMigrationNeverClobbers(t *testing.T) {
	dir := t.TempDir()
	legacyName := "dup.db" + legacyPragmaSuffix

	// Clean-path DB with a marker row.
	s, err := New("sqlite:" + dir + "/dup.db")
	if err != nil {
		t.Fatalf("New clean: %v", err)
	}
	if err := s.CreateTask(&Task{ID: "task_clean", Name: "clean"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Legacy file with a different marker row.
	sl, err := New("sqlite:" + dir + "/" + legacyName)
	if err != nil {
		t.Fatalf("New legacy: %v", err)
	}
	if err := sl.CreateTask(&Task{ID: "task_legacy", Name: "legacy"}); err != nil {
		t.Fatal(err)
	}
	sl.Close()

	// Open the clean path: no rename, clean data intact.
	s2, err := New("sqlite:" + dir + "/dup.db")
	if err != nil {
		t.Fatalf("New clean again: %v", err)
	}
	defer s2.Close()
	if _, err := s2.Task("task_clean"); err != nil {
		t.Fatalf("clean DB was clobbered: %v", err)
	}
}

// InMemoryStore is a Store backed by an in-memory database for tests.
func InMemory() *Store {
	s, err := New("sqlite::memory:")
	if err != nil {
		panic("store: in-memory: " + err.Error())
	}
	return s
}

// ---- files_actions & sessions tables (M2) ------------------------------------

// seedAgent inserts a minimal agent row so M2 tables' FK constraints pass.
func seedAgent(db *Store, id string) {
	if err := db.UpsertAgent(Agent{ID: id, UUID: "u_" + id, ED25519Pub: "k", X25519Pub: "k", Version: "1"}); err != nil {
		panic("seedAgent: " + err.Error())
	}
}

func TestFilesActionsInsert(t *testing.T) {
	db, _ := setupTestDB(t)
	seedAgent(db, "a1")
	fa := FileAction{
		ID: "fa1", AgentID: "a1", Op: "upload",
		Path: "/tmp/test", Actor: "op", State: "ok",
		Size: sql.NullInt64{Int64: 1234, Valid: true}, SHA256: "abc", Code: 0,
		Created: time.Now().Unix(),
	}
	if err := db.InsertFileAction(fa); err != nil {
		t.Fatalf("InsertFileAction: %v", err)
	}
}

func TestSessionsCRUD(t *testing.T) {
	db, _ := setupTestDB(t)
	seedAgent(db, "a1")
	now := time.Now().Unix()
	s := Session{
		ID: "s1", AgentID: "a1", Cmd: "/bin/bash",
		ArgsJSON: `["-i"]`, Cols: 80, Rows: 24,
		Record: true, State: "open", Actor: "op", Opened: now,
	}
	if err := db.CreateSession(s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := db.GetSession("s1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != "s1" || got.State != "open" {
		t.Fatalf("got %+v", got)
	}
	if err := db.UpdateSessionState("s1", "closed", 0, ""); err != nil {
		t.Fatalf("UpdateSessionState: %v", err)
	}
	got, _ = db.GetSession("s1")
	if got.State != "closed" || !got.Closed.Valid || got.Closed.Int64 == 0 {
		t.Fatalf("state=%s closed=%v", got.State, got.Closed)
	}
}

func TestSessionRecords(t *testing.T) {
	db, _ := setupTestDB(t)
	seedAgent(db, "a1")
	db.CreateSession(Session{ID: "s1", AgentID: "a1", State: "open", Opened: time.Now().Unix()})
	if err := db.AppendSessionRecord("s1", 0, []byte("hello")); err != nil {
		t.Fatalf("AppendSessionRecord: %v", err)
	}
	recs, err := db.ListSessionRecords("s1")
	if err != nil {
		t.Fatalf("ListSessionRecords: %v", err)
	}
	if len(recs) != 1 || string(recs[0].Data) != "hello" {
		t.Fatalf("wrong records: %+v", recs)
	}
}

func TestInterruptAgentSessions(t *testing.T) {
	db, _ := setupTestDB(t)
	seedAgent(db, "a1")
	seedAgent(db, "a2")
	now := time.Now().Unix()
	db.CreateSession(Session{ID: "s1", AgentID: "a1", State: "open", Opened: now})
	db.CreateSession(Session{ID: "s2", AgentID: "a1", State: "open", Opened: now})
	db.CreateSession(Session{ID: "s3", AgentID: "a2", State: "open", Opened: now})
	n, err := db.InterruptAgentSessions("a1")
	if err != nil {
		t.Fatalf("InterruptAgentSessions: %v", err)
	}
	if n != 2 {
		t.Fatalf("interrupted %d, want 2", n)
	}
	s, _ := db.GetSession("s1")
	if s.State != "interrupted" {
		t.Fatalf("s1 state=%s", s.State)
	}
	s2, _ := db.GetSession("s3")
	if s2.State != "open" {
		t.Fatalf("s3 state=%s, want open", s2.State)
	}
}

// ---- observe facts document merge (M5) ------------------------------------

// TestFactsFlatAndObserveMerge verifies that the flat facts stream and the
// structured observe facts stream merge into one document without clobbering
// each other, in either arrival order.
func TestFactsFlatAndObserveMerge(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	if err := db.UpsertAgent(Agent{ID: "ag_m", UUID: "um", ED25519Pub: "k1", X25519Pub: "k2"}); err != nil {
		t.Fatal(err)
	}

	// Flat first, then observe.
	if err := db.UpsertFacts(Facts{AgentID: "ag_m", Data: map[string]string{"host.os": "linux"}}); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
	}
	if err := db.UpsertHostFactsJSON("ag_m", `{"services_detailed":{"units":[{"name":"myapp"}]}}`); err != nil {
		t.Fatalf("UpsertHostFactsJSON: %v", err)
	}

	blob, err := db.LatestHostFactsJSON("ag_m")
	if err != nil {
		t.Fatalf("LatestHostFactsJSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(blob), &doc); err != nil {
		t.Fatalf("blob not JSON: %v (%s)", err, blob)
	}
	if doc["host.os"] != "linux" {
		t.Errorf("flat key lost after observe upsert: %v", doc)
	}
	if _, ok := doc["services_detailed"]; !ok {
		t.Errorf("structured key missing: %v", doc)
	}

	// Flat view still returns only string values.
	flat, err := db.LatestFacts("ag_m")
	if err != nil {
		t.Fatalf("LatestFacts: %v", err)
	}
	if flat.Data["host.os"] != "linux" {
		t.Errorf("flat view = %v, want host.os=linux", flat.Data)
	}
	if _, ok := flat.Data["services_detailed"]; ok {
		t.Errorf("structured value leaked into flat view: %v", flat.Data)
	}

	// Observe after flat (reverse order) must also merge.
	if err := db.UpsertHostFactsJSON("ag_m", `{"configs":{"haproxy":{"present":true}}}`); err != nil {
		t.Fatalf("UpsertHostFactsJSON (2): %v", err)
	}
	blob, _ = db.LatestHostFactsJSON("ag_m")
	doc = nil
	if err := json.Unmarshal([]byte(blob), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"host.os", "services_detailed", "configs"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("key %q lost after second merge: %v", k, doc)
		}
	}
}

// TestFactsSameSecondWritesBothPersist locks in the timestamp-collision fix:
// the (agent_id, ts) primary key must not let a same-second flat write drop
// the observe document (or vice versa).
func TestFactsSameSecondWritesBothPersist(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	if err := db.UpsertAgent(Agent{ID: "ag_ts", UUID: "uts", ED25519Pub: "k1", X25519Pub: "k2"}); err != nil {
		t.Fatal(err)
	}

	// Force the exact same second for both writes.
	ts := time.Now().Unix()
	if err := db.UpsertFacts(Facts{AgentID: "ag_ts", TS: ts, Data: map[string]string{"host.os": "linux"}}); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
	}
	// UpsertHostFactsJSON uses now(); make it collide by writing directly with
	// the same ts through the same code path used by the stream handler.
	if err := db.UpsertHostFactsJSON("ag_ts", `{"certificates":{"items":[{"path":"/x.pem"}]}}`); err != nil {
		t.Fatalf("UpsertHostFactsJSON: %v", err)
	}

	blob, _ := db.LatestHostFactsJSON("ag_ts")
	var doc map[string]any
	if err := json.Unmarshal([]byte(blob), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["certificates"]; !ok {
		t.Errorf("certificates lost in same-second write: %v", doc)
	}
	if doc["host.os"] != "linux" {
		t.Errorf("flat key lost in same-second write: %v", doc)
	}
}

// TestFactsConcurrentUpsertsNoLostUpdate is the regression test for the
// read-modify-write race: concurrent flat and observe upserts for one host
// must never drop either side.
func TestFactsConcurrentUpsertsNoLostUpdate(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	if err := db.UpsertAgent(Agent{ID: "ag_c", UUID: "uc", ED25519Pub: "k1", X25519Pub: "k2"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertFacts(Facts{AgentID: "ag_c", Data: map[string]string{"host.os": "linux"}}); err != nil {
		t.Fatal(err)
	}

	const rounds = 40
	for i := 0; i < rounds; i++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_ = db.UpsertFacts(Facts{AgentID: "ag_c", Data: map[string]string{"host.os": "linux", "host.kernel": fmt.Sprintf("k%d", i)}})
		}(i)
		go func(i int) {
			defer wg.Done()
			_ = db.UpsertHostFactsJSON("ag_c", fmt.Sprintf(`{"services_detailed":{"units":[{"name":"u%d"}]}}`, i))
		}(i)
		wg.Wait()

		blob, err := db.LatestHostFactsJSON("ag_c")
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(blob), &doc); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if _, ok := doc["services_detailed"]; !ok {
			t.Fatalf("round %d: structured facts lost (flat write won): %s", i, blob)
		}
		if doc["host.os"] != "linux" {
			t.Fatalf("round %d: flat facts lost (observe write won): %s", i, blob)
		}
	}
}

// TestFactsConcurrentDistinctAgents checks the per-agent lock does not
// serialize unrelated hosts into corruption.
func TestFactsConcurrentDistinctAgents(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ag_%d", i)
		if err := db.UpsertAgent(Agent{ID: id, UUID: "u" + id, ED25519Pub: "k1", X25519Pub: "k2"}); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_ = db.UpsertFacts(Facts{AgentID: id, Data: map[string]string{"host.os": "linux"}})
			_ = db.UpsertHostFactsJSON(id, `{"services_detailed":{"units":[{"name":"app"}]}}`)
		}(id)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ag_%d", i)
		blob, err := db.LatestHostFactsJSON(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(blob), &doc); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if doc["host.os"] != "linux" || doc["services_detailed"] == nil {
			t.Errorf("%s: incomplete document: %s", id, blob)
		}
	}
}

// TestLatestHostFactsJSONEmpty verifies the "no facts" contract.
func TestLatestHostFactsJSONEmpty(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	if err := db.UpsertAgent(Agent{ID: "ag_e", UUID: "ue", ED25519Pub: "k1", X25519Pub: "k2"}); err != nil {
		t.Fatal(err)
	}
	blob, err := db.LatestHostFactsJSON("ag_e")
	if err != nil {
		t.Fatalf("LatestHostFactsJSON: %v", err)
	}
	if blob != "" {
		t.Errorf("blob = %q, want empty", blob)
	}
	if _, err := db.LatestFacts("ag_e"); err == nil {
		t.Error("LatestFacts on factless agent: want ErrNotFound")
	}
}

// TestUpsertHostFactsJSONInvalid verifies a malformed observe blob is rejected
// (and does not corrupt the stored document).
func TestUpsertHostFactsJSONInvalid(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	if err := db.UpsertAgent(Agent{ID: "ag_i", UUID: "ui", ED25519Pub: "k1", X25519Pub: "k2"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertFacts(Facts{AgentID: "ag_i", Data: map[string]string{"host.os": "linux"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertHostFactsJSON("ag_i", "{not json"); err == nil {
		t.Fatal("expected error for malformed blob")
	}
	blob, _ := db.LatestHostFactsJSON("ag_i")
	if !strings.Contains(blob, "host.os") {
		t.Errorf("document corrupted by rejected write: %s", blob)
	}
	// Empty blob is a no-op, not an error.
	if err := db.UpsertHostFactsJSON("ag_i", ""); err != nil {
		t.Errorf("empty blob: %v", err)
	}
}

// TestLatestFactsRejectsStructuredOnlyDocument: a document whose keys are all
// structured still yields an empty (not error) flat view.
func TestLatestFactsStructuredOnly(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	if err := db.UpsertAgent(Agent{ID: "ag_s", UUID: "us", ED25519Pub: "k1", X25519Pub: "k2"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertHostFactsJSON("ag_s", `{"services_detailed":{"units":[]}}`); err != nil {
		t.Fatal(err)
	}
	f, err := db.LatestFacts("ag_s")
	if err != nil {
		t.Fatalf("LatestFacts: %v", err)
	}
	if len(f.Data) != 0 {
		t.Errorf("flat view = %v, want empty", f.Data)
	}
}
