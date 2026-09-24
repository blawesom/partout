package store

import (
	"database/sql"
	"strings"
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
		ID:      "fa1", AgentID: "a1", Op: "upload",
		Path: "/tmp/test", Actor: "op", State: "ok",
		Size:  sql.NullInt64{Int64: 1234, Valid: true}, SHA256: "abc", Code: 0,
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
