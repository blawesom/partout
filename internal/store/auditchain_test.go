// Audit hash-chain tests (PRD Decision 5, 1.0 gate): append → verify OK;
// tamper → verify fails and names the row; legacy rows are backfilled
// lazily on the first append; concurrent appends leave no broken links.
package store

import (
	"fmt"
	"sync"
	"testing"
)

func appendAuditEvents(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := range n {
		if err := s.AppendAudit(AuditEvent{
			TS:      int64(1700000000 + i),
			Kind:    "test.event",
			Actor:   "tester",
			Payload: fmt.Sprintf(`{"i":%d}`, i),
		}); err != nil {
			t.Fatalf("AppendAudit %d: %v", i, err)
		}
	}
}

// TestAuditChain_AppendAndVerify appends rows and verifies the chain holds.
func TestAuditChain_AppendAndVerify(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	const n = 10
	appendAuditEvents(t, s, n)

	res, err := s.VerifyAuditChain()
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !res.OK || res.RowsChecked != n {
		t.Fatalf("verify = {OK:%v rows:%d}, want {OK:true rows:%d}", res.OK, res.RowsChecked, n)
	}
}

// TestAuditChain_TamperDetection edits a row's payload behind the store's
// back and verifies the chain walk fails and names the tampered row.
func TestAuditChain_TamperDetection(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	const n = 10
	appendAuditEvents(t, s, n)

	// Tamper with row 5's payload via direct SQL.
	if _, err := s.db.Exec(`UPDATE audit_events SET payload='{"i":"tampered"}' WHERE id=5`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err := s.VerifyAuditChain()
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.OK {
		t.Fatal("tampered chain verified OK; want failure")
	}
	if res.BrokenRowID != 5 {
		t.Fatalf("broken_row_id = %d, want 5", res.BrokenRowID)
	}
	if res.Reason == "" {
		t.Error("empty failure reason")
	}
}

// TestAuditChain_LegacyBackfill simulates a pre-upgrade database: audit rows
// written without chain data and no audit_chain_state row. The first append
// must backfill the chain over the legacy rows (in id order, without
// rewriting their content) and verification must pass.
func TestAuditChain_LegacyBackfill(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	// Seed three pre-chain rows and drop the head state, as a v25 database
	// upgraded to v26 would look.
	for i := range 3 {
		if _, err := s.db.Exec(`INSERT INTO audit_events(ts, kind, actor, payload) VALUES(?,?,?,?)`,
			int64(1700000000+i), "legacy.event", "legacy", fmt.Sprintf(`{"i":%d}`, i)); err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM audit_chain_state`); err != nil {
		t.Fatal(err)
	}

	appendAuditEvents(t, s, 1)

	res, err := s.VerifyAuditChain()
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !res.OK || res.RowsChecked != 4 {
		t.Fatalf("verify = {OK:%v rows:%d}, want {OK:true rows:4}", res.OK, res.RowsChecked)
	}

	// Legacy row content must be untouched.
	var payload string
	if err := s.db.QueryRow(`SELECT payload FROM audit_events WHERE id=1`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if payload != `{"i":0}` {
		t.Errorf("legacy row payload = %q, want untouched {\"i\":0}", payload)
	}

	// Head state must now track the last row.
	var lastID int64
	var lastHash string
	if err := s.db.QueryRow(`SELECT last_id, last_hash FROM audit_chain_state WHERE id=1`).Scan(&lastID, &lastHash); err != nil {
		t.Fatal(err)
	}
	if lastID != 4 || lastHash == "" {
		t.Errorf("chain head = (%d, %q), want (4, non-empty)", lastID, lastHash)
	}
}

// TestAuditChain_ConcurrentAppends exercises the single-writer store from
// parallel goroutines (SQLite serializes the write transactions) and checks
// the resulting chain has no broken links.
func TestAuditChain_ConcurrentAppends(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	// Sequential prefix.
	appendAuditEvents(t, s, 5)

	// Parallel batch.
	const workers, perWorker = 4, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range perWorker {
				if err := s.AppendAudit(AuditEvent{
					TS:      1700001000,
					Kind:    "test.concurrent",
					Actor:   "tester",
					Payload: fmt.Sprintf(`{"w":%d,"i":%d}`, w, i),
				}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AppendAudit: %v", err)
		}
	}

	res, err := s.VerifyAuditChain()
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	want := int64(5 + workers*perWorker)
	if !res.OK || res.RowsChecked != want {
		t.Fatalf("verify = {OK:%v rows:%d}, want {OK:true rows:%d}", res.OK, res.RowsChecked, want)
	}
}

// TestAuditChain_EmptyLog verifies cleanly with zero rows.
func TestAuditChain_EmptyLog(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	res, err := s.VerifyAuditChain()
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !res.OK || res.RowsChecked != 0 {
		t.Fatalf("verify = {OK:%v rows:%d}, want {OK:true rows:0}", res.OK, res.RowsChecked)
	}
}

// TestAuditChain_KeyedV2 appends rows with an audit key set (algo=2, HMAC) and
// verifies the chain holds; a direct-SQL rewrite of the chain head must NOT
// verify without the key (an attacker with DB write access cannot recompute
// algo=2 rows).
func TestAuditChain_KeyedV2(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s.SetAuditKey(key)
	s.SetAuditKeyID("test:keyid")

	appendAuditEvents(t, s, 5)

	// All rows are algo=2 now.
	var algo int
	if err := s.db.QueryRow(`SELECT algo FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&algo); err != nil {
		t.Fatalf("algo scan: %v", err)
	}
	if algo != AuditAlgoV2 {
		t.Fatalf("algo = %d, want %d", algo, AuditAlgoV2)
	}

	res, err := s.VerifyAuditChain()
	if err != nil || !res.OK || res.RowsChecked != 5 {
		t.Fatalf("verify = {OK:%v rows:%d err:%v}, want OK with 5 rows", res.OK, res.RowsChecked, err)
	}

	// Tamper a payload: verify must fail at that row even with the key (the
	// attacker in this test does not have it, but the recompute check is the
	// same code path).
	if _, err := s.db.Exec(`UPDATE audit_events SET payload='{"i":"tampered"}' WHERE id=3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err = s.VerifyAuditChain()
	if err != nil || res.OK || res.BrokenRowID != 3 {
		t.Fatalf("tampered verify = {OK:%v row:%d err:%v}, want broken at 3", res.OK, res.BrokenRowID, err)
	}
}

// TestAuditChain_KeyedVerifyWithoutKey: a database written WITH a key fails
// closed on algo=2 rows when verified without the key (e.g. wrong deployment
// restored without the identity dir).
func TestAuditChain_KeyedVerifyWithoutKey(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()
	s.SetAuditKey([]byte("0123456789abcdef0123456789abcdef"))
	s.SetAuditKeyID("test:keyid")
	appendAuditEvents(t, s, 3)

	// Reopen without the key, with the chain-state row present (a real
	// restored DB carries it; its presence also stops the legacy backfill
	// from recomputing the chain as algo=1).
	s2, _ := setupTestDB(t)
	defer s2.Close()
	headID, headHash, headKeyID, err := s.AuditChainHeadFull()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if headKeyID != "test:keyid" {
		t.Fatalf("head keyID = %q, want test:keyid", headKeyID)
	}
	if _, err := s2.db.Exec(`INSERT INTO audit_chain_state(id, last_id, last_hash, key_id) VALUES(1, ?, ?, ?)`, headID, headHash, headKeyID); err != nil {
		t.Fatalf("state: %v", err)
	}
	// Copy rows over to simulate a restored DB file.
	for i := 1; i <= 3; i++ {
		var ts int64
		var kind, actor, payload, prev, hash string
		var algo int
		if err := s.db.QueryRow(`SELECT ts, kind, actor, payload, prev_hash, hash, algo FROM audit_events WHERE id=?`, i).
			Scan(&ts, &kind, &actor, &payload, &prev, &hash, &algo); err != nil {
			t.Fatalf("copy row %d: %v", i, err)
		}
		if _, err := s2.db.Exec(`INSERT INTO audit_events(id, ts, kind, actor, agent_id, payload, prev_hash, hash, algo) VALUES(?,?,?,?,?,?,?,?,?)`,
			i, ts, kind, actor, "", payload, prev, hash, algo); err != nil {
			t.Fatalf("insert row %d: %v", i, err)
		}
	}
	res, err := s2.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("keyed rows verified OK without the key — must fail closed")
	}
	if res.Reason == "" {
		t.Fatal("empty reason")
	}
}

// TestAuditChain_MixedV1V2: legacy algo=1 rows followed by keyed algo=2 rows
// verify together when the key is set (the upgrade path).
func TestAuditChain_MixedV1V2(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()
	appendAuditEvents(t, s, 3) // algo=1 (no key yet)
	s.SetAuditKey([]byte("0123456789abcdef0123456789abcdef"))
	s.SetAuditKeyID("test:keyid")
	appendAuditEvents(t, s, 3) // algo=2

	res, err := s.VerifyAuditChain()
	if err != nil || !res.OK || res.RowsChecked != 6 {
		t.Fatalf("verify = {OK:%v rows:%d err:%v}, want OK with 6 rows", res.OK, res.RowsChecked, err)
	}
}

// TestAuditChain_Head verifies AuditChainHead tracks the last row and the
// installed key id.
func TestAuditChain_Head(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()
	s.SetAuditKey([]byte("0123456789abcdef0123456789abcdef"))
	s.SetAuditKeyID("test:keyid")
	appendAuditEvents(t, s, 4)
	id, hash, keyID2, err := s.AuditChainHeadFull()
	if err != nil {
		t.Fatalf("AuditChainHead: %v", err)
	}
	if keyID2 != "test:keyid" {
		t.Fatalf("head keyID = %q, want test:keyid", keyID2)
	}
	if id != 4 || hash == "" {
		t.Fatalf("head = (%d, %q), want (4, non-empty)", id, hash)
	}
}

// TestAuditChain_KeyRotationGuard: the chain state pins the key id — a store
// reopened with a DIFFERENT key sees the stored id (main.go refuses to start
// on mismatch) and fails closed on verify; the same key verifies fine.
func TestAuditChain_KeyRotationGuard(t *testing.T) {
	s, dir := setupTestDB(t)
	keyA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	s.SetAuditKey(keyA)
	s.SetAuditKeyID("k:aaaa")
	appendAuditEvents(t, s, 3)

	stored, err := s.AuditChainKeyID()
	if err != nil || stored != "k:aaaa" {
		t.Fatalf("AuditChainKeyID = %q, %v; want k:aaaa", stored, err)
	}

	// Reopen the same DB file with a different key: stored id is still the
	// old one (that is what main.go's startup guard compares), and verify
	// fails closed on the algo=2 rows.
	s2, err := New("sqlite:" + dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	keyB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	s2.SetAuditKey(keyB)
	s2.SetAuditKeyID("k:bbbb")
	stored2, err := s2.AuditChainKeyID()
	if err != nil || stored2 != "k:aaaa" {
		t.Fatalf("reopened AuditChainKeyID = %q, %v; want k:aaaa (chain pins its key)", stored2, err)
	}
	res, err := s2.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("verify with the wrong key must fail closed on algo=2 rows")
	}

	// Fresh DB: no pinned key yet — any key is accepted.
	s3, _ := setupTestDB(t)
	defer s3.Close()
	if id, err := s3.AuditChainKeyID(); err != nil || id != "" {
		t.Fatalf("fresh AuditChainKeyID = %q, %v; want empty", id, err)
	}
}

// TestAuditChain_RestartSameKeyVerifies: rows written under a keyed chain
// still verify after a process restart with the SAME key (persistence of the
// chain + state row across reopen).
func TestAuditChain_RestartSameKeyVerifies(t *testing.T) {
	s, dir := setupTestDB(t)
	key := []byte("cccccccccccccccccccccccccccccccc")
	s.SetAuditKey(key)
	s.SetAuditKeyID("k:cccc")
	appendAuditEvents(t, s, 5)
	s.Close()

	s2, err := New("sqlite:" + dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.SetAuditKey(key)
	s2.SetAuditKeyID("k:cccc")
	res, err := s2.VerifyAuditChain()
	if err != nil || !res.OK || res.RowsChecked != 5 {
		t.Fatalf("verify after restart = {OK:%v rows:%d err:%v}, want OK with 5 rows", res.OK, res.RowsChecked, err)
	}
	if id, _ := s2.AuditChainKeyID(); id != "k:cccc" {
		t.Fatalf("key id after restart = %q, want k:cccc", id)
	}
	// And new appends continue the same chain.
	appendAuditEvents(t, s2, 2)
	res, err = s2.VerifyAuditChain()
	if err != nil || !res.OK || res.RowsChecked != 7 {
		t.Fatalf("verify after post-restart appends = {OK:%v rows:%d err:%v}, want OK with 7", res.OK, res.RowsChecked, err)
	}
}
