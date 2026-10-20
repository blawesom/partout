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
