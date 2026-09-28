package store

import (
	"testing"
	"time"
)

// TestApprovalRequestLifecycle covers create → read → list → decide.
func TestApprovalRequestLifecycle(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	req := &ApprovalRequest{
		ID: "apr_1", ActionClass: "exec", PayloadJSON: `{"cmd":"rm -rf /"}`,
		AgentID: "ag_1", ExecutionID: "exec_1", RunID: "run_1",
		Actor: "alice", ActorRole: "operator", MatchedRules: "r1",
		State: "pending", CreatedUnix: time.Now().Unix(),
		ExpiresUnix: time.Now().Unix() + 3600,
	}
	if err := db.CreateApprovalRequest(req); err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	got, err := db.GetApprovalRequest("apr_1")
	if err != nil {
		t.Fatalf("GetApprovalRequest: %v", err)
	}
	if got == nil {
		t.Fatal("expected row, got nil")
	}
	if got.ActionClass != "exec" || got.RunID != "run_1" || got.State != "pending" {
		t.Fatalf("unexpected row: %+v", got)
	}

	// Missing id → nil, no error.
	missing, err := db.GetApprovalRequest("apr_missing")
	if err != nil || missing != nil {
		t.Fatalf("missing lookup: got %v, err %v", missing, err)
	}

	// Decide pending → approved.
	if err := db.DecideApprovalRequest("apr_1", "approved", "bob", ""); err != nil {
		t.Fatalf("DecideApprovalRequest: %v", err)
	}
	got, _ = db.GetApprovalRequest("apr_1")
	if got.State != "approved" || got.DecidedBy != "bob" {
		t.Fatalf("after approve: %+v", got)
	}
	if got.DecidedUnix == 0 {
		t.Fatal("decided_unix should be set")
	}

	// A decided request cannot transition again.
	if err := db.DecideApprovalRequest("apr_1", "denied", "carol", "too late"); err == nil {
		t.Fatal("expected error deciding an already-approved request")
	}
}

// TestApprovalRequestLazyExpiry: pending rows past expiry are surfaced as
// expired by list, and can never be decided afterwards.
func TestApprovalRequestLazyExpiry(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	now := time.Now().Unix()
	req := &ApprovalRequest{
		ID: "apr_exp", ActionClass: "exec", PayloadJSON: `{}`,
		AgentID: "ag_1", State: "pending",
		CreatedUnix: now - 7200, ExpiresUnix: now - 3600,
	}
	if err := db.CreateApprovalRequest(req); err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	reqs, err := db.ListApprovalRequests("", 50)
	if err != nil {
		t.Fatalf("ListApprovalRequests: %v", err)
	}
	if len(reqs) != 1 || reqs[0].State != "expired" {
		t.Fatalf("expected 1 expired, got %+v", reqs)
	}

	// Expired requests cannot be approved retroactively.
	if err := db.DecideApprovalRequest("apr_exp", "approved", "bob", ""); err == nil {
		t.Fatal("expected error approving an expired request")
	}
}

// TestApprovalRequestExplicitExpiry drives ExpireApprovalRequests directly.
func TestApprovalRequestExplicitExpiry(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	now := time.Now().Unix()
	for _, r := range []*ApprovalRequest{
		{ID: "apr_old", ActionClass: "exec", PayloadJSON: `{}`, AgentID: "ag_1",
			RunID: "run_old", ExecutionID: "exec_old", State: "pending",
			CreatedUnix: now - 7200, ExpiresUnix: now - 1},
		{ID: "apr_fresh", ActionClass: "exec", PayloadJSON: `{}`, AgentID: "ag_1",
			State: "pending", CreatedUnix: now, ExpiresUnix: now + 3600},
	} {
		if err := db.CreateApprovalRequest(r); err != nil {
			t.Fatalf("CreateApprovalRequest: %v", err)
		}
	}

	expired, err := db.ExpireApprovalRequests()
	if err != nil {
		t.Fatalf("ExpireApprovalRequests: %v", err)
	}
	if len(expired) != 1 || expired[0].ID != "apr_old" {
		t.Fatalf("expected only apr_old expired, got %+v", expired)
	}
}
