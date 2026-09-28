package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestApprovalsAPI covers the approvals REST surface end to end: list,
// get, approve (admin only), deny, and error paths.
func TestApprovalsAPI(t *testing.T) {
	apiH, streamH, srv := startAPITest(t)

	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	st := apiH.Store()
	var dispatched *pb.Decision
	apr := approvals.New(st, streamH, sse.New(), nil)
	apr.SetIdentity(ident)
	apr.RegisterDispatcher("exec", func(req *store.ApprovalRequest, d *pb.Decision) error {
		dispatched = d
		return nil
	})
	apiH.SetApprovals(apr)

	// Create a pending request (simulating a parked dispatch).
	req, err := apr.NewRequest(approvals.NewRequestParams{
		ActionClass: "exec", AgentID: "ag_api", ExecutionID: "exec_x", RunID: "run_x",
		Actor: "alice", ActorRole: "operator", MatchedRules: []string{"r1"},
		Payload: map[string]any{"cmd": "rm"},
	})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	// 1. List (no auth → local admin).
	resp, err := http.Get(srv.URL + "/api/v1/approvals")
	if err != nil {
		t.Fatalf("GET /approvals: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d; body = %s", resp.StatusCode, body)
	}
	var page map[string]any
	_ = json.Unmarshal(body, &page)
	items, _ := page["approvals"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 approval, got %d (%s)", len(items), body)
	}

	// 2. Get by id.
	resp, err = http.Get(srv.URL + "/api/v1/approvals/" + req.ID)
	if err != nil {
		t.Fatalf("GET /approvals/{id}: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d; body = %s", resp.StatusCode, body)
	}
	var one map[string]any
	_ = json.Unmarshal(body, &one)
	if one["state"] != "pending" {
		t.Fatalf("state = %v, want pending", one["state"])
	}

	// 3. Enable auth; viewer cannot approve.
	apiH.SetAuth("admin-token", "op-token", "view-token")
	req2, _ := http.NewRequest("POST", srv.URL+"/api/v1/approvals/"+req.ID+"/approve", nil)
	req2.Header.Set("Authorization", "Bearer view-token")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST approve (viewer): %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer approve status = %d, want 403", resp2.StatusCode)
	}

	// 4. Admin approves → dispatcher called with a signed allow decision.
	req3, _ := http.NewRequest("POST", srv.URL+"/api/v1/approvals/"+req.ID+"/approve", nil)
	req3.Header.Set("Authorization", "Bearer admin-token")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("POST approve (admin): %v", err)
	}
	body, _ = io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("admin approve status = %d; body = %s", resp3.StatusCode, body)
	}
	if dispatched == nil {
		t.Fatal("dispatcher not called on approve")
	}
	if dispatched.Effect != policy.EffectAllow || dispatched.ApprovalId != req.ID {
		t.Fatalf("dispatched decision = %+v", dispatched)
	}

	// 5. Approving again → 409 (already decided).
	req4, _ := http.NewRequest("POST", srv.URL+"/api/v1/approvals/"+req.ID+"/approve", nil)
	req4.Header.Set("Authorization", "Bearer admin-token")
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("POST approve again: %v", err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusConflict {
		t.Fatalf("re-approve status = %d, want 409", resp4.StatusCode)
	}

	// 6. Approve an unknown id → 404.
	req5, _ := http.NewRequest("POST", srv.URL+"/api/v1/approvals/apr_missing/approve", nil)
	req5.Header.Set("Authorization", "Bearer admin-token")
	resp5, err := http.DefaultClient.Do(req5)
	if err != nil {
		t.Fatalf("POST approve missing: %v", err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusNotFound {
		t.Fatalf("approve missing status = %d, want 404", resp5.StatusCode)
	}

	// 7. Deny a fresh request (with reason).
	req6, _ := apr.NewRequest(approvals.NewRequestParams{
		ActionClass: "exec", AgentID: "ag_api", Payload: map[string]any{"cmd": "rm"},
	})
	denyBody, _ := json.Marshal(map[string]string{"reason": "too risky"})
	req7, _ := http.NewRequest("POST", srv.URL+"/api/v1/approvals/"+req6.ID+"/deny", bytes.NewReader(denyBody))
	req7.Header.Set("Authorization", "Bearer admin-token")
	req7.Header.Set("Content-Type", "application/json")
	resp7, err := http.DefaultClient.Do(req7)
	if err != nil {
		t.Fatalf("POST deny: %v", err)
	}
	body, _ = io.ReadAll(resp7.Body)
	resp7.Body.Close()
	if resp7.StatusCode != http.StatusOK {
		t.Fatalf("deny status = %d; body = %s", resp7.StatusCode, body)
	}
	// Verify persisted.
	stored, _ := apr.Get(req6.ID)
	if stored.State != "denied" || stored.DecisionReason != "too risky" {
		t.Fatalf("after deny: %+v", stored)
	}
}
