package packages_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/packages"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestApplyRequireApprovalParksAndApprove is the M4 packages E2E loop:
// a require_approval rule on pkg.apply parks the apply on an approval
// request (no op dispatched); admin approval re-dispatches the exact
// payload and the action row completes.
func TestApplyRequireApprovalParksAndApprove(t *testing.T) {
	st, pc, h, _, cleanup := newBufconnTest(t)
	defer cleanup()

	// require_approval rule for all package applies.
	if err := st.CreatePolicy("pol_pkg_appr", "pkg-apply-needs-approval", policy.Match{
		Actions: []string{policy.ActionPkgApply},
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	apr := approvals.New(st, h, sse.New(), nil)
	apr.SetIdentity(ident)
	pc.SetApprovals(apr)
	apr.RegisterDispatcher(policy.ActionPkgApply, func(req *store.ApprovalRequest, dec *pb.Decision) error {
		_, err := pc.DispatchApprovedApply(req, dec)
		return err
	})

	// 1. Real apply → parked on an approval request (no op dispatched).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = pc.Apply(ctx, "ag_test", pkgActor, []string{"bash"}, false)
	var apprErr *packages.ApprovalRequiredError
	if !errors.As(err, &apprErr) {
		t.Fatalf("Apply err = %v, want *ApprovalRequiredError", err)
	}
	if apprErr.ApprovalID == "" {
		t.Fatal("expected an approval id")
	}

	// No action row should have been recorded (the gate runs before insert).
	actions, err := st.ListPkgActions(50)
	if err != nil {
		t.Fatalf("ListPkgActions: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("expected 0 pkg actions before approval, got %d", len(actions))
	}

	// 2. Non-admin cannot approve.
	if _, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "carol", Role: "operator"}); err == nil {
		t.Fatal("operator must not approve")
	}

	// 3. Admin approval → re-dispatch; the fake agent answers, action completes.
	got, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "bob", Role: "admin"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.State != "approved" {
		t.Fatalf("after approve: %+v", got)
	}

	actions, err = st.ListPkgActions(50)
	if err != nil {
		t.Fatalf("ListPkgActions after: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 pkg action after approval, got %d", len(actions))
	}
	a := actions[0]
	if a.Status != "succeeded" || a.DrySummary == "" {
		t.Fatalf("action = %+v, want succeeded with summary", a)
	}
}
