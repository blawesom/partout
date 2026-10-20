package packages_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/policy"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/packages"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// seedEOLCache installs EOL cache rows so the refresher resolves
// deterministic states for the test agent's os-release facts. The harness
// registers ubuntu facts; 20.04 is long past EOL, 24.04 is supported.
func seedEOLCache(t *testing.T, st *store.Store) {
	t.Helper()
	now := time.Now().Unix()
	rows := []store.EOLRow{
		{Distro: "ubuntu", Cycle: "20.04", EOLDate: "2024-05-31", FetchedAt: now},
		{Distro: "ubuntu", Cycle: "24.04", EOLDate: "2029-04-30", FetchedAt: now},
	}
	if err := st.ReplaceEOLCache(rows); err != nil {
		t.Fatalf("ReplaceEOLCache: %v", err)
	}
}

// TestApplyEOLEndedHostParksForApproval is the PRD §5.6 gate: a host whose
// OS is past end-of-support + pkg.apply + the seeded EOL rule parks on an
// approval request whose payload names the reason in plain words.
func TestApplyEOLEndedHostParksForApproval(t *testing.T) {
	st, pc, h, _, cleanup := newBufconnTest(t)
	defer cleanup()

	// Ended-EOL facts for the test agent (harness registers ubuntu).
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_test", Data: map[string]string{
		"host.distro": "ubuntu", "host.distro_version": "20.04",
	}}); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
	}
	seedEOLCache(t, st)
	pc.SetEOLProvider(func(agentID string) string {
		if agentID == "ag_test" {
			return policy.EOLEnded
		}
		return ""
	})

	// The seeded default rule (same shape as preset.Policies).
	if err := st.CreatePolicy("pol_eol_appr", "default-require-approval-eol-upgrade", policy.Match{
		Hosts: "all", Actions: []string{policy.ActionPkgApply}, EOL: policy.EOLEnded,
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

	// Real apply → parked on an approval request, nothing dispatched.
	_, err = pc.Apply(context.Background(), "ag_test", pkgActor, nil, false)
	var apprErr *packages.ApprovalRequiredError
	if !errors.As(err, &apprErr) {
		t.Fatalf("Apply err = %v, want *ApprovalRequiredError", err)
	}

	// The request payload must name the reason.
	req, err := st.GetApprovalRequest(apprErr.ApprovalID)
	if err != nil || req == nil {
		t.Fatalf("GetApprovalRequest: %v %v", req, err)
	}
	if req.ActionClass != policy.ActionPkgApply {
		t.Errorf("action_class = %q, want pkg.apply", req.ActionClass)
	}
	if !strings.Contains(req.PayloadJSON, "host OS is past end-of-support") {
		t.Errorf("payload does not name the EOL reason: %s", req.PayloadJSON)
	}
}

// TestApplyEOLSupportedHostAllowed: the same rule does not touch a host
// whose OS is still supported — the apply runs to completion.
func TestApplyEOLSupportedHostAllowed(t *testing.T) {
	st, pc, _, _, cleanup := newBufconnTest(t)
	defer cleanup()

	if err := st.UpsertFacts(store.Facts{AgentID: "ag_test", Data: map[string]string{
		"host.distro": "ubuntu", "host.distro_version": "24.04",
	}}); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
	}
	seedEOLCache(t, st)
	pc.SetEOLProvider(func(agentID string) string {
		if agentID == "ag_test" {
			return policy.EOLSupported
		}
		return ""
	})

	if err := st.CreatePolicy("pol_eol_appr", "default-require-approval-eol-upgrade", policy.Match{
		Hosts: "all", Actions: []string{policy.ActionPkgApply}, EOL: policy.EOLEnded,
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	action, err := pc.Apply(context.Background(), "ag_test", pkgActor, nil, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if action.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", action.Status)
	}
}
