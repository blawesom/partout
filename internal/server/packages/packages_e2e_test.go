package packages_test

import (
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"database/sql"

	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/externaldata"
	"github.com/blawesom/partout/internal/server/packages"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// --- helpers ---------------------------------------------------------------

func newBufconnTest(t *testing.T) (*store.Store, *packages.Controller, *stream.Handler, *grpc.ClientConn, func()) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	sseB := sse.New()
	lg := log.New(io.Discard, "srv:", 0)
	h := stream.NewHandler(st, sseB, lg)
	pc := packages.New(st, h, sseB, lg)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	agentClient := pb.NewAgentStreamClient(conn)
	s, err := agentClient.Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Handshake: use a generated identity.
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_test", UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	// Register os-release facts so the controller can derive the OSV ecosystem.
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_test", Data: map[string]string{
		"host.distro": "ubuntu", "host.distro_version": "24.04",
	}}); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
	}
	env, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv challenge: %v", err)
	}
	ch := env.GetChallenge()
	ts := time.Now().Unix()
	if err := s.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: id.UUID, Ts: ts, Sig: id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, ts)),
		}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}

	// Fake agent: handle PKG_OP, respond with canned data.
	fakeInstalled := map[string]string{
		"coreutils":  "9.4-1",
		"bash":       "5.2.21",
		"gzip":       "1.13",
		"python3.12": "3.12.3",
	}
	fakeAvailable := map[string]string{
		"coreutils":  "9.4-2ubuntu1",
		"bash":       "5.2.21-2",
		"gzip":       "1.13-1",
		"python3.12": "3.12.3-1ubuntu0.5",
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			pkgOp := down.GetPkgOp()
			if pkgOp == nil {
				continue
			}
			var res *pb.PkgResult
			switch pkgOp.Kind {
			case pb.PkgOpKind_PKG_LIST_UPDATES:
				updates := make([]*pb.PkgUpdate, 0, len(fakeInstalled))
				for name, installed := range fakeInstalled {
					if avail, ok := fakeAvailable[name]; ok && avail != installed {
						updates = append(updates, &pb.PkgUpdate{
							Name:      name,
							Installed: installed,
							Available: avail,
						})
					}
				}
				res = &pb.PkgResult{OpId: pkgOp.OpId, Kind: pkgOp.Kind, Code: 0, Updates: updates}

			case pb.PkgOpKind_PKG_APPLY:
				// Fake apply: fake before state, then fake after state
				before := make([]*pb.PkgUpdate, 0, len(fakeInstalled))
				after := make([]*pb.PkgUpdate, 0, len(fakeInstalled))
				for name, installed := range fakeInstalled {
					before = append(before, &pb.PkgUpdate{Name: name, Installed: installed})
					avail, ok := fakeAvailable[name]
					if ok {
						after = append(after, &pb.PkgUpdate{Name: name, Installed: avail})
					} else {
						after = append(after, &pb.PkgUpdate{Name: name, Installed: installed})
					}
				}
				res = &pb.PkgResult{
					OpId: pkgOp.OpId, Kind: pkgOp.Kind, Code: 0,
					Before:        before,
					After:         after,
					DryRunSummary: "3 packages upgraded (simulated)",
					Applied:       !pkgOp.DryRun,
					AppliedCount:  3,
				}

			default:
				res = &pb.PkgResult{OpId: pkgOp.OpId, Kind: pkgOp.Kind, Code: 500,
					Error: "unsupported package operation"}
			}
			if err := s.Send(&pb.Envelope{
				Kind:    pb.EnvelopeKind_PKG_RESULT,
				CorrId:  pkgOp.OpId,
				Payload: &pb.Envelope_PkgResult{PkgResult: res},
			}); err != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_test") == nil {
		if time.Now().After(deadline) {
			cancel()
			conn.Close()
			st.Close()
			t.Fatal("session not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cleanup := func() {
		s.CloseSend()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		cancel()
		conn.Close()
		st.Close()
	}
	return st, pc, h, conn, cleanup
}

var pkgActor = packages.Actor{Principal: "local", Role: "admin"}

// --- tests -----------------------------------------------------------------

func TestListUpdates(t *testing.T) {
	st, pc, _, _, cleanup := newBufconnTest(t)
	defer cleanup()
	ctx := context.Background()

	ups, err := pc.ListUpdates(ctx, "ag_test", pkgActor)
	if err != nil {
		t.Fatalf("ListUpdates: %v", err)
	}
	if len(ups) != 4 {
		t.Fatalf("got %d updates, want 4: %+v", len(ups), ups)
	}
	names := make(map[string]bool)
	for _, u := range ups {
		if u.Installed == "" || u.Available == "" {
			t.Errorf("update %s: installed=%q available=%q", u.Name, u.Installed, u.Available)
		}
		names[u.Name] = true
	}
	for want := range fakeInstalled {
		if !names[want] {
			t.Errorf("missing expected update: %s", want)
		}
	}

	// Audit row recorded.
	events, err := st.AuditPage("", "", 0, 20, 0)
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	pkgEvents := 0
	for _, ev := range events {
		if ev.Kind == "package" {
			pkgEvents++
		}
	}
	if pkgEvents < 1 {
		t.Fatalf("no package audit event found")
	}
}

func TestApplyDryRun(t *testing.T) {
	st, pc, _, _, cleanup := newBufconnTest(t)
	defer cleanup()
	ctx := context.Background()

	action, err := pc.Apply(ctx, "ag_test", pkgActor, nil, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if action.Status != "succeeded" {
		t.Fatalf("status=%q, want succeeded", action.Status)
	}
	if action.Kind != "dry_run" {
		t.Fatalf("kind=%q, want dry_run", action.Kind)
	}
	if action.AppliedCount != 3 {
		t.Fatalf("applied_count=%d, want 3", action.AppliedCount)
	}
	if strings.Count(action.DrySummary, "packages") == 0 {
		t.Fatalf("empty dry summary: %q", action.DrySummary)
	}
	if action.BeforeJSON == "" || action.AfterJSON == "" {
		t.Fatalf("missing before/after journal")
	}

	// Store row recorded.
	stored, err := st.GetPkgAction(action.ID)
	if err != nil {
		t.Fatalf("GetPkgAction: %v", err)
	}
	if stored.Status != "succeeded" {
		t.Fatalf("stored status=%q", stored.Status)
	}
}

func TestApplyReal(t *testing.T) {
	_, pc, _, _, cleanup := newBufconnTest(t)
	defer cleanup()
	ctx := context.Background()

	action, err := pc.Apply(ctx, "ag_test", pkgActor, nil, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if action.Status != "succeeded" {
		t.Fatalf("status=%q, want succeeded", action.Status)
	}
	if action.Kind != "apply" {
		t.Fatalf("kind=%q, want apply", action.Kind)
	}
	if action.AppliedCount != 3 {
		t.Fatalf("applied_count=%d, want 3", action.AppliedCount)
	}
}

// --- store tests -----------------------------------------------------------

// fakeInstalled is the shared map for fake PKG_RESULT data.
var fakeInstalled = map[string]string{
	"coreutils":  "9.4-1",
	"bash":       "5.2.21",
	"gzip":       "1.13",
	"python3.12": "3.12.3",
}

func TestPkgActionCRUD(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	action := &store.PkgAction{
		AgentID:      "ag_test",
		Kind:         "apply",
		Status:       "running",
		DrySummary:   "3 upgraded",
		AppliedCount: 3,
	}
	if err := st.InsertPkgAction(action); err != nil {
		t.Fatalf("InsertPkgAction: %v", err)
	}

	// Finalize.
	beforeJSON, _ := store.MarshalPkgUpdates([]store.PkgUpdateJSON{
		{Name: "bash", Installed: "5.2.21"},
	})
	afterJSON, _ := store.MarshalPkgUpdates([]store.PkgUpdateJSON{
		{Name: "bash", Installed: "5.2.21-2"},
	})
	if err := st.FinalizePkgAction(action.ID, "succeeded", "3 upgraded", beforeJSON, afterJSON, 3, ""); err != nil {
		t.Fatalf("FinalizePkgAction: %v", err)
	}

	// Get.
	stored, err := st.GetPkgAction(action.ID)
	if err != nil {
		t.Fatalf("GetPkgAction: %v", err)
	}
	if stored.Status != "succeeded" || stored.AppliedCount != 3 {
		t.Fatalf("bad stored row: %+v", stored)
	}

	// List.
	listed, err := st.ListPkgActions(50)
	if err != nil {
		t.Fatalf("ListPkgActions: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d actions, want 1", len(listed))
	}

	// Unmarshal.
	before, err := store.UnmarshalPkgUpdates(stored.BeforeJSON)
	if err != nil {
		t.Fatalf("UnmarshalPkgUpdates (before): %v", err)
	}
	if len(before) != 1 || before[0].Name != "bash" {
		t.Fatalf("bad before: %+v", before)
	}
}

// TestSecurityScan (M5.1): one scan pass over the connected fake agent —
// vuln cache seeded so no network is touched — persists findings + meta.
func TestSecurityScan(t *testing.T) {
	st, pc, _, _, cleanup := newBufconnTest(t)
	defer cleanup()

	// Air-gapped refresher: cache-only correlation, so the scan never
	// touches OSV (test stays deterministic + offline).
	t.Setenv("PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH", "1")

	// Seed the vuln cache (Correlate short-circuits on a fresh cache row,
	// so the scan never touches OSV). Ecosystem for the test agent's
	// os-release facts (ubuntu 24.04) is "Ubuntu:24.04".
	err := st.InsertVulns([]store.VulnRow{
		{VulnID: "CVE-2025-0001", Package: "bash", Ecosystem: "Ubuntu:24.04", Version: "5.2.21",
			Severity: sql.NullFloat64{Float64: 7.8, Valid: true}, Summary: "priv esc", URL: "https://osv.dev/CVE-2025-0001"},
		{VulnID: "CVE-2025-0002", Package: "bash", Ecosystem: "Ubuntu:24.04", Version: "5.2.21",
			Severity: sql.NullFloat64{Float64: 8.6, Valid: true}, Summary: "rce", URL: "https://osv.dev/CVE-2025-0002"},
	})
	if err != nil {
		t.Fatalf("InsertVulns: %v", err)
	}
	pc.SetRefresher(externaldata.New(st, log.New(io.Discard, "", 0)))

	n, err := pc.SecurityScan(context.Background())
	if err != nil {
		t.Fatalf("SecurityScan: %v", err)
	}
	if n != 1 {
		t.Fatalf("scanned = %d, want 1", n)
	}

	meta, err := st.SecurityScanMetaFor("ag_test")
	if err != nil {
		t.Fatalf("SecurityScanMetaFor: %v", err)
	}
	if meta.UpdatesTotal != 4 {
		t.Errorf("updates_total = %d, want 4 (all fake packages have an update)", meta.UpdatesTotal)
	}
	if meta.SecurityUpdates != 1 {
		t.Errorf("security_updates = %d, want 1 (only bash is correlated)", meta.SecurityUpdates)
	}

	fs, err := st.SecurityFindingsFor("ag_test")
	if err != nil {
		t.Fatalf("SecurityFindingsFor: %v", err)
	}
	if len(fs) != 1 || fs[0].Pkg != "bash" {
		t.Fatalf("findings = %+v, want one bash finding", fs)
	}
	if fs[0].VulnCount != 2 {
		t.Errorf("vuln_count = %d, want 2", fs[0].VulnCount)
	}
	if fs[0].MaxCVSS != 7.5 { // "high" label -> representative 7.5
		t.Errorf("max_cvss = %v, want 7.5", fs[0].MaxCVSS)
	}
	if fs[0].VulnIDs != "CVE-2025-0001,CVE-2025-0002" {
		t.Errorf("vuln_ids = %q, want both CVEs", fs[0].VulnIDs)
	}

	// A second scan pass replaces (no duplicate findings).
	if _, err := pc.SecurityScan(context.Background()); err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if fs, _ := st.SecurityFindingsFor("ag_test"); len(fs) != 1 {
		t.Fatalf("after rescan findings = %d, want 1", len(fs))
	}
}
