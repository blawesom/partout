package control_test

import (
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestDispatchRequireApprovalParksAndReDispatches is the M4 E2E loop:
// a require_approval rule parks the run, admin approval signs a fresh
// allow decision and re-dispatches the exact payload to the agent.
func TestDispatchRequireApprovalParksAndReDispatches(t *testing.T) {
	// 1. Store + agent.
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_apr", UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetRole("ag_apr", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// require_approval rule for rm -rf.
	if err := st.CreatePolicy("pol_approval", "approval-rm", policy.Match{
		CommandRegex: `rm\s+-rf`,
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// 2. Server identity + control + approvals (wired like main.go).
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	h.SetServerPubKey(ident.PubB64())
	ctl := control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0))
	ctl.SetIdentity(ident)
	apr := approvals.New(st, h, sseB, log.New(io.Discard, "apr: ", 0))
	apr.SetIdentity(ident)
	apr.OnExecExpired = func(execID string) {
		if err := ctl.FinalizeExecution(execID); err != nil {
			t.Logf("finalize expired exec: %v", err)
		}
	}
	apr.RegisterDispatcher(policy.ActionExec, ctl.DispatchApprovedCommand)
	ctl.SetApprovals(apr)

	// 3. bufconn + agent handshake.
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	streamClient, err := pb.NewAgentStreamClient(conn).Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	env, err := streamClient.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	ch := env.GetChallenge()
	if ch == nil {
		t.Fatalf("expected CHALLENGE, got %s", env.Kind)
	}
	sig := id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, time.Now().Unix()))
	if err := streamClient.Send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{AgentUuid: id.UUID, Ts: time.Now().Unix(), Sig: sig}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_apr") == nil {
		if time.Now().After(deadline) {
			t.Fatal("session not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Agent-side reader: captures the (re-)dispatched command.
	type gotCmd struct {
		cmd *pb.Command
	}
	cmdCh := make(chan *pb.Command, 1)
	go func() {
		for {
			env, err := streamClient.Recv()
			if err != nil {
				return
			}
			if c := env.GetCommand(); c != nil {
				cmdCh <- c
				return
			}
		}
	}()

	// 4. Dispatch → parked on an approval request.
	res, err := ctl.Dispatch(ctx, control.DispatchRequest{
		Selector: "role:web", Cmd: "rm", Args: []string{"-rf", "/tmp/junk"},
		TimeoutS: 10, CreatedBy: "alice", ActorRole: "operator",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(res.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(res.Runs))
	}
	run := res.Runs[0]
	if run.State != "awaiting_approval" || run.ApprovalID == "" {
		t.Fatalf("run = %+v, want awaiting_approval with approval id", run)
	}

	// No command may have been sent to the agent yet.
	select {
	case c := <-cmdCh:
		t.Fatalf("command dispatched before approval: %+v", c)
	case <-time.After(200 * time.Millisecond):
	}

	// Execution must not be finalized while the run is parked.
	exec, err := st.GetExecution(res.ExecutionID)
	if err != nil {
		t.Fatalf("GetExecution: %v", err)
	}
	if exec.State == "succeeded" || exec.State == "failed" {
		t.Fatalf("execution finalized early: %s", exec.State)
	}

	// 5. A non-admin cannot approve.
	if _, err := apr.Approve(run.ApprovalID, approvals.Actor{Principal: "alice", Role: "operator"}); err == nil {
		t.Fatal("operator must not approve")
	}

	// 6. Admin approval → re-dispatch with a signed approval decision.
	if _, err := apr.Approve(run.ApprovalID, approvals.Actor{Principal: "bob", Role: "admin"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	var sent *pb.Command
	select {
	case sent = <-cmdCh:
	case <-time.After(2 * time.Second):
		t.Fatal("command not re-dispatched after approval")
	}
	if sent.RunId != run.RunID || sent.Cmd != "rm" {
		t.Fatalf("re-dispatched wrong command: %+v", sent)
	}
	dec := sent.Decision
	if dec == nil {
		t.Fatal("re-dispatched command has no decision")
	}
	if dec.Effect != policy.EffectAllow || dec.ApprovalId != run.ApprovalID {
		t.Fatalf("decision = %+v, want allow + approval %s", dec, run.ApprovalID)
	}
	version, _ := st.PolicyBundleVersion()
	if !policy.VerifyDecision(ident.Pub, dec.RunId, version, dec.Effect,
		dec.MatchedRules, dec.ActorRole, dec.ApprovalId, dec.Sig) {
		t.Fatal("re-dispatched decision signature failed to verify")
	}

	// Run state advanced to delivered.
	deadline2 := time.Now().Add(2 * time.Second)
	for {
		runs, _ := st.ListRunsForExecution(res.ExecutionID)
		if len(runs) == 1 && (runs[0].State == "delivered" || runs[0].State == "running") {
			break
		}
		if time.Now().After(deadline2) {
			t.Fatalf("run state = %v", runs)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Audit trail: the request + the dispatch.
	events, err := st.ListAudit("approval", 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected approval audit events")
	}
	evts2, err := st.ListAudit("approval.dispatch", 10)
	if err != nil {
		t.Fatalf("ListAudit dispatch: %v", err)
	}
	if len(evts2) == 0 {
		t.Fatal("expected approval.dispatch audit event")
	}

	streamClient.CloseSend()
}

// TestDispatchRequireApprovalFailsClosedWithoutEngine: without the approvals
// controller wired, require_approval fails closed as a deny.
func TestDispatchRequireApprovalFailsClosedWithoutEngine(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_aprc", UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetRole("ag_aprc", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := st.CreatePolicy("pol_approval2", "approval-rm2", policy.Match{
		CommandRegex: `rm\s+-rf`,
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	h.SetServerPubKey(ident.PubB64())
	ctl := control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0)) // no SetApprovals
	ctl.SetIdentity(ident)

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	streamClient, err := pb.NewAgentStreamClient(conn).Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	env, err := streamClient.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	ch := env.GetChallenge()
	if ch == nil {
		t.Fatalf("expected CHALLENGE, got %s", env.Kind)
	}
	sig := id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, time.Now().Unix()))
	_ = streamClient.Send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{AgentUuid: id.UUID, Ts: time.Now().Unix(), Sig: sig}},
	})
	deadline := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_aprc") == nil {
		if time.Now().After(deadline) {
			t.Fatal("session not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}

	res, err := ctl.Dispatch(ctx, control.DispatchRequest{
		Selector: "role:web", Cmd: "rm", Args: []string{"-rf", "/"},
		TimeoutS: 10, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(res.Runs) != 1 || res.Runs[0].State != "denied" {
		t.Fatalf("run = %+v, want denied (fail closed)", res.Runs)
	}
	streamClient.CloseSend()
}
