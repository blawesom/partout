package sessions_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/sessions"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// newSessBufconn builds a bufconn server + connected fake agent that records
// every SESSION_OPEN envelope it receives.
func newSessBufconn(t *testing.T) (*store.Store, *sessions.Manager, *stream.Handler, func(), chan string) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	sseB := sse.New()
	lg := log.New(io.Discard, "srv:", 0)
	h := stream.NewHandler(st, sseB, lg)
	sm := sessions.New(st, h, sseB, lg)

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
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_sess", UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
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

	opens := make(chan string, 8)
	go func() {
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			so := down.GetSessionOpen()
			if so != nil {
				opens <- so.SessionId
			}
		}
	}()

	cleanup := func() {
		cancel()
		_ = conn.Close()
		gs.Stop()
	}
	return st, sm, h, cleanup, opens
}

// TestSessionOpenRequireApprovalParksAndApprove is the M4 sessions E2E loop:
// a require_approval rule (command_regex) parks the open (session row
// awaiting_approval, no SESSION_OPEN on the wire); admin approval sends the
// open down with the signed decision and the session goes open.
func TestSessionOpenRequireApprovalParksAndApprove(t *testing.T) {
	st, sm, h, cleanup, opens := newSessBufconn(t)
	defer cleanup()

	// A session running "vim" requires approval.
	if err := st.CreatePolicy("pol_sess_appr", "vim-needs-approval", policy.Match{
		Actions:      []string{policy.ActionExec},
		CommandRegex: "vim",
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	apr := approvals.New(st, h, sse.New(), nil)
	apr.SetIdentity(ident)
	sm.SetApprovals(apr)
	apr.RegisterDispatcher("session.open", func(req *store.ApprovalRequest, dec *pb.Decision) error {
		return sm.DispatchApprovedSession(context.Background(), req, dec)
	})

	// 1. Open → parked.
	_, err = sm.Open(context.Background(), sessions.OpenRequest{
		AgentID: "ag_sess", Cmd: "vim",
		Actor: "alice", Role: "operator",
	})
	var apprErr *sessions.ApprovalRequiredError
	if !errors.As(err, &apprErr) {
		t.Fatalf("Open err = %v, want *ApprovalRequiredError", err)
	}
	sess := apprErr.Session
	if sess == nil || sess.State != "awaiting_approval" {
		t.Fatalf("parked session = %+v, want state awaiting_approval", sess)
	}

	// No SESSION_OPEN on the wire before approval.
	select {
	case id := <-opens:
		t.Fatalf("session %s opened before approval", id)
	case <-time.After(200 * time.Millisecond):
	}

	// 2. Non-admin cannot approve.
	if _, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "carol", Role: "operator"}); err == nil {
		t.Fatal("operator must not approve")
	}

	// 3. Admin approval → open dispatched, session open.
	got, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "bob", Role: "admin"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.State != "approved" {
		t.Fatalf("after approve: %+v", got)
	}
	select {
	case sid := <-opens:
		if sid != sess.ID {
			t.Fatalf("opened session %s, want %s", sid, sess.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SESSION_OPEN not dispatched after approval")
	}
	final, err := st.GetSession(sess.ID)
	if err != nil || final == nil {
		t.Fatalf("GetSession: %v", err)
	}
	if final.State != "open" {
		t.Fatalf("session state = %s, want open", final.State)
	}
}
