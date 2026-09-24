package sessions_test

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

	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/sessions"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// startSessionsServer wires a stream handler + sessions manager on bufconn
// and runs a fake PTY agent:
//
//   - SESSION_OPEN: emits one SessionData chunk and stays open (no result),
//     so the session remains "open" until closed or interrupted.
//   - SESSION_CLOSE: emits a SessionResult (succeeded, exit 0).
func startSessionsServer(t *testing.T) (*store.Store, *sessions.Manager, func()) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
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

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	sm := sessions.New(st, h, sseB, log.New(io.Discard, "mgr: ", 0))

	lis := bufconn.Listen(1 << 20)
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	s, err := pb.NewAgentStreamClient(conn).Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Handshake.
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

	// Fake PTY loop.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			switch {
			case down.GetSessionOpen() != nil:
				o := down.GetSessionOpen()
				_ = s.Send(&pb.Envelope{
					Kind: pb.EnvelopeKind_SESSION_DATA,
					Payload: &pb.Envelope_SessionData{SessionData: &pb.SessionData{
						SessionId: o.SessionId, Seq: 0, Data: []byte("hello pty\n"),
					}},
				})
				// Stay open (no result) until SESSION_CLOSE.
			case down.GetSessionClose() != nil:
				c := down.GetSessionClose()
				_ = s.Send(&pb.Envelope{
					Kind: pb.EnvelopeKind_SESSION_RESULT,
					Payload: &pb.Envelope_SessionResult{SessionResult: &pb.SessionResult{
						SessionId: c.SessionId, ExitCode: 0, State: "succeeded", DurationMs: 1,
					}},
				})
			}
		}
	}()

	// Wait for the server to register the session.
	deadline := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_sess") == nil {
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
	return st, sm, cleanup
}

// TestSessionOpenDataClose verifies: open → data recorded → close → result
// finalizes the row (closed, exit 0), and replay returns the chunk.
func TestSessionOpenDataClose(t *testing.T) {
	st, sm, cleanup := startSessionsServer(t)
	defer cleanup()
	ctx := context.Background()

	sess, err := sm.Open(ctx, sessions.OpenRequest{
		AgentID: "ag_sess", Cmd: "/bin/sh", Cols: 80, Rows: 24,
		Record: true, Actor: "local", Role: "local",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if sess.State != "open" {
		t.Fatalf("state=%s, want open", sess.State)
	}

	// Close the session (triggers the fake agent's result).
	if err := sm.Close(sess.ID); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Wait for the result to finalize the session row.
	deadline := time.Now().Add(5 * time.Second)
	var got *store.Session
	for {
		got, err = st.GetSession(sess.ID)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got.State == "closed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session did not close (state=%s)", got.State)
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !got.ExitCode.Valid || got.ExitCode.Int32 != 0 {
		t.Fatalf("exit_code=%v, want 0", got.ExitCode)
	}

	// Replay: the recorded chunk is present.
	recs, err := sm.Replay(sess.ID)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(recs) != 1 || string(recs[0].Data) != "hello pty\n" {
		t.Fatalf("replay=%+v, want one 'hello pty\\n' frame", recs)
	}
}

func TestSessionPolicyDeny(t *testing.T) {
	st, sm, cleanup := startSessionsServer(t)
	defer cleanup()
	ctx := context.Background()

	if err := st.CreatePolicy("pol_deny_rm", "deny-rm", policy.Match{
		CommandRegex: "^rm",
	}, policy.EffectDeny, 100); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	_, err := sm.Open(ctx, sessions.OpenRequest{
		AgentID: "ag_sess", Cmd: "rm", Args: []string{"-rf", "/"},
		Actor: "local", Role: "local",
	})
	if err == nil {
		t.Fatal("expected policy deny")
	}
	if !strings.Contains(err.Error(), "denied by policy") {
		t.Fatalf("error=%v, want 'denied by policy'", err)
	}
}

func TestSessionOnDisconnect(t *testing.T) {
	st, sm, cleanup := startSessionsServer(t)
	defer cleanup()
	ctx := context.Background()

	// Open stays open (fake agent doesn't auto-finalize).
	sess, err := sm.Open(ctx, sessions.OpenRequest{
		AgentID: "ag_sess", Cmd: "/bin/sh", Actor: "local", Role: "local",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if sess.State != "open" {
		t.Fatalf("state=%s, want open", sess.State)
	}

	// Simulate agent disconnect → interrupt open sessions (D2).
	sm.OnDisconnect("ag_sess")

	got, err := st.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.State != "interrupted" {
		t.Fatalf("state=%s, want interrupted", got.State)
	}
}
