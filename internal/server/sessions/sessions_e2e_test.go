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
	st, sm, _, _, cleanup := startSessionsServerFull(t)
	return st, sm, cleanup
}

// startSessionsServerWithResult additionally returns the stream handler and a
// SESSION_RESULT sender so tests can exercise the up-envelope path directly.
func startSessionsServerWithResult(t *testing.T) (*store.Store, *sessions.Manager, *stream.Handler, func(sessionID string, exit int32, state string) error, func()) {
	t.Helper()
	return startSessionsServerFull(t)
}

// startSessionsServerFull starts the store + manager + a handshaken fake agent
// and exposes the raw stream for tests that need to send up envelopes.
func startSessionsServerFull(t *testing.T) (*store.Store, *sessions.Manager, *stream.Handler, func(sessionID string, exit int32, state string) error, func()) {
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

	// Fake PTY loop. All stream access (Send/Recv) happens through this
	// single loop; cleanup signals stop and waits for done before
	// CloseSend, so the stream is never used concurrently (race-safe).
	stop := make(chan struct{})
	done := make(chan struct{})
	type downMsg struct {
		env *pb.Envelope
		err error
	}
	down := make(chan downMsg, 1)
	launchRecv := func() {
		go func() {
			env, err := s.Recv()
			down <- downMsg{env: env, err: err}
		}()
	}
	launchRecv()
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case m := <-down:
				if m.err != nil {
					return
				}
				switch {
				case m.env.GetSessionOpen() != nil:
					o := m.env.GetSessionOpen()
					_ = s.Send(&pb.Envelope{
						Kind: pb.EnvelopeKind_SESSION_DATA,
						Payload: &pb.Envelope_SessionData{SessionData: &pb.SessionData{
							SessionId: o.SessionId, Seq: 0, Data: []byte("hello pty\n"),
						}},
					})
					// Stay open (no result) until SESSION_CLOSE.
				case m.env.GetSessionClose() != nil:
					c := m.env.GetSessionClose()
					_ = s.Send(&pb.Envelope{
						Kind: pb.EnvelopeKind_SESSION_RESULT,
						Payload: &pb.Envelope_SessionResult{SessionResult: &pb.SessionResult{
							SessionId: c.SessionId, ExitCode: 0, State: "succeeded", DurationMs: 1,
						}},
					})
				}
				launchRecv()
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

	sendResult := func(sessionID string, exit int32, state string) error {
		return s.Send(&pb.Envelope{
			Kind: pb.EnvelopeKind_SESSION_RESULT,
			Payload: &pb.Envelope_SessionResult{SessionResult: &pb.SessionResult{
				SessionId: sessionID, ExitCode: exit, State: state, DurationMs: 1,
			}},
		})
	}

	cleanup := func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		s.CloseSend()
		cancel()
		conn.Close()
		st.Close()
	}
	return st, sm, h, sendResult, cleanup
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

	// Wait for the agent's recorded data frame to land before closing. The
	// fake agent replies to SESSION_OPEN with a SESSION_DATA uplink; if we
	// closed before it was recorded, the close could drop it and the replay
	// assertion below would flake. The round trip (open → down envelope →
	// agent recv → up envelope → server record) can exceed a few seconds under
	// CI load (-race -count=2, all packages in parallel), so use a generous
	// budget; a missing frame is still a hard fail, not a hang.
	dataDeadline := time.Now().Add(20 * time.Second)
	for {
		recs, _ := sm.Replay(sess.ID)
		if len(recs) == 1 && string(recs[0].Data) == "hello pty\n" {
			break
		}
		if time.Now().After(dataDeadline) {
			t.Fatalf("recorded data frame did not arrive (recs=%+v)", recs)
		}
		time.Sleep(20 * time.Millisecond)
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

// TestSessionLateResultDoesNotResurrectInterrupted pins the D2 guarantee
// (arch §3.4): once a disconnect has marked an open session "interrupted",
// a late or replayed SESSION_RESULT from the agent must not overwrite that
// terminal state with "closed".
//
// This drives the real up-stream path (SESSION_RESULT envelope -> stream
// SessionResultHook -> manager.onSessionResult) rather than calling the
// private method, so it also guards the hook wiring.
func TestSessionLateResultDoesNotResurrectInterrupted(t *testing.T) {
	st, sm, _, sendResult, cleanup := startSessionsServerWithResult(t)
	defer cleanup()
	ctx := context.Background()

	sess, err := sm.Open(ctx, sessions.OpenRequest{
		AgentID: "ag_sess", Cmd: "/bin/sh", Actor: "local", Role: "local",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Stream drops: the server declares the session interrupted (D2).
	sm.OnDisconnect("ag_sess")
	got, err := st.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.State != "interrupted" {
		t.Fatalf("after disconnect: state=%s, want interrupted", got.State)
	}

	// A late result arrives over the stream (replay / in-flight race).
	if err := sendResult(sess.ID, 0, "succeeded"); err != nil {
		t.Fatalf("sendResult: %v", err)
	}

	// Give the hook a moment to run, then assert the state is unchanged.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err = st.GetSession(sess.ID)
		if err != nil {
			t.Fatalf("GetSession after late result: %v", err)
		}
		if got.State != "interrupted" {
			t.Fatalf("late result resurrected session: state=%s, want interrupted", got.State)
		}
		time.Sleep(20 * time.Millisecond)
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
