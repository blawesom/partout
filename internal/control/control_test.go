package control_test

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

	agentexec "github.com/blawesom/partout/internal/agent/exec"
	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestEndToEndDispatch runs the full loop: server + agent on bufconn,
// dispatch a command, agent executes it, streams output, server records
// succeeded + captured output.
func TestEndToEndDispatch(t *testing.T) {
	// 1. Store.
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// 2. Seed the agent (identity + public keys).
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(id.Ed25519Pub)
	xpubB64 := base64.StdEncoding.EncodeToString(id.X25519Pub)
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_e2e", UUID: id.UUID, ED25519Pub: pubB64, X25519Pub: xpubB64,
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	// Give the host a role so the selector resolves it.
	if err := st.SetRole("ag_e2e", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// 3. Handler + control.
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	ctl := control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0))

	// 4. bufconn gRPC server.
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// 5. Agent connects + handshakes.
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
	agentClient := pb.NewAgentStreamClient(conn)
	streamClient, err := agentClient.Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Handshake.
	env, err := streamClient.Recv()
	if err != nil {
		t.Fatalf("Recv challenge: %v", err)
	}
	ch := env.GetChallenge()
	if ch == nil {
		t.Fatalf("expected CHALLENGE, got %s", env.Kind)
	}
	ts := time.Now().Unix()
	sig := id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, ts))
	if err := streamClient.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: id.UUID, Ts: ts, Sig: sig,
		}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // let server mark connected

	// Wait until the server has registered the session (the dispatch path
	// requires an active session; polling here avoids a timing race under load).
	deadlineSession := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_e2e") == nil {
		if time.Now().After(deadlineSession) {
			t.Fatalf("session not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 6. Agent command loop: receive down, execute, stream output + result.
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		for {
			down, err := streamClient.Recv()
			if err != nil {
				return
			}
			cmd := down.GetCommand()
			if cmd == nil {
				continue
			}
			// Execute.
			seq := 0
			onChunk := func(c agentexec.Chunk) {
				s := pb.OutputStream_OUTPUT_STDOUT
				if c.Stream == "stderr" {
					s = pb.OutputStream_OUTPUT_STDERR
				}
				streamClient.Send(&pb.Envelope{
					Kind: pb.EnvelopeKind_COMMAND_OUTPUT,
					Payload: &pb.Envelope_Output{Output: &pb.CommandOutput{
						RunId: cmd.RunId, ChunkSeq: uint64(seq), Stream: s, Data: c.Data,
					}},
				})
				seq++
			}
			res, _ := agentexec.Run(ctx, cmd.Cmd, cmd.Args, "", nil, cmd.TimeoutS, onChunk)
			// Result.
			streamClient.Send(&pb.Envelope{
				Kind: pb.EnvelopeKind_COMMAND_RESULT,
				Payload: &pb.Envelope_Result{Result: &pb.CommandResult{
					RunId: cmd.RunId, ExitCode: res.ExitCode, State: res.State, DurationMs: res.DurationMS,
				}},
			})
		}
	}()

	// 7. Dispatch a command.
	res, err := ctl.Dispatch(ctx, control.DispatchRequest{
		Selector:  "role:web",
		Cmd:       "echo",
		Args:      []string{"hello", "e2e"},
		TimeoutS:  10,
		CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(res.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(res.Runs))
	}
	if !res.Runs[0].Delivered {
		t.Fatalf("run not delivered: %v", res.Errors)
	}
	runID := res.Runs[0].RunID
	execID := res.ExecutionID

	// 8. Wait for the run to reach a terminal state + output captured.
	deadline := time.Now().Add(5 * time.Second)
	for {
		runs, _ := st.ListRunsForExecution(execID)
		if len(runs) == 1 && runs[0].State == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			state := "none"
			if len(runs) == 1 {
				state = runs[0].State
			}
			t.Fatalf("run did not reach succeeded (state=%s)", state)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 9. Verify captured output.
	chunks, err := st.ListOutput(runID)
	if err != nil {
		t.Fatalf("ListOutput: %v", err)
	}
	var out strings.Builder
	for _, c := range chunks {
		out.Write(c.Data)
	}
	if got := strings.TrimSpace(out.String()); got != "hello e2e" {
		t.Fatalf("output = %q, want 'hello e2e'", got)
	}

	// 10. Verify the audit log has the dispatch.
	events, err := st.ListAudit("exec.dispatch", 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}

	// Stop the agent loop.
	streamClient.CloseSend()
	select {
	case <-agentDone:
	case <-time.After(2 * time.Second):
		t.Fatal("agent loop did not stop")
	}
}

// TestDispatchPolicyDeny exercises the server-side policy deny gate:
//  1. Creates a deny rule (command_regex "secret" → deny).
//  2. Dispatches a matching command → agent never sees it, run = denied.
//  3. Dispatches a non-matching command → agent sees it, run = delivered.
func TestDispatchPolicyDeny(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// Seed agent.
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(id.Ed25519Pub)
	xpubB64 := base64.StdEncoding.EncodeToString(id.X25519Pub)
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_pd", UUID: id.UUID, ED25519Pub: pubB64, X25519Pub: xpubB64,
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetRole("ag_pd", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// Create a deny policy.
	if err := st.CreatePolicy("pol_no_secret", "no-secret", policy.Match{
		CommandRegex: "secret",
	}, policy.EffectDeny, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// Server identity (signs decisions).
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}

	// Handler + control.
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	h.SetServerPubKey(ident.PubB64())
	ctl := control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0))
	ctl.SetIdentity(ident)

	// bufconn server.
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// Agent connect + handshake.
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
	agentClient := pb.NewAgentStreamClient(conn)
	streamClient, err := agentClient.Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	// Handshake.
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
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: id.UUID, Ts: time.Now().Unix(), Sig: sig,
		}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// Wait for session.
	deadlineSession := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_pd") == nil {
		if time.Now().After(deadlineSession) {
			t.Fatal("session not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 1. Dispatch matching the deny rule → should be denied.
	res, err := ctl.Dispatch(ctx, control.DispatchRequest{
		Selector: "role:web", Cmd: "cat", Args: []string{"secret.txt"},
		TimeoutS: 10, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(res.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(res.Runs))
	}
	if res.Runs[0].State != "denied" {
		t.Fatalf("run state = %s, want denied (errors: %v)", res.Runs[0].State, res.Errors)
	}

	// Verify execution aggregate is terminal (failed).
	exec, err := st.GetExecution(res.ExecutionID)
	if err != nil {
		t.Fatalf("GetExecution: %v", err)
	}
	if exec.State != "failed" {
		t.Fatalf("execution state = %s, want failed", exec.State)
	}

	// Audit has policy.deny event.
	events, err := st.ListAudit("policy.deny", 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected policy.deny audit event")
	}

	// 2. Dispatch non-matching command → should be delivered.
	res2, err := ctl.Dispatch(ctx, control.DispatchRequest{
		Selector: "role:web", Cmd: "ls", Args: []string{"/tmp"},
		TimeoutS: 10, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("Dispatch non-matching: %v", err)
	}
	if len(res2.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(res2.Runs))
	}
	if !res2.Runs[0].Delivered {
		t.Fatalf("non-matching run not delivered: %v", res2.Errors)
	}

	streamClient.CloseSend()
}
