package stream_test

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

	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/store"
)

// startBufServer wires a stream.Handler on an in-memory bufconn gRPC server.
// Returns the store, handler, and client conn.
func startBufServer(t *testing.T, st *store.Store) (*stream.Handler, *grpc.ClientConn) {
	t.Helper()
	h := stream.NewHandler(st, nil, log.New(io.Discard, "srv: ", 0))
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
	return h, conn
}

// TestFullHandshakeLifecycle verifies: register agent → handshake → connected
// → heartbeat/facts → disconnect.
func TestFullHandshakeLifecycle(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(id.Ed25519Pub)
	xpubB64 := base64.StdEncoding.EncodeToString(id.X25519Pub)
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_test", UUID: id.UUID, ED25519Pub: pubB64, X25519Pub: xpubB64,
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	_, conn := startBufServer(t, st)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agentClient := pb.NewAgentStreamClient(conn)
	streamClient, err := agentClient.Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// 1. Receive challenge.
	env, err := streamClient.Recv()
	if err != nil {
		t.Fatalf("Recv challenge: %v", err)
	}
	ch := env.GetChallenge()
	if ch == nil {
		t.Fatalf("expected CHALLENGE, got %s", env.Kind)
	}

	// 2. Reply with signed AuthProof.
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

	// Give the server a moment to mark connected.
	time.Sleep(100 * time.Millisecond)
	a, err := st.Agent("ag_test")
	if err != nil {
		t.Fatalf("Agent: %v", err)
	}
	if a.State != "connected" {
		t.Fatalf("state = %q, want connected", a.State)
	}

	// 3. Send a facts batch.
	if err := streamClient.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_FACTS_BATCH,
		Payload: &pb.Envelope_Facts{Facts: &pb.FactsBatch{
			HostId: "ag_test",
			Full:   true,
			Facts:  map[string]string{"distro": "debian", "version": "12"},
		}},
	}); err != nil {
		t.Fatalf("Send facts: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	facts, err := st.LatestFacts("ag_test")
	if err != nil {
		t.Fatalf("LatestFacts: %v", err)
	}
	if facts.Data["distro"] != "debian" {
		t.Errorf("distro = %q, want debian", facts.Data["distro"])
	}

	// 4. Send a heartbeat.
	if err := streamClient.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_HEARTBEAT,
		Payload: &pb.Envelope_Heartbeat{Heartbeat: &pb.Heartbeat{
			AgentVersion: "v0.1.0",
		}},
	}); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}

	// 5. Close the stream.
	if err := streamClient.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	// Drain until the server's side finishes.
	for {
		if _, err := streamClient.Recv(); err != nil {
			break
		}
	}
	time.Sleep(100 * time.Millisecond)

	a, err = st.Agent("ag_test")
	if err != nil {
		t.Fatalf("Agent after disconnect: %v", err)
	}
	if a.State != "disconnected" {
		t.Errorf("state after disconnect = %q, want disconnected", a.State)
	}
}

// TestHandshakeBadSignature verifies a bad signature rejects the handshake and
// does NOT mark the agent connected.
func TestHandshakeBadSignature(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	good, _ := identity.LoadOrGenerate(t.TempDir())
	other, _ := identity.LoadOrGenerate(t.TempDir())
	pubB64 := base64.StdEncoding.EncodeToString(good.Ed25519Pub)
	xpubB64 := base64.StdEncoding.EncodeToString(good.X25519Pub)
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_bad", UUID: good.UUID, ED25519Pub: pubB64, X25519Pub: xpubB64,
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	_, conn := startBufServer(t, st)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agentClient := pb.NewAgentStreamClient(conn)
	streamClient, err := agentClient.Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	env, err := streamClient.Recv()
	if err != nil {
		t.Fatalf("Recv challenge: %v", err)
	}
	ch := env.GetChallenge()
	if ch == nil {
		t.Fatalf("expected CHALLENGE, got %s", env.Kind)
	}

	// Sign with the WRONG key.
	ts := time.Now().Unix()
	badSig := other.Sign(hsauth.BuildMsg(ch.Nonce, good.UUID, ts))
	if err := streamClient.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: good.UUID, Ts: ts, Sig: badSig,
		}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}

	// The server should close the stream.
	_, _ = streamClient.Recv()
	time.Sleep(100 * time.Millisecond)

	a, err := st.Agent("ag_bad")
	if err != nil {
		t.Fatalf("Agent: %v", err)
	}
	if a.State == "connected" {
		t.Fatal("agent marked connected despite bad signature")
	}
}
