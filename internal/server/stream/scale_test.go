package stream_test

// Scale test (1.0 prep): one server, 100 real concurrent stream agents —
// real TCP, real gRPC, real Ed25519 challenge/response handshakes. Asserts
// all connect, all authenticate (policy bundle delivered), all disconnect
// cleanly, and no goroutines leak.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func TestScaleConcurrentAgents(t *testing.T) {
	const N = 100

	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	h := stream.NewHandler(st, sse.New(), log.New(io.Discard, "", 0))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// Seed N agents, each with its own real identity (generated once, used
	// for both the store row and the client handshake).
	type seeded struct {
		id   *identity.Identity
		uuid string
	}
	agents := make([]seeded, N)
	var idDirs []string
	for i := 0; i < N; i++ {
		dir, err := os.MkdirTemp("", "partout-scale-ident")
		if err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		idDirs = append(idDirs, dir)
		id, err := identity.LoadOrGenerate(dir)
		if err != nil {
			t.Fatalf("identity %d: %v", i, err)
		}
		agents[i] = seeded{id: id, uuid: id.UUID}
		if err := st.UpsertAgent(store.Agent{
			ID: fmt.Sprintf("ag_scale_%d", i), UUID: id.UUID,
			ED25519Pub: id.Ed25519PubB64(), X25519Pub: id.X25519PubB64(),
		}); err != nil {
			t.Fatalf("UpsertAgent %d: %v", i, err)
		}
	}
	t.Cleanup(func() {
		for _, d := range idDirs {
			_ = os.RemoveAll(d)
		}
	})

	baseGoroutines := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu     sync.Mutex
		authed int
		failed []string
	)
	reportFail := func(i int, err error) {
		mu.Lock()
		failed = append(failed, fmt.Sprintf("%d:%v", i, err))
		mu.Unlock()
	}

	// Minimal real client: dial, challenge, sign, auth proof, then consume
	// down envelopes until the server pushes the policy bundle (auth
	// succeeded) or the context is done.
	for i := 0; i < N; i++ {
		go func(i int) {
			if err := runScaleClient(ctx, lis.Addr().String(), agents[i].id, func() {
				mu.Lock()
				authed++
				mu.Unlock()
			}); err != nil {
				reportFail(i, err)
			}
		}(i)
	}

	// All N must authenticate within 60 s.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		a, f := authed, len(failed)
		mu.Unlock()
		if a >= N {
			break
		}
		if f > 0 {
			t.Fatalf("client failures: %v", failed)
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	if authed < N {
		t.Fatalf("authenticated %d/%d within 60s", authed, N)
	}
	mu.Unlock()

	// All N must show connected in the store.
	uuids := make([]string, N)
	for i := range agents {
		uuids[i] = agents[i].uuid
	}
	if err := waitForScaleState(t, st, uuids, "connected", 30*time.Second); err != nil {
		t.Fatalf("connected states: %v", err)
	}

	// Disconnect everything; the server must drop every session cleanly.
	cancel()
	if err := waitForScaleState(t, st, uuids, "disconnected", 30*time.Second); err != nil {
		t.Errorf("not all agents disconnected after cancel: %v", err)
	}

	// No goroutine leak: back to roughly the baseline (small tolerance for
	// runtime housekeeping).
	time.Sleep(500 * time.Millisecond)
	if got := runtime.NumGoroutine(); got > baseGoroutines+10 {
		t.Errorf("goroutines after teardown = %d, baseline %d (leak?)", got, baseGoroutines)
	}
}

func runScaleClient(ctx context.Context, addr string, id *identity.Identity, onAuthed func()) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	s, err := pb.NewAgentStreamClient(conn).Stream(ctx)
	if err != nil {
		return err
	}
	env, err := s.Recv()
	if err != nil {
		return err
	}
	ch := env.GetChallenge()
	if ch == nil {
		return errors.New("expected CHALLENGE, got " + env.Kind.String())
	}
	ts := time.Now().Unix()
	sig := id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, ts))
	if err := s.Send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{AgentUuid: id.UUID, Ts: ts, Sig: sig}},
	}); err != nil {
		return err
	}
	for {
		env, err := s.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean teardown
			}
			return err
		}
		if env.GetPolicyBundle() != nil {
			onAuthed()
			// Keep the stream open (consuming) until ctx is done so the
			// server sees 100 live sessions, then Recv fails and we return.
			for {
				if _, err := s.Recv(); err != nil {
					return nil
				}
			}
		}
	}
}

func waitForScaleState(t *testing.T, st *store.Store, uuids []string, want string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok := true
		for _, u := range uuids {
			ag, err := st.AgentByUUID(u)
			if err != nil || ag == nil || ag.State != want {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for all agents in state %s", want)
}
