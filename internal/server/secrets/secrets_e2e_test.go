package secrets_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	agentsecrets "github.com/blawesom/partout/internal/agent/secrets"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/secrets"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

type env struct {
	st       *store.Store
	mgr      *secrets.Manager
	agent    *identity.Identity
	cache    *agentsecrets.Cache
	cacheDir string
	cancel   context.CancelFunc
}

func startServer(t *testing.T) *env {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_sec", UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	sseB := sse.New()
	lg := log.New(io.Discard, "srv: ", 0)
	h := stream.NewHandler(st, sseB, lg)
	mgr, err := secrets.New(st, h, master, lg)
	if err != nil {
		t.Fatalf("secrets.New: %v", err)
	}

	// Agent-side cache (real implementation).
	secDir := t.TempDir()
	cache, err := agentsecrets.New(secDir, id.X25519Priv)
	if err != nil {
		t.Fatalf("agent secrets cache: %v", err)
	}

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
	agentClient := pb.NewAgentStreamClient(conn)
	s, err := agentClient.Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	t.Cleanup(cancel)

	// Handshake.
	chEnv, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv challenge: %v", err)
	}
	ch := chEnv.GetChallenge()
	ts := time.Now().Unix()
	if err := s.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: id.UUID, Ts: ts, Sig: id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, ts)),
		}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}

	// Fake agent loop: the real cache handles SECRET_MATERIALIZE.
	go func() {
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			sm := down.GetSecretMaterialize()
			if sm == nil {
				continue
			}
			if _, err := cache.Handle(sm); err != nil {
				t.Errorf("agent cache Handle(%s): %v", sm.Ref, err)
			}
		}
	}()

	// Wait for the server to register the session. Handshake completion and
	// session registration are asynchronous, so returning before this point
	// lets a fast Materialize race the registration and fail with
	// "no active session" under load.
	deadline := time.Now().Add(5 * time.Second)
	for h.AgentSession("ag_sec") == nil {
		if time.Now().After(deadline) {
			t.Fatal("agent session not registered within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	return &env{st: st, mgr: mgr, agent: id, cache: cache, cacheDir: secDir, cancel: cancel}
}

func materialize(t *testing.T, e *env, agentID, name, ref string) int64 {
	t.Helper()
	var v int64
	var err error
	for i := 0; i < 20; i++ {
		v, err = e.mgr.Materialize(agentID, name, ref)
		if err == nil {
			return v
		}
		if i == 19 {
			t.Fatalf("Materialize(%s): %v", name, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return v
}

func waitForCache(t *testing.T, c *agentsecrets.Cache, ref string, timeout time.Duration) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if v, ok := c.Get(ref); ok {
			return v, true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "", false
}

// waitForValue waits until the cache holds want (or times out).
func waitForValue(t *testing.T, c *agentsecrets.Cache, ref, want string, timeout time.Duration) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if v, ok := c.Get(ref); ok && v == want {
			return v, true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "", false
}

func mustSecretID(t *testing.T, e *env, name string) string {
	t.Helper()
	v, err := e.mgr.Get(name)
	if err != nil {
		t.Fatalf("Get(%s): %v", name, err)
	}
	return v.ID
}

func TestSecretMaterializeE2E(t *testing.T) {
	e := startServer(t)

	if _, err := e.mgr.CreateSecret("db-pass", "s3cr3t-value", "", 0, "admin"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	v := materialize(t, e, "ag_sec", "db-pass", "run_1")
	if v != 1 {
		t.Fatalf("version = %d, want 1", v)
	}

	val, ok := waitForCache(t, e.cache, "db-pass", 2*time.Second)
	if !ok {
		t.Fatal("agent cache did not receive db-pass")
	}
	if val != "s3cr3t-value" {
		t.Fatalf("value = %q, want s3cr3t-value", val)
	}

	// Audit binding: which version, which agent, which run.
	binds, err := e.mgr.Bindings("db-pass", 10)
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if len(binds) != 1 || binds[0].Version != 1 || binds[0].AgentID != "ag_sec" || binds[0].Ref != "run_1" {
		t.Fatalf("bindings = %+v", binds)
	}

	// Read API returns metadata only, never the value.
	view, err := e.mgr.Get("db-pass")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.Version != 1 || view.AgentCount < 1 || view.Name != "db-pass" {
		t.Fatalf("view = %+v", view)
	}

	// ttl=0: unknown refs are unavailable (fail closed).
	if _, ok := e.cache.Get("no-such-ref"); ok {
		t.Fatal("unknown ref: want not ok")
	}
}

func TestSecretRotateInvalidates(t *testing.T) {
	e := startServer(t)

	if _, err := e.mgr.CreateSecret("api-key", "old-value", "", 0, "admin"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	materialize(t, e, "ag_sec", "api-key", "run_1")
	if v, ok := waitForCache(t, e.cache, "api-key", 2*time.Second); !ok || v != "old-value" {
		t.Fatalf("initial materialize: %q ok=%v", v, ok)
	}

	v, err := e.mgr.RotateSecret("api-key", "new-value", "admin")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if v != 2 {
		t.Fatalf("rotated version = %d, want 2", v)
	}
	secID := mustSecretID(t, e, "api-key")
	old, err := e.st.GetSecretVersion(secID, 1)
	if err != nil {
		t.Fatalf("GetSecretVersion(1): %v", err)
	}
	if !old.Revoked {
		t.Fatal("v1 should be revoked after rotation")
	}

	// Next materialization serves v2 to the agent.
	if got := materialize(t, e, "ag_sec", "api-key", "run_2"); got != 2 {
		t.Fatalf("post-rotation version = %d, want 2", got)
	}
	if _, ok := waitForValue(t, e.cache, "api-key", "new-value", 2*time.Second); !ok {
		t.Fatal("after rotation: cache does not hold new-value within 2s")
	}

	// Revoke: no active version → materialization fails.
	if err := e.mgr.RevokeSecret("api-key", "admin"); err != nil {
		t.Fatalf("RevokeSecret: %v", err)
	}
	if _, err := e.mgr.Materialize("ag_sec", "api-key", "run_3"); err == nil {
		t.Fatal("materialize after revoke: want error")
	}
}

func TestSecretSelectorBinding(t *testing.T) {
	e := startServer(t)

	// Agent has no tag:env → the binding must fail closed.
	if _, err := e.mgr.CreateSecret("prod-only", "v", "tag:env=prod", 0, "admin"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if _, err := e.mgr.Materialize("ag_sec", "prod-only", "run_1"); err == nil {
		t.Fatal("materialize outside selector: want error")
	}

	// Tag the agent → now it matches.
	if err := e.st.SetTag("ag_sec", "env", "prod"); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	if _, err := e.mgr.Materialize("ag_sec", "prod-only", "run_2"); err != nil {
		t.Fatalf("materialize inside selector: %v", err)
	}
}

// TestSecretOfflineCache verifies the agent persists only the SEALED form
// for offline_ttl secrets, and that a fresh cache process can still open it
// (simulating an agent restart while the server is unreachable).
func TestSecretOfflineCache(t *testing.T) {
	e := startServer(t)

	if _, err := e.mgr.CreateSecret("offline-tok", "cached-secret", "", 3600, "admin"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	materialize(t, e, "ag_sec", "offline-tok", "run_1")
	val, ok := waitForCache(t, e.cache, "offline-tok", 2*time.Second)
	if !ok || val != "cached-secret" {
		t.Fatalf("materialize: %q ok=%v", val, ok)
	}

	// The on-disk file must NOT contain the plaintext.
	// (A fresh cache from the same dir must still be able to open it.)
	fresh, err := agentsecrets.New(e.cacheDir, e.agent.X25519Priv)
	if err != nil {
		t.Fatalf("reopen cache: %v", err)
	}
	v, ok := fresh.Get("offline-tok")
	if !ok || v != "cached-secret" {
		t.Fatalf("offline reopen: %q ok=%v, want cached-secret", v, ok)
	}

	// A different agent (fresh identity) must NOT be able to open the
	// sealed cache — it is E2E-bound to the original X25519 key.
	other, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	otherCache, err := agentsecrets.New(e.cacheDir, other.X25519Priv)
	if err != nil {
		t.Fatalf("other cache: %v", err)
	}
	v, ok = otherCache.Get("offline-tok")
	if ok {
		t.Fatalf("cross-agent open succeeded: %q — E2E binding is broken", v)
	}
}
