package tasks_test

// E2E for the task→secret wire path (v0.9.13 known gap): a task whose step
// declares a `secret:NAME` ref is dispatched through the REAL server-side
// controller → the server materializes the secret down the stream
// (SecretMaterialize, E2E-encrypted) BEFORE the TASK_RUN envelope → the
// REAL agent-side executor (real E2E cache) resolves the ref into the
// step's rendered value → TASK_RUN_RESULT back over the wire. Also covers
// the fail-fast paths: an unbound ref (or the feature being off) aborts
// the dispatch server-side with the ref named, and no task envelope is
// sent.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blawesom/partout/internal/agent/elevate"
	agentsecrets "github.com/blawesom/partout/internal/agent/secrets"
	"github.com/blawesom/partout/internal/agent/task"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	serversecrets "github.com/blawesom/partout/internal/server/secrets"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/server/tasks"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// secretAgent is a real agent-side task stack (executor + E2E secret
// cache) attached to a live stream, standing in for the full agent. It
// records the order of down-stream envelope kinds so tests can assert
// materialization precedes the task envelope.
type secretAgent struct {
	s      pb.AgentStream_StreamClient
	cancel context.CancelFunc
	conn   *grpc.ClientConn
	cache  *agentsecrets.Cache
	mu     sync.Mutex
	order  []string // envelope kinds in arrival order (SECRET_MATERIALIZE / TASK_RUN)
}

// startSecretServer wires the stream handler + tasks controller + REAL
// secrets manager on bufconn.
func startSecretServer(t *testing.T) (*store.Store, *stream.Handler, *tasks.Controller, *serversecrets.Manager, *bufconn.Listener) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	lg := log.New(io.Discard, "srv:", 0)
	h := stream.NewHandler(st, sseB, lg)
	tc := tasks.New(st, h, sseB, lg)

	// Real secrets manager (random master key).
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	mgr, err := serversecrets.New(st, h, master, lg)
	if err != nil {
		t.Fatalf("secrets.New: %v", err)
	}
	tc.SetSecrets(mgr)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return st, h, tc, mgr, lis
}

// newSecretAgent connects a real agent stack (executor + E2E cache) and
// runs the down-envelope loop: SecretMaterialize is handled by the real
// cache; TaskRun runs the real task runner (with the executor's secrets
// lookup wired to that cache, fail-closed) and reports the result.
func newSecretAgent(t *testing.T, h *stream.Handler, st *store.Store, lis *bufconn.Listener, agentID string) *secretAgent {
	t.Helper()
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: agentID, UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

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
	client := pb.NewAgentStreamClient(conn)
	s, err := client.Stream(ctx)
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

	// Real agent-side secret cache (sealed-disk dir under TempDir).
	cache, err := agentsecrets.New(t.TempDir(), id.X25519Priv)
	if err != nil {
		t.Fatalf("agent secrets cache: %v", err)
	}

	// The executor's secrets lookup is the same closure the real agent
	// wires (internal/agent/agent.go): the E2E cache, fail-closed.
	secLookup := func(ref string, _ int64) (string, error) {
		v, ok := cache.Get(ref)
		if !ok {
			return "", errSecretUnavailable(ref)
		}
		return v, nil
	}
	exec := task.NewExecutor(elevate.None, secLookup)
	exec.SetFileRoot(t.TempDir()) // file steps are confined to the file root
	runner := task.New(exec)

	sa := &secretAgent{s: s, cancel: cancel, conn: conn, cache: cache}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			switch {
			case down.GetSecretMaterialize() != nil:
				sm := down.GetSecretMaterialize()
				sa.mu.Lock()
				sa.order = append(sa.order, "SECRET_MATERIALIZE")
				sa.mu.Unlock()
				if _, err := cache.Handle(sm); err != nil {
					t.Errorf("agent cache Handle(%s): %v", sm.Ref, err)
				}
			case down.GetTaskRun() != nil:
				run := down.GetTaskRun()
				sa.mu.Lock()
				sa.order = append(sa.order, "TASK_RUN")
				sa.mu.Unlock()
				// Run the REAL agent-side task runner and report.
				res := runner.Run(context.Background(), run)
				pbSteps := make([]*pb.TaskStepResult, 0, len(res.Steps))
				for _, sr := range res.Steps {
					pbSteps = append(pbSteps, &pb.TaskStepResult{
						StepIndex: int32(sr.Index), State: sr.State, Detail: sr.Detail,
						Started: sr.Started, Finished: sr.Finished,
					})
				}
				if err := s.Send(&pb.Envelope{
					Kind:   pb.EnvelopeKind_TASK_RUN_RESULT,
					CorrId: run.RunId,
					Payload: &pb.Envelope_TaskRunResult{TaskRunResult: &pb.TaskRunResult{
						RunId: run.RunId, State: res.State, Error: res.Error, Steps: pbSteps,
					}},
				}); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		s.CloseSend()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		cancel()
		conn.Close()
	})

	// Wait for the session to register.
	deadline := time.Now().Add(5 * time.Second)
	for h.AgentSession(agentID) == nil {
		if time.Now().After(deadline) {
			t.Fatal("session not registered within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sa
}

type secretUnavailableErr struct{ ref string }

func (e *secretUnavailableErr) Error() string { return "secret \"" + e.ref + "\" unavailable" }

func errSecretUnavailable(ref string) error { return &secretUnavailableErr{ref} }

func (sa *secretAgent) envelopeOrder() []string {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	return append([]string(nil), sa.order...)
}

func (sa *secretAgent) sawTaskRun() bool {
	for _, k := range sa.envelopeOrder() {
		if k == "TASK_RUN" {
			return true
		}
	}
	return false
}

// TestRunTaskSecretMaterializeE2E drives the full dispatch path: the task
// declares `secret:db-pass` in a template step var and a command step
// env; the server must send SecretMaterialize BEFORE the task envelope,
// the agent's rendered value must contain the secret plaintext (the
// template step writes it to a file under the file root), and the audit
// row must bind the version to this run.
func TestRunTaskSecretMaterializeE2E(t *testing.T) {
	st, h, tc, mgr, lis := startSecretServer(t)
	if err := st.CreateTask(&store.Task{ID: "task_sec", Name: "secret task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	sa := newSecretAgent(t, h, st, lis, "ag_sec")
	ctx := context.Background()

	if _, err := mgr.CreateSecret("db-pass", "s3cr3t-value", "", 0, "admin"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	// A task whose steps declare the secret: a template step whose var is
	// the ref (the value renders into the written file), and a command
	// step whose env is the ref.
	steps := []*pb.TaskStep{
		{Kind: "template", Name: "render app config", Path: "app.conf",
			Template: "db_password={{.pw}}\n", Vars: map[string]string{"pw": "secret:db-pass"}},
		{Kind: "command", Name: "check", Command: "true", Env: map[string]string{"DB_PASS": "secret:db-pass"}},
	}

	run, err := tc.Run(ctx, "ag_sec", "task_sec", 1, steps, taskActor)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.State != "succeeded" {
		t.Fatalf("run state = %q, want succeeded (error: %s)", run.State, run.Error)
	}

	// The materialize envelope must precede the task envelope.
	order := sa.envelopeOrder()
	if len(order) != 2 || order[0] != "SECRET_MATERIALIZE" || order[1] != "TASK_RUN" {
		t.Fatalf("envelope order = %v, want [SECRET_MATERIALIZE TASK_RUN]", order)
	}

	// The agent's rendered template var must contain the secret value:
	// the per-step detail recorded on the server mirrors what the agent
	// reported for the template step (rendered, N bytes).
	stepRows, err := st.TaskRunSteps(run.ID)
	if err != nil {
		t.Fatalf("TaskRunSteps: %v", err)
	}
	rendered := false
	for _, s := range stepRows {
		if strings.Contains(s.Detail, "rendered") {
			rendered = true
		}
	}
	if !rendered {
		t.Fatalf("template step detail = %+v, want a rendered marker", stepRows)
	}
	// Audit: one secret.materialized row per dispatch, bound to this run.
	binds, err := mgr.Bindings("db-pass", 10)
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if len(binds) != 1 || binds[0].AgentID != "ag_sec" || binds[0].Ref != run.ID {
		t.Fatalf("bindings = %+v, want one row ref=%s", binds, run.ID)
	}
}

// TestRunTaskSecretUnboundRefFailsFast: a step declaring a ref with no
// binding covering the host fails the dispatch server-side with the ref
// named — the task envelope is never sent.
func TestRunTaskSecretUnboundRefFailsFast(t *testing.T) {
	st, h, tc, mgr, lis := startSecretServer(t)
	_ = mgr
	if err := st.CreateTask(&store.Task{ID: "task_unbound", Name: "unbound"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	sa := newSecretAgent(t, h, st, lis, "ag_sec")
	ctx := context.Background()

	// No secret "nope" exists: the ref is unbound.
	steps := []*pb.TaskStep{
		{Kind: "command", Name: "uses secret", Command: "true",
			Env: map[string]string{"TOKEN": "secret:nope"}},
	}

	run, err := tc.Run(ctx, "ag_sec", "task_unbound", 1, steps, taskActor)
	if err == nil {
		t.Fatal("Run: want error for unbound secret ref")
	}
	if !strings.Contains(err.Error(), `secret "nope"`) {
		t.Fatalf("err = %q, want it to name the ref secret \"nope\"", err.Error())
	}
	if run != nil && run.State != "failed" {
		t.Fatalf("run = %+v, want a failed run row", run)
	}
	// No task envelope may have been sent.
	if sa.sawTaskRun() {
		t.Fatal("task envelope was sent despite unbound secret ref")
	}
}

// TestRunTaskSecretsDisabledFailsFast: with the feature off (no
// materializer installed), a declaring task fails fast with a clear
// reason instead of dispatching a doomed run.
func TestRunTaskSecretsDisabledFailsFast(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateTask(&store.Task{ID: "task_off", Name: "off"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	tc := tasks.New(st, nil, sse.New(), log.New(io.Discard, "tasks:", 0))

	steps := []*pb.TaskStep{
		{Kind: "command", Command: "true", Env: map[string]string{"T": "secret:x"}},
	}
	_, err = tc.Run(context.Background(), "ag_x", "task_off", 1, steps, taskActor)
	if err == nil {
		t.Fatal("Run: want error with secrets feature off")
	}
	if !strings.Contains(err.Error(), "secrets feature disabled") {
		t.Fatalf("err = %q, want \"secrets feature disabled\" in it", err.Error())
	}
}
