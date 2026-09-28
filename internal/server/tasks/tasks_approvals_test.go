package tasks_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/server/tasks"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// newTaskBufconn builds a bufconn server + connected fake agent that answers
// TASK_RUN envelopes with a succeeded result (one step).
func newTaskBufconn(t *testing.T) (*store.Store, *tasks.Controller, *stream.Handler, func(), chan string) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	sseB := sse.New()
	lg := log.New(io.Discard, "srv:", 0)
	h := stream.NewHandler(st, sseB, lg)
	tc := tasks.New(st, h, sseB, lg)

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
		ID: "ag_task", UUID: id.UUID,
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

	runs := make(chan string, 8)
	go func() {
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			tr := down.GetTaskRun()
			if tr == nil {
				continue
			}
			runs <- tr.RunId
			res := &pb.TaskRunResult{
				RunId: tr.RunId, State: "succeeded",
				Steps: []*pb.TaskStepResult{{
					StepIndex: 0, State: "succeeded", Detail: "ok",
				}},
			}
			_ = s.Send(&pb.Envelope{
				Kind:    pb.EnvelopeKind_TASK_RUN_RESULT,
				Payload: &pb.Envelope_TaskRunResult{TaskRunResult: res},
			})
		}
	}()

	cleanup := func() {
		cancel()
		_ = conn.Close()
		gs.Stop()
	}
	return st, tc, h, cleanup, runs
}

// seedTask creates one task with a single command step; returns id + version.
func seedTask(t *testing.T, st *store.Store) (string, int) {
	t.Helper()
	taskID := "task_appr"
	if err := st.CreateTask(&store.Task{ID: taskID, Name: "appr task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	stepsJSON, _ := json.Marshal([]store.TaskStep{{
		Kind: "command", Command: "uptime",
	}})
	if err := st.UpsertTaskVersion(&store.TaskVersion{
		TaskID: taskID, Version: 1, StepsJSON: string(stepsJSON),
	}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}
	return taskID, 1
}

// TestTaskRunRequireApprovalParksAndApprove is the M4 tasks E2E loop: a
// require_approval rule on task.run parks the run (row awaiting_approval, no
// TASK_RUN on the wire); admin approval re-dispatches it and the run
// completes succeeded.
func TestTaskRunRequireApprovalParksAndApprove(t *testing.T) {
	st, tc, h, cleanup, runs := newTaskBufconn(t)
	defer cleanup()

	taskID, version := seedTask(t, st)

	if err := st.CreatePolicy("pol_task_appr", "task-needs-approval", policy.Match{
		Actions: []string{policy.ActionTaskRun},
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	tc.SetIdentity(ident)
	apr := approvals.New(st, h, sse.New(), nil)
	apr.SetIdentity(ident)
	tc.SetApprovals(apr)
	apr.RegisterDispatcher(policy.ActionTaskRun, tc.DispatchApprovedTaskRun)

	// 1. Run → parked.
	ver, err := st.TaskVersion(taskID, version)
	if err != nil || ver == nil {
		t.Fatalf("TaskVersion: %v", err)
	}
	steps, _ := store.DecodeTaskSteps(ver.StepsJSON)
	pbSteps := make([]*pb.TaskStep, 0, len(steps))
	for _, s := range steps {
		pbSteps = append(pbSteps, &pb.TaskStep{Kind: s.Kind, Command: s.Command, Args: s.Args})
	}
	_, err = tc.Run(context.Background(), "ag_task", taskID, version, pbSteps,
		tasks.Actor{Principal: "alice", Role: "operator"})
	var apprErr *tasks.ApprovalRequiredError
	if !errors.As(err, &apprErr) {
		t.Fatalf("Run err = %v, want *ApprovalRequiredError", err)
	}

	// Run row parked, nothing on the wire.
	run, err := st.TaskRun(apprErr.RunID)
	if err != nil || run == nil {
		t.Fatalf("TaskRun: %v", err)
	}
	if run.State != "awaiting_approval" {
		t.Fatalf("run state = %s, want awaiting_approval", run.State)
	}
	select {
	case rid := <-runs:
		t.Fatalf("task run %s dispatched before approval", rid)
	case <-time.After(200 * time.Millisecond):
	}

	// 2. Non-admin cannot approve.
	if _, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "carol", Role: "operator"}); err == nil {
		t.Fatal("operator must not approve")
	}

	// 3. Admin approval → dispatched, result recorded, run succeeded.
	got, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "bob", Role: "admin"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.State != "approved" {
		t.Fatalf("after approve: %+v", got)
	}
	select {
	case <-runs:
	case <-time.After(2 * time.Second):
		t.Fatal("task run not dispatched after approval")
	}
	final, err := st.TaskRun(apprErr.RunID)
	if err != nil || final == nil {
		t.Fatalf("TaskRun final: %v", err)
	}
	if final.State != "succeeded" {
		t.Fatalf("run state = %s, want succeeded (err=%q)", final.State, final.Error)
	}
}
