package tasks_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/server/tasks"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// --- helpers ---------------------------------------------------------------

func newBufconnTest(t *testing.T) (*store.Store, *tasks.Controller, func()) {
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
		ID: "ag_test", UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_test", Data: map[string]string{
		"host.distro": "ubuntu", "host.distro_version": "24.04",
	}}); err != nil {
		t.Fatalf("UpsertFacts: %v", err)
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

	// Fake agent: handle TASK_RUN, respond with a canned result.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			run := down.GetTaskRun()
			if run == nil {
				continue
			}
			// Simulate: all steps succeed.
			steps := make([]*pb.TaskStepResult, 0, len(run.Steps))
			for i, step := range run.Steps {
				steps = append(steps, &pb.TaskStepResult{
					StepIndex: int32(i),
					State:     "ok",
					Detail:    "step " + step.GetKind() + " completed",
				})
			}
			if err := s.Send(&pb.Envelope{
				Kind:   pb.EnvelopeKind_TASK_RUN_RESULT,
				CorrId: run.RunId,
				Payload: &pb.Envelope_TaskRunResult{TaskRunResult: &pb.TaskRunResult{
					RunId: run.RunId, State: "succeeded", Steps: steps,
				}},
			}); err != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_test") == nil {
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
	return st, tc, cleanup
}

var taskActor = tasks.Actor{Principal: "local", Role: "admin"}

// --- tests -----------------------------------------------------------------

func TestRunTask(t *testing.T) {
	st, tc, cleanup := newBufconnTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a task with 2 steps.
	taskID := "task_test"
	if err := st.CreateTask(&store.Task{ID: taskID, Name: "test task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	steps := []*pb.TaskStep{
		{Kind: "command", Name: "echo", Command: "echo", Args: []string{"hello"}},
		{Kind: "file", Name: "write file", Path: "/tmp/test.txt", Content: "hi"},
	}
	stepsJSON, _ := json.Marshal(store.TaskStep{Kind: "command"})
	_ = st.UpsertTaskVersion(&store.TaskVersion{TaskID: taskID, Version: 1, StepsJSON: string(stepsJSON)})

	run, err := tc.Run(ctx, "ag_test", taskID, 1, steps, taskActor)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.State != "succeeded" {
		t.Fatalf("state=%q, want succeeded", run.State)
	}

	// Verify the run is recorded in the store.
	stored, err := st.TaskRun(run.ID)
	if err != nil {
		t.Fatalf("TaskRun: %v", err)
	}
	if stored.State != "succeeded" {
		t.Fatalf("stored state=%q, want succeeded", stored.State)
	}
	if stored.TaskID != taskID {
		t.Fatalf("stored task_id=%q, want %s", stored.TaskID, taskID)
	}
}

func TestRunTaskPolicyDeny(t *testing.T) {
	st, tc, cleanup := newBufconnTest(t)
	defer cleanup()
	ctx := context.Background()

	// Set an identity so the policy gate runs.
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	tc.SetIdentity(&certutil.ServerIdentity{Pub: id.Ed25519Pub, Priv: id.Ed25519Priv})

	// Set up a policy rule that denies task.run for operators.
	if err := st.CreatePolicy("pol_deny", "deny task.run", policy.Match{
		Actions:    []string{"task.run"},
		ActorRoles: []string{"operator"},
	}, policy.EffectDeny, 0); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// Create a task.
	taskID := "task_deny"
	if err := st.CreateTask(&store.Task{ID: taskID, Name: "deny task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	steps := []*pb.TaskStep{
		{Kind: "command", Name: "echo", Command: "echo"},
	}

	run, err := tc.Run(ctx, "ag_test", taskID, 1, steps,
		tasks.Actor{Principal: "local", Role: "operator"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The run should be marked failed/denied.
	if run.State != "failed" {
		t.Fatalf("state=%q, want failed", run.State)
	}
}

// --- store tests -----------------------------------------------------------

func TestTaskCRUD(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	task := &store.Task{ID: "task_test", Name: "test", Description: "a test task"}
	if err := st.CreateTask(task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	// Upsert version.
	steps := []store.TaskStep{
		{Kind: "command", Name: "echo", Command: "echo", Args: []string{"hi"}},
		{Kind: "file", Name: "write", Path: "/tmp/f", Content: "x"},
	}
	stepsJSON, _ := json.Marshal(steps)
	ver := &store.TaskVersion{TaskID: "task_test", Version: 1, StepsJSON: string(stepsJSON)}
	if err := st.UpsertTaskVersion(ver); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}

	// Get.
	fetched, err := st.Task("task_test")
	if err != nil || fetched == nil {
		t.Fatalf("Task: %v %v", err, fetched)
	}
	if fetched.Name != "test" {
		t.Fatalf("name=%q, want test", fetched.Name)
	}

	// Latest version.
	latest, err := st.LatestTaskVersion("task_test")
	if err != nil || latest == nil {
		t.Fatalf("LatestTaskVersion: %v %v", err, latest)
	}
	if latest.Version != 1 {
		t.Fatalf("version=%d, want 1", latest.Version)
	}
	decoded, err := store.DecodeTaskSteps(latest.StepsJSON)
	if err != nil {
		t.Fatalf("DecodeTaskSteps: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("decoded %d steps, want 2", len(decoded))
	}

	// List tasks.
	listed, err := st.ListTasks(10)
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d tasks, want 1", len(listed))
	}
}

func TestTaskRunSteps(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{ID: "ag_test", UUID: "uuid-test",
		ED25519Pub: "eA==", X25519Pub: "eA=="}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	run := &store.TaskRun{
		ID: "tr_test", TaskID: "task_test", TaskVersion: 1, AgentID: "ag_test",
	}
	if err := st.CreateTaskRun(run); err != nil {
		t.Fatalf("CreateTaskRun: %v", err)
	}

	// Record steps.
	step1 := &store.TaskRunStep{RunID: "tr_test", StepIdx: 0, Kind: "command", Name: "echo", State: "ok", Detail: "done"}
	if err := st.RecordTaskRunStep(step1); err != nil {
		t.Fatalf("RecordTaskRunStep: %v", err)
	}
	step2 := &store.TaskRunStep{RunID: "tr_test", StepIdx: 1, Kind: "file", Name: "write", State: "changed", Detail: "file written"}
	if err := st.RecordTaskRunStep(step2); err != nil {
		t.Fatalf("RecordTaskRunStep: %v", err)
	}

	// Finalize.
	if err := st.FinalizeTaskRun("tr_test", "succeeded", "", 0); err != nil {
		t.Fatalf("FinalizeTaskRun: %v", err)
	}

	// Get run.
	stored, err := st.TaskRun("tr_test")
	if err != nil {
		t.Fatalf("TaskRun: %v", err)
	}
	if stored.State != "succeeded" {
		t.Fatalf("state=%q, want succeeded", stored.State)
	}

	// List steps.
	steps, err := st.TaskRunSteps("tr_test")
	if err != nil {
		t.Fatalf("TaskRunSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("listed %d steps, want 2", len(steps))
	}
	if steps[0].State != "ok" || steps[1].State != "changed" {
		t.Fatalf("bad step states: %q, %q", steps[0].State, steps[1].State)
	}
}

func TestPlaybookCRUD(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_test", Version: 1,
		StepsJSON: `[]`}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}

	pb := &store.Playbook{ID: "pb_test", Name: "test playbook", TaskID: "task_test", TaskVersion: 1, Selector: "env:prod"}
	if err := st.CreatePlaybook(pb); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	fetched, err := st.Playbook("pb_test")
	if err != nil || fetched == nil {
		t.Fatalf("Playbook: %v %v", err, fetched)
	}
	if fetched.Name != "test playbook" {
		t.Fatalf("name=%q, want test playbook", fetched.Name)
	}

	listed, err := st.ListPlaybooks()
	if err != nil {
		t.Fatalf("ListPlaybooks: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d playbooks, want 1", len(listed))
	}
}
