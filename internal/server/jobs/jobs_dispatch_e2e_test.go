package jobs_test

// E2E for the job dispatch wire path (M3 gap): JOB_ASSIGN over a live
// bufconn stream → the REAL agent-side scheduler (real task executor + real
// policy guardrail) fires the job → JOB_RUN_RESULT back over the wire →
// job_runs row + assignment state on the server. The cron minute-boundary
// itself is delegated to robfig/cron; RunNow exercises the same fire()
// path a cron tick takes.

import (
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blawesom/partout/internal/agent/guardrail"
	agentjobs "github.com/blawesom/partout/internal/agent/jobs"
	"github.com/blawesom/partout/internal/agent/task"
	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/jobs"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// fakeAgent is a real agent-side job stack (scheduler + executor + guardrail)
// attached to a live stream, standing in for the full agent process.
type fakeAgent struct {
	agentID string
	id      *identity.Identity
	s       pb.AgentStreamClient
	conn    *grpc.ClientConn
	sendMu  sync.Mutex // serializes up-sends
	sched   *agentjobs.Scheduler
	guard   *guardrail.Guard
}

// startDispatchServer wires the stream handler + jobs controller on bufconn.
func startDispatchServer(t *testing.T) (*store.Store, *stream.Handler, *jobs.Controller, *bufconn.Listener) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	sseB := sse.New()
	lg := log.New(io.Discard, "srv:", 0)
	h := stream.NewHandler(st, sseB, lg)
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	h.SetServerPubKey(base64.StdEncoding.EncodeToString(ident.Pub))
	ctrl := jobs.New(st, h, sseB, lg)
	ctrl.SetIdentity(ident)
	h.JobRunResultHook = func(agentID string, r *pb.JobRunResult) {
		t.Logf("DEBUG OnRunResult %s %s state=%s", agentID, r.RunId, r.State)
		ctrl.OnRunResult(agentID, r)
	}

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	t.Cleanup(func() { _ = st.Close() })
	return st, h, ctrl, lis
}

// newFakeAgent connects one fake agent to the stream and starts its
// envelope loop (POLICY_BUNDLE / JOB_ASSIGN / JOB_UNASSIGN).
func newFakeAgent(t *testing.T, h *stream.Handler, st *store.Store, lis *bufconn.Listener, agentID string) *fakeAgent {
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

	// Handshake: challenge → auth proof (Ed25519 over the nonce).
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

	fa := &fakeAgent{
		agentID: agentID, id: id, s: client, conn: conn,
	}
	fa.guard = guardrail.NewGuard(id.UUID, t.TempDir())
	fa.sched = agentjobs.New(t.TempDir(), task.NewExecutor(nil), func(r *agentjobs.Report) {
		fa.sendMu.Lock()
		defer fa.sendMu.Unlock()
		_ = s.Send(&pb.Envelope{
			Kind:   pb.EnvelopeKind_JOB_RUN_RESULT,
			CorrId: r.RunID,
			Payload: &pb.Envelope_JobRunResult{JobRunResult: &pb.JobRunResult{
				RunId: r.RunID, JobId: r.JobID, State: r.State, Error: r.Error,
				ScheduledAt: r.ScheduledAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
				Trigger: r.Trigger, RetryOf: r.RetryOf,
			}},
		})
	}, log.New(io.Discard, agentID+": ", 0))
	fa.sched.SetGuard(fa.guard)

	// Envelope loop: the real agent's down-traffic handling for the
	// job-relevant kinds.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			switch {
			case down.GetPolicyBundle() != nil:
				fa.guard.OnBundle(down.GetPolicyBundle())
			case down.GetJobAssign() != nil:
				ja := down.GetJobAssign()
				_ = fa.sched.Apply(&agentjobs.Assignment{
					JobID: ja.JobId, Name: ja.Name, Cron: ja.Cron, Timezone: ja.Timezone,
					TaskID: ja.TaskId, TaskVersion: ja.TaskVersion, Steps: ja.Steps,
					MaxRunS: ja.MaxRunS, OverlapPolicy: ja.OverlapPolicy,
					FailurePolicy: ja.FailurePolicy, RetryBackoffS: ja.RetryBackoffS,
					SelectorSnapshot: ja.SelectorSnapshot, Version: ja.Version,
					Decision: ja.Decision,
				})
			case down.GetJobUnassign() != nil:
				fa.sched.Remove(down.GetJobUnassign().GetJobId())
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
	waitFor(t, agentID+" session", func() bool { return h.AgentSession(agentID) != nil })
	return fa
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("timed out waiting for %s\n%s", what, buf[:n])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func jobInList(s *agentjobs.Scheduler, jobID string) bool {
	for _, a := range s.List() {
		if a.JobID == jobID {
			return true
		}
	}
	return false
}

// TestJobDispatchE2E drives the full wire path: create → JOB_ASSIGN →
// fire → JOB_RUN_RESULT → job_runs row; then selector edits re-push and
// unassign over the wire.
func TestJobDispatchE2E(t *testing.T) {
	st, h, ctrl, lis := startDispatchServer(t)

	agA := newFakeAgent(t, h, st, lis, "ag_a")
	agB := newFakeAgent(t, h, st, lis, "ag_b")
	if err := st.SetTag("ag_a", "env", "test"); err != nil {
		t.Fatal(err)
	}

	// Both agents must have received the policy bundle (guardrail armed).
	waitFor(t, "policy bundles", func() bool {
		return agA.guard.Loaded() && agB.guard.Loaded()
	})

	// Task with one trivial step.
	if err := st.CreateTask(&store.Task{ID: "task_e2e", Name: "e2e"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_e2e", Version: 1,
		StepsJSON: `[{"kind":"command","name":"echo","command":"/bin/echo","args":["hello"]}]`}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	actor := jobs.Actor{Principal: "admin", Role: "admin"}

	// 1. Create: selector matches only ag_a → JOB_ASSIGN lands there only.
	job, err := ctrl.Create(ctx, jobs.Job{
		Name: "e2e job", TaskID: "task_e2e", Cron: "* * * * *", Selector: "tag:env=test",
	}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	assignments, _ := st.JobAssignmentsForJob(job.ID)
	if len(assignments) != 1 || assignments[0].AgentID != "ag_a" {
		t.Fatalf("assignments: %+v (want only ag_a)", assignments)
	}
	waitFor(t, "JOB_ASSIGN on ag_a", func() bool { return jobInList(agA.sched, job.ID) })
	if jobInList(agB.sched, job.ID) {
		t.Fatal("ag_b got a JOB_ASSIGN it should not match")
	}

	// 2. Fire the job (same fire() path as a cron tick) → the real task
	// runner executes → JOB_RUN_RESULT over the wire → job_runs row.
	if err := agA.sched.RunNow(job.ID); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	var run *store.JobRun
	waitFor(t, "job_runs row", func() bool {
		runs, _ := st.ListJobRuns(10)
		if len(runs) == 0 {
			return false
		}
		run = runs[0]
		return run.State != "running" && run.State != "pending"
	})
	if run.JobID != job.ID || run.AgentID != "ag_a" {
		t.Fatalf("run: %+v", run)
	}
	if run.State != "succeeded" {
		t.Fatalf("run state=%q, want succeeded (err=%s)", run.State, run.Error)
	}
	if run.Trigger != "manual" {
		t.Fatalf("trigger=%q, want manual", run.Trigger)
	}
	if run.TaskID != "task_e2e" || run.TaskVersion != 1 {
		t.Fatalf("task lineage: %+v", run)
	}
	assignments, _ = st.JobAssignmentsForJob(job.ID)
	if len(assignments) != 1 || assignments[0].LastRunState != "succeeded" {
		t.Fatalf("assignment last_run_state: %+v", assignments)
	}

	// 3. Widen the selector to "all" → ag_b receives a (fresh) JOB_ASSIGN
	// over the wire (PRD §5.4: editing a selector re-resolves + re-pushes).
	if _, err := ctrl.Update(ctx, job.ID, jobs.Job{Selector: "all"}, actor); err != nil {
		t.Fatalf("Update(all): %v", err)
	}
	waitFor(t, "JOB_ASSIGN on ag_b", func() bool { return jobInList(agB.sched, job.ID) })
	if !jobInList(agA.sched, job.ID) {
		t.Fatal("ag_a lost its assignment on re-push")
	}

	// 4. Narrow to a selector matching no host → both agents receive
	// JOB_UNASSIGN and stop holding the schedule; store assignments clear.
	if _, err := ctrl.Update(ctx, job.ID, jobs.Job{Selector: "tag:env=none"}, actor); err != nil {
		t.Fatalf("Update(none): %v", err)
	}
	waitFor(t, "JOB_UNASSIGN on both", func() bool {
		return !jobInList(agA.sched, job.ID) && !jobInList(agB.sched, job.ID)
	})
	assignments, _ = st.JobAssignmentsForJob(job.ID)
	if len(assignments) != 0 {
		t.Fatalf("assignments after unassign: %+v", assignments)
	}
}
