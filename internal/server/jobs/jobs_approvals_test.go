package jobs_test

import (
	"context"
	"encoding/base64"
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
	"github.com/blawesom/partout/internal/server/jobs"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// newJobBufconn builds a bufconn server + connected fake agent that answers
// TASK_RUN envelopes with a succeeded result and records runs seen.
func newJobBufconn(t *testing.T) (*store.Store, *jobs.Controller, *stream.Handler, func(), chan string) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	sseB := sse.New()
	lg := log.New(io.Discard, "srv:", 0)
	h := stream.NewHandler(st, sseB, lg)
	jc := jobs.New(st, h, sseB, lg)

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
		ID: "ag_job", UUID: id.UUID,
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
			res := &pb.TaskRunResult{RunId: tr.RunId, State: "succeeded"}
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
	return st, jc, h, cleanup, runs
}

// TestJobRunNowRequireApprovalParksAndApprove is the M4 jobs E2E loop: the
// job is created while task.run is allowed; a require_approval rule arrives;
// RunNow parks the job run (row awaiting_approval, no TASK_RUN on the wire);
// admin approval re-dispatches it.
func TestJobRunNowRequireApprovalParksAndApprove(t *testing.T) {
	st, jc, h, cleanup, runs := newJobBufconn(t)
	defer cleanup()

	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	jc.SetIdentity(ident)

	// Task + job (no rules yet → allowed).
	if err := st.CreateTask(&store.Task{ID: "task_job_appr", Name: "job task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_job_appr", Version: 1,
		StepsJSON: `[{"kind":"command","command":"uptime"}]`}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}
	ctx := context.Background()
	actor := jobs.Actor{Principal: "admin", Role: "admin"}
	job, err := jc.Create(ctx, jobs.Job{
		Name: "appr job", TaskID: "task_job_appr", Cron: "0 0 * * *",
		Selector: "host:ag_job",
	}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Now task.run requires approval on this host.
	if err := st.CreatePolicy("pol_job_appr", "job-needs-approval", policy.Match{
		Actions: []string{policy.ActionTaskRun},
		Hosts:   "host:ag_job",
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	apr := approvals.New(st, h, sse.New(), nil)
	apr.SetIdentity(ident)
	jc.SetApprovals(apr)
	apr.RegisterDispatcher("job.run", jc.DispatchApprovedJobRun)

	// 1. RunNow → parked.
	err = jc.RunNow(ctx, job.ID, "ag_job", actor)
	var apprErr *jobs.ApprovalRequiredError
	if !errors.As(err, &apprErr) {
		t.Fatalf("RunNow err = %v, want *ApprovalRequiredError", err)
	}
	run, err := st.GetJobRun(apprErr.RunID)
	if err != nil || run == nil {
		t.Fatalf("GetJobRun: %v", err)
	}
	if run.State != "awaiting_approval" {
		t.Fatalf("job run state = %s, want awaiting_approval", run.State)
	}
	select {
	case rid := <-runs:
		t.Fatalf("job run %s dispatched before approval", rid)
	case <-time.After(200 * time.Millisecond):
	}

	// 2. Non-admin cannot approve.
	if _, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "carol", Role: "operator"}); err == nil {
		t.Fatal("operator must not approve")
	}

	// 3. Admin approval → dispatched.
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
		t.Fatal("job run not dispatched after approval")
	}
	final, err := st.GetJobRun(apprErr.RunID)
	if err != nil || final == nil {
		t.Fatalf("GetJobRun final: %v", err)
	}
	if final.State != "dispatched" {
		t.Fatalf("job run state = %s, want dispatched (err=%q)", final.State, final.Error)
	}
}
