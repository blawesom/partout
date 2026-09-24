package jobs_test

import (
	"context"
	"crypto/ed25519"
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
	"github.com/blawesom/partout/internal/server/jobs"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// jobPolicyHarness builds a store + stream handler + bufconn fake agent that
// captures JobAssignment/TaskRun down-envelopes, plus a server identity.
type jobPolicyHarness struct {
	st          *store.Store
	h           *stream.Handler
	ctrl        *jobs.Controller
	srvIdent    *certutil.ServerIdentity
	cleanup     func()
	jobAssign   chan *pb.JobAssignment
	jobUnassign chan string
	taskRuns    chan *pb.TaskRun
}

// ctrlPub returns the server's Ed25519 public key (verifies Decisions).
func (harness *jobPolicyHarness) ctrlPub() ed25519.PublicKey {
	return harness.srvIdent.Pub
}

// newJobPolicyHarness wires the harness; the fake agent authenticates as
// ag_test and captures job/task down-envelopes.
func newJobPolicyHarness(t *testing.T) *jobPolicyHarness {
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
		ID: "ag_test", UUID: id.UUID,
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

	jobAssign := make(chan *pb.JobAssignment, 8)
	jobUnassign := make(chan string, 8)
	taskRuns := make(chan *pb.TaskRun, 8)
	go func() {
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			if ja := down.GetJobAssign(); ja != nil {
				jobAssign <- ja
			}
			if ju := down.GetJobUnassign(); ju != nil {
				jobUnassign <- ju.GetJobId()
			}
			if tr := down.GetTaskRun(); tr != nil {
				taskRuns <- tr
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

	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	jc.SetIdentity(ident)

	return &jobPolicyHarness{
		st: st, h: h, ctrl: jc, srvIdent: ident,
		cleanup: func() {
			s.CloseSend()
			cancel()
			_ = conn.Close()
			gs.Stop()
			st.Close()
		},
		jobAssign:   jobAssign,
		jobUnassign: jobUnassign,
		taskRuns:    taskRuns,
	}
}

func (harness *jobPolicyHarness) seedTask(t *testing.T) {
	t.Helper()
	if err := harness.st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := harness.st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_test", Version: 1,
		StepsJSON: `[{"kind":"command","name":"echo","command":"echo"}]`}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}
}

// TestJobCreateAllowedCarriesSignedDecision verifies the happy path: an
// allowed job create pushes per-host assignments carrying a valid signed
// Decision bound to the job id + current bundle version.
func TestJobCreateAllowedCarriesSignedDecision(t *testing.T) {
	harness := newJobPolicyHarness(t)
	defer harness.cleanup()
	harness.seedTask(t)

	identPub := harness.ctrlPub()
	job, err := harness.ctrl.Create(context.Background(), jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "* * * * *", Selector: "all",
	}, jobs.Actor{Principal: "admin", Role: "admin"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	select {
	case ja := <-harness.jobAssign:
		d := ja.GetDecision()
		if d == nil {
			t.Fatal("JobAssignment has no Decision")
		}
		if ja.JobId != job.ID {
			t.Fatalf("assignment job_id=%q, want %q", ja.JobId, job.ID)
		}
		if d.GetRunId() != job.ID {
			t.Fatalf("decision run_id=%q, want job id %q", d.GetRunId(), job.ID)
		}
		if d.GetEffect() != policy.EffectAllow {
			t.Fatalf("decision effect=%q, want allow", d.GetEffect())
		}
		ver, _ := harness.st.PolicyBundleVersion()
		if d.GetBundleVersion() != ver {
			t.Fatalf("decision bundle_version=%d, want %d", d.GetBundleVersion(), ver)
		}
		if !policy.VerifyDecision(identPub, d.GetRunId(), d.GetBundleVersion(),
			d.GetEffect(), d.GetMatchedRules(), d.GetActorRole(), d.GetSig()) {
			t.Fatal("decision signature invalid")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no JobAssignment pushed")
	}
}

// TestJobCreateDeniedByPolicy verifies a policy denial rejects the job
// BEFORE any state is persisted: no job row, no assignment, PolicyError.
func TestJobCreateDeniedByPolicy(t *testing.T) {
	harness := newJobPolicyHarness(t)
	defer harness.cleanup()
	harness.seedTask(t)

	// Deny task.run for everyone.
	if err := harness.st.CreatePolicy("pol_deny", "deny task.run", policy.Match{
		Actions: []string{"task.run"},
	}, policy.EffectDeny, 0); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	_, err := harness.ctrl.Create(context.Background(), jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "* * * * *", Selector: "all",
	}, jobs.Actor{Principal: "admin", Role: "admin"})
	if err == nil {
		t.Fatal("Create: expected policy denial, got nil")
	}
	var pe *jobs.PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("Create: want *PolicyError, got %T: %v", err, err)
	}

	// Nothing persisted.
	listed, _ := harness.st.ListJobs()
	if len(listed) != 0 {
		t.Fatalf("listed %d jobs after denied create, want 0", len(listed))
	}
	select {
	case ja := <-harness.jobAssign:
		t.Fatalf("unexpected JobAssignment pushed: %+v", ja)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestJobUpdateDeniedByPolicy verifies re-authorization on update: a job
// saved before a denying rule exists cannot be re-saved after it does.
func TestJobUpdateDeniedByPolicy(t *testing.T) {
	harness := newJobPolicyHarness(t)
	defer harness.cleanup()
	harness.seedTask(t)

	job, err := harness.ctrl.Create(context.Background(), jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "* * * * *", Selector: "all",
	}, jobs.Actor{Principal: "admin", Role: "admin"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Drain the assignment from the create.
	select {
	case <-harness.jobAssign:
	case <-time.After(3 * time.Second):
		t.Fatal("no JobAssignment from create")
	}

	// Now add a denying rule.
	if err := harness.st.CreatePolicy("pol_deny", "deny task.run", policy.Match{
		Actions: []string{"task.run"},
	}, policy.EffectDeny, 0); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	_, err = harness.ctrl.Update(context.Background(), job.ID, jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "*/5 * * * *", Selector: "all",
	}, jobs.Actor{Principal: "admin", Role: "admin"})
	if err == nil {
		t.Fatal("Update: expected policy denial, got nil")
	}
	var pe *jobs.PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("Update: want *PolicyError, got %T: %v", err, err)
	}

	// The job row is unchanged (cron not bumped).
	got, _ := harness.st.GetJob(job.ID)
	if got == nil || got.Cron != "* * * * *" {
		t.Fatalf("job changed after denied update: %+v", got)
	}
}

// TestJobRunNowDeniedByPolicy verifies a manual job run is gated like
// task.run: denied hosts get a 'denied' run row and no dispatch.
func TestJobRunNowDeniedByPolicy(t *testing.T) {
	harness := newJobPolicyHarness(t)
	defer harness.cleanup()
	harness.seedTask(t)

	if err := harness.st.CreatePolicy("pol_deny", "deny task.run", policy.Match{
		Actions: []string{"task.run"},
	}, policy.EffectDeny, 0); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if err := harness.st.CreateJob(&store.Job{
		ID: "job_pre", Name: "pre", TaskID: "task_test", TaskVersion: 1,
		Cron: "* * * * *", Selector: "all",
	}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	err := harness.ctrl.RunNow(context.Background(), "job_pre", "ag_test",
		jobs.Actor{Principal: "admin", Role: "admin"})
	if err == nil {
		t.Fatal("RunNow: expected policy denial, got nil")
	}
	var pe *jobs.PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("RunNow: want *PolicyError, got %T: %v", err, err)
	}

	// No dispatch went out.
	select {
	case tr := <-harness.taskRuns:
		t.Fatalf("unexpected TaskRun dispatched: %+v", tr)
	case <-time.After(200 * time.Millisecond):
	}

	// A 'denied' run row was recorded.
	runs, _ := harness.st.JobRunsForJob("job_pre", 10)
	if len(runs) != 1 {
		t.Fatalf("listed %d runs, want 1", len(runs))
	}
	if runs[0].State != "denied" {
		t.Fatalf("run state=%q, want denied", runs[0].State)
	}
}

// TestJobRunNowAllowedDispatchesSignedDecision verifies the manual-run path
// dispatches a TaskRun carrying a fresh signed decision for that run.
func TestJobRunNowAllowedDispatchesSignedDecision(t *testing.T) {
	harness := newJobPolicyHarness(t)
	defer harness.cleanup()
	harness.seedTask(t)

	if err := harness.st.CreateJob(&store.Job{
		ID: "job_pre", Name: "pre", TaskID: "task_test", TaskVersion: 1,
		Cron: "* * * * *", Selector: "all",
	}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	err := harness.ctrl.RunNow(context.Background(), "job_pre", "ag_test",
		jobs.Actor{Principal: "admin", Role: "admin"})
	if err != nil {
		t.Fatalf("RunNow: %v", err)
	}

	select {
	case tr := <-harness.taskRuns:
		d := tr.GetDecision()
		if d == nil {
			t.Fatal("TaskRun has no Decision")
		}
		if d.GetRunId() != tr.GetRunId() {
			t.Fatalf("decision run_id=%q, want task run id %q", d.GetRunId(), tr.GetRunId())
		}
		identPub := harness.ctrlPub()
		if !policy.VerifyDecision(identPub, d.GetRunId(), d.GetBundleVersion(),
			d.GetEffect(), d.GetMatchedRules(), d.GetActorRole(), d.GetSig()) {
			t.Fatal("decision signature invalid")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no TaskRun dispatched")
	}
}

// TestJobUpdateNoMatchingSelectorRejected verifies a selector that resolves to
// no hosts is rejected outright by the policy gate (pre-existing resolver
// semantics), leaving existing assignments untouched.
func TestJobUpdateNoMatchingSelectorRejected(t *testing.T) {
	harness := newJobPolicyHarness(t)
	defer harness.cleanup()
	harness.seedTask(t)

	job, err := harness.ctrl.Create(context.Background(), jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "* * * * *", Selector: "all",
	}, jobs.Actor{Principal: "admin", Role: "admin"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	select {
	case <-harness.jobAssign:
	case <-time.After(3 * time.Second):
		t.Fatal("no JobAssignment from create")
	}

	if _, err := harness.ctrl.Update(context.Background(), job.ID, jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "* * * * *", Selector: "role:does-not-exist",
	}, jobs.Actor{Principal: "admin", Role: "admin"}); err == nil {
		t.Fatal("Update to a selector matching no hosts: expected an error")
	}
	// The rejected update must not have dropped the existing assignment.
	if n := len(mustAssignments(t, harness, job.ID)); n != 1 {
		t.Fatalf("assignments after rejected update = %d, want 1", n)
	}
}

// TestJobUpdateKeepsMatchingHosts verifies reconciliation only drops hosts
// that fell out of the selector, leaving the rest assigned.
func TestJobUpdateKeepsMatchingHosts(t *testing.T) {
	harness := newJobPolicyHarness(t)
	defer harness.cleanup()
	harness.seedTask(t)

	// A second host that will be dropped, tagged so the selector can target it.
	if err := harness.st.UpsertAgent(store.Agent{
		ID: "ag_other", UUID: "uuid-other", ED25519Pub: "eA==", X25519Pub: "eA==",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := harness.st.SetTag("ag_other", "env", "lab"); err != nil {
		t.Fatalf("SetTag: %v", err)
	}

	job, err := harness.ctrl.Create(context.Background(), jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "* * * * *", Selector: "all",
	}, jobs.Actor{Principal: "admin", Role: "admin"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n := len(mustAssignments(t, harness, job.ID)); n != 2 {
		t.Fatalf("assignments after create = %d, want 2", n)
	}

	// Narrow to the connected host only (the other one is not "connected"
	// in the test but still assigned — drop it).
	if _, err := harness.ctrl.Update(context.Background(), job.ID, jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "*/5 * * * *", Selector: "tag:env=lab",
	}, jobs.Actor{Principal: "admin", Role: "admin"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	select {
	case <-harness.jobUnassign:
	case <-time.After(3 * time.Second):
		t.Fatal("no JOB_UNASSIGN pushed")
	}

	assigned := mustAssignments(t, harness, job.ID)
	if len(assigned) != 1 || assigned[0].AgentID != "ag_other" {
		t.Fatalf("assignments after narrowing = %+v, want only ag_other", assigned)
	}
}

func mustAssignments(t *testing.T, harness *jobPolicyHarness, jobID string) []*store.JobAssignment {
	t.Helper()
	a, err := harness.st.JobAssignmentsForJob(jobID)
	if err != nil {
		t.Fatalf("JobAssignmentsForJob: %v", err)
	}
	return a
}
