package jobs_test

// RunNow secret materialization: a job whose task steps declare
// `secret:NAME` refs must have the secret materialized down the stream
// BEFORE the TASK_RUN envelope (v0.9.13 known gap), and an unbound ref
// must fail the manual run server-side with the ref named — no task
// envelope on the wire.

import (
	"context"
	"crypto/rand"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/server/jobs"
	serversecrets "github.com/blawesom/partout/internal/server/secrets"
	"github.com/blawesom/partout/internal/store"
)

func logDiscard() *log.Logger { return log.New(io.Discard, "srv:", 0) }

// TestJobRunNowMaterializesSecrets: the bound secret is materialized
// before the task envelope; the dispatch succeeds.
func TestJobRunNowMaterializesSecrets(t *testing.T) {
	st, jc, h, cleanup, runs := newJobBufconn(t)
	defer cleanup()

	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	jc.SetIdentity(ident)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	mgr, err := serversecrets.New(st, h, master, logDiscard())
	if err != nil {
		t.Fatalf("secrets.New: %v", err)
	}
	jc.SetSecrets(mgr)
	if _, err := mgr.CreateSecret("job-token", "tok-value", "", 0, "admin"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	if err := st.CreateTask(&store.Task{ID: "task_job_sec", Name: "job task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_job_sec", Version: 1,
		StepsJSON: `[{"kind":"command","command":"true","env":{"T":"secret:job-token"}}]`}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}
	ctx := context.Background()
	actor := jobs.Actor{Principal: "admin", Role: "admin"}
	job, err := jc.Create(ctx, jobs.Job{
		Name: "sec job", TaskID: "task_job_sec", Cron: "0 0 * * *",
		Selector: "host:ag_job",
	}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := jc.RunNow(ctx, job.ID, "ag_job", actor); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	// The task envelope must have been dispatched (the harness answers it).
	select {
	case <-runs:
	case <-time.After(2 * time.Second):
		t.Fatal("task run not dispatched")
	}
	// The audit binding ties the materialization to the job run.
	binds, err := mgr.Bindings("job-token", 10)
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if len(binds) != 1 || binds[0].AgentID != "ag_job" {
		t.Fatalf("bindings = %+v, want one row for ag_job", binds)
	}
	if !strings.HasPrefix(binds[0].Ref, "jr_") {
		t.Fatalf("binding ref = %q, want a jr_* run id", binds[0].Ref)
	}
}

// TestJobRunNowUnboundSecretFailsFast: an unbound ref aborts the manual
// run server-side with the ref named; no task envelope is sent.
func TestJobRunNowUnboundSecretFailsFast(t *testing.T) {
	st, jc, h, cleanup, runs := newJobBufconn(t)
	defer cleanup()
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	jc.SetIdentity(ident)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	mgr, err := serversecrets.New(st, h, master, logDiscard())
	if err != nil {
		t.Fatalf("secrets.New: %v", err)
	}
	jc.SetSecrets(mgr)

	if err := st.CreateTask(&store.Task{ID: "task_job_unb", Name: "job task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_job_unb", Version: 1,
		StepsJSON: `[{"kind":"command","command":"true","env":{"T":"secret:missing-tok"}}]`}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}
	ctx := context.Background()
	actor := jobs.Actor{Principal: "admin", Role: "admin"}
	job, err := jc.Create(ctx, jobs.Job{
		Name: "unb job", TaskID: "task_job_unb", Cron: "0 0 * * *",
		Selector: "host:ag_job",
	}, actor)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = jc.RunNow(ctx, job.ID, "ag_job", actor)
	if err == nil {
		t.Fatal("RunNow: want error for unbound secret ref")
	}
	if !strings.Contains(err.Error(), `secret "missing-tok"`) {
		t.Fatalf("err = %q, want it to name the ref secret \"missing-tok\"", err.Error())
	}
	select {
	case rid := <-runs:
		t.Fatalf("task run %s dispatched despite unbound secret ref", rid)
	case <-time.After(200 * time.Millisecond):
	}
}
