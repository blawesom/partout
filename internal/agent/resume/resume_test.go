package resume

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/agent/guardrail"
	"github.com/blawesom/partout/internal/agent/jobs"
	"github.com/blawesom/partout/internal/agent/task"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
)

// --- test helpers -----------------------------------------------------------

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return priv
}

// testGuard builds a guard with a policy bundle (version v, default-allow)
// signed by the server key priv.Public().
func testGuard(t *testing.T, v uint64, priv ed25519.PrivateKey) *guardrail.Guard {
	t.Helper()
	g := guardrail.NewGuard("agent_1", t.TempDir())
	g.OnBundle(&pb.PolicyBundle{
		Version:      v,
		RulesJson:    "[]",
		AgentId:      "agent_1",
		ServerPubkey: []byte(base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))),
	})
	return g
}

func signedDecision(priv ed25519.PrivateKey, runID string, v uint64) *pb.Decision {
	sig := policy.SignDecision(priv, runID, v, policy.EffectAllow, nil, "admin", "")
	return &pb.Decision{
		RunId: runID, BundleVersion: v, Effect: policy.EffectAllow,
		Sig: sig, ActorRole: "admin",
	}
}

// fakeRebootExecutor builds an executor with zero flush and an injected
// reboot command.
func fakeRebootExecutor(t *testing.T, rebootErr error) (*task.Executor, *bool) {
	t.Helper()
	e := task.NewExecutor(elevate.None, nil)
	e.SetRebootFlush(0)
	called := false
	e.SetRebootCmd(func() error {
		called = true
		return rebootErr
	})
	return e, &called
}

// wireRunner wires a marker store + hook + abort on a runner (mirrors the
// agent wiring).
func wireRunner(t *testing.T, store *Store, r *task.Runner) {
	t.Helper()
	r.SetRebootHook(func(_ context.Context, rc *task.RebootCtx) error {
		m := &Marker{
			RunID:       rc.Run.GetRunId(),
			Kind:        KindTask,
			TaskID:      rc.Run.GetTaskId(),
			TaskVersion: rc.Run.GetTaskVersion(),
			StartIdx:    rc.RebootIndex,
			Steps:       rc.Run.GetSteps()[rc.RebootIndex+1:],
			MaxRunS:     rc.MaxRunS,
			Decision:    rc.Run.GetDecision(),
			CreatedAt:   time.Now().Unix(),
		}
		if rc.JobID != "" {
			m.Kind = KindJob
			m.JobID = rc.JobID
		}
		for _, d := range rc.Done {
			m.DoneSteps = append(m.DoneSteps, DoneStep{
				Index: d.Index, Name: d.Name, State: d.State, Detail: d.Detail,
				Started: d.Started, Finished: d.Finished,
			})
		}
		return store.Save(m)
	})
	r.SetRebootAbort(func(runID string) { _ = store.Delete(runID) })
}

type taskReports struct {
	mu     sync.Mutex
	called bool
	state  string
	errMsg string
	steps  []*pb.TaskStepResult
}

func (r *taskReports) fn() func(runID, state, errMsg string, steps []*pb.TaskStepResult) {
	return func(runID, state, errMsg string, steps []*pb.TaskStepResult) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.called = true
		r.state = state
		r.errMsg = errMsg
		r.steps = steps
	}
}

type jobReports struct {
	mu     sync.Mutex
	called bool
	rep    *jobs.Report
}

func (r *jobReports) fn() func(*jobs.Report) {
	return func(rep *jobs.Report) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.called = true
		r.rep = rep
	}
}

// --- store tests -------------------------------------------------------------

func TestStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "resume"))
	if err != nil {
		t.Fatal(err)
	}
	m := &Marker{
		RunID: "tr_abc123", Kind: KindTask, TaskID: "task_1", TaskVersion: 2,
		StartIdx:  1,
		Steps:     []*pb.TaskStep{{Kind: "file", Path: "/tmp/x", Content: "y"}},
		DoneSteps: []DoneStep{{Index: 0, Name: "echo", State: "ok"}},
		CreatedAt: time.Now().Unix(),
	}
	if err := s.Save(m); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RunID != "tr_abc123" || list[0].StartIdx != 1 {
		t.Fatalf("bad list: %+v", list)
	}
	if len(list[0].Steps) != 1 || list[0].Steps[0].GetPath() != "/tmp/x" {
		t.Fatalf("bad remaining steps: %+v", list[0].Steps)
	}
	if err := s.Delete("tr_abc123"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List()
	if len(list) != 0 {
		t.Fatalf("marker not deleted: %+v", list)
	}
	// Unsafe ids are rejected.
	if err := s.Save(&Marker{RunID: "../evil"}); err == nil {
		t.Fatal("unsafe run id accepted")
	}
}

// --- reboot step flow ----------------------------------------------------------

func TestRebootStepFlow(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "resume"))
	exec, called := fakeRebootExecutor(t, nil)
	priv := testKey(t)
	const runID = "tr_reboot1"

	runner := task.New(exec)
	wireRunner(t, store, runner)

	steps := []*pb.TaskStep{
		{Kind: "command", Name: "echo", Command: "/bin/echo", Args: []string{"hi"}},
		{Kind: "reboot", Name: "reboot host"},
		{Kind: "file", Name: "write", Path: filepath.Join(dir, "after.txt"), Content: "after"},
	}
	res := runner.Run(context.Background(), &pb.TaskRun{
		RunId: runID, TaskId: "task_1", TaskVersion: 1,
		Steps: steps, Decision: signedDecision(priv, runID, 3),
	})

	if res.State != task.StateRebooting {
		t.Fatalf("state=%q, want rebooting (err=%s)", res.State, res.Error)
	}
	if !*called {
		t.Fatal("reboot command was not called")
	}
	// The step after the reboot must NOT have run.
	if _, err := os.Stat(filepath.Join(dir, "after.txt")); !os.IsNotExist(err) {
		t.Fatal("post-reboot step ran before the reboot")
	}
	// The marker must exist with the remaining step + the done command step.
	list, _ := store.List()
	if len(list) != 1 {
		t.Fatalf("markers=%d, want 1", len(list))
	}
	m := list[0]
	if m.RunID != runID || m.StartIdx != 1 || m.Kind != KindTask {
		t.Fatalf("bad marker: %+v", m)
	}
	if len(m.Steps) != 1 || m.Steps[0].GetKind() != "file" {
		t.Fatalf("remaining steps: %+v", m.Steps)
	}
	if len(m.DoneSteps) != 1 || m.DoneSteps[0].State != "ok" {
		t.Fatalf("done steps: %+v", m.DoneSteps)
	}
	if m.Decision == nil {
		t.Fatal("marker missing decision")
	}
}

func TestRebootCommandFailure(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "resume"))
	exec, called := fakeRebootExecutor(t, errors.New("permission denied"))
	runner := task.New(exec)
	wireRunner(t, store, runner)

	res := runner.Run(context.Background(), &pb.TaskRun{
		RunId: "tr_fail1", TaskId: "task_1", TaskVersion: 1,
		Steps: []*pb.TaskStep{
			{Kind: "reboot", Name: "reboot"},
			{Kind: "command", Name: "echo", Command: "/bin/echo"},
		},
	})

	if res.State != task.StateFailed {
		t.Fatalf("state=%q, want failed", res.State)
	}
	if !*called {
		t.Fatal("reboot command was not attempted")
	}
	// The marker must have been discarded (no resume will happen).
	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("marker left behind after failed reboot: %+v", list)
	}
}

// --- resume after reboot -------------------------------------------------------

func TestResumeAfterBootTaskKind(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "resume"))
	priv := testKey(t)
	const runID = "tr_resume1"

	after := filepath.Join(dir, "after.txt")
	// Marker as the reboot-step hook would have written it.
	m := &Marker{
		RunID: runID, Kind: KindTask, TaskID: "task_1", TaskVersion: 1,
		StartIdx: 1,
		Steps: []*pb.TaskStep{
			{Kind: "file", Name: "write", Path: after, Content: "resumed"},
		},
		DoneSteps: []DoneStep{{Index: 0, Name: "echo", State: "ok", Detail: "done"}},
		Decision:  signedDecision(priv, runID, 4),
		CreatedAt: time.Now().Add(-2 * time.Minute).Unix(),
	}
	if err := store.Save(m); err != nil {
		t.Fatal(err)
	}

	tr := &taskReports{}
	exec := task.NewExecutor(elevate.None, nil)
	r := New(store, exec, testGuard(t, 4, priv), nil, nil, nil, tr.fn(), nil)
	r.SetBootAge(func() (time.Duration, bool) { return 30 * time.Second, true }) // booted 30s ago

	r.ResumePending()

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if !tr.called || tr.state != "succeeded" {
		t.Fatalf("report: called=%v state=%q err=%q", tr.called, tr.state, tr.errMsg)
	}
	// The remaining step ran.
	got, err := os.ReadFile(after)
	if err != nil || string(got) != "resumed" {
		t.Fatalf("remaining step did not run: %q err=%v", got, err)
	}
	// Marker deleted.
	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("marker not deleted: %+v", list)
	}
	// Step report carries the original indices (done step 0 + resumed step 2).
	idxs := map[int]string{}
	for _, s := range tr.steps {
		idxs[int(s.GetStepIndex())] = s.GetState()
	}
	if idxs[0] != "ok" || idxs[2] != "changed" {
		t.Fatalf("step indices: %+v (want 0=ok, 2=changed)", idxs)
	}
}

func TestResumeAfterBootJobKind(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "resume"))
	priv := testKey(t)
	const runID = "jr_job1_123"

	m := &Marker{
		RunID: runID, Kind: KindJob, JobID: "job_1", TaskID: "task_1", TaskVersion: 1,
		StartIdx: 0,
		Steps: []*pb.TaskStep{
			{Kind: "command", Name: "echo", Command: "/bin/echo", Args: []string{"after"}},
		},
		CreatedAt: time.Now().Add(-1 * time.Minute).Unix(),
	}
	// The marker's decision must be signed for the run id.)
	m.Decision = signedDecision(priv, runID, 2)
	if err := store.Save(m); err != nil {
		t.Fatal(err)
	}

	jr := &jobReports{}
	exec := task.NewExecutor(elevate.None, nil)
	r := New(store, exec, testGuard(t, 2, priv), nil, nil, jr.fn(), nil, nil)
	r.SetBootAge(func() (time.Duration, bool) { return 5 * time.Second, true })

	r.ResumePending()

	jr.mu.Lock()
	defer jr.mu.Unlock()
	if !jr.called || jr.rep == nil {
		t.Fatal("no job report")
	}
	if jr.rep.State != "succeeded" || jr.rep.Trigger != "resume" || jr.rep.JobID != "job_1" {
		t.Fatalf("job report: %+v", jr.rep)
	}
	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("marker not deleted: %+v", list)
	}
}

func TestResumeStaleMarkerNoReboot(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "resume"))
	priv := testKey(t)

	m := &Marker{
		RunID: "tr_stale", Kind: KindTask, TaskID: "task_1", TaskVersion: 1,
		StartIdx: 0,
		Steps:    []*pb.TaskStep{{Kind: "command", Name: "echo", Command: "/bin/echo"}},
		Decision: signedDecision(priv, "tr_stale", 1),
		// Marker from 10 minutes ago, host has been up 2 hours: no reboot.
		CreatedAt: time.Now().Add(-10 * time.Minute).Unix(),
	}
	if err := store.Save(m); err != nil {
		t.Fatal(err)
	}

	tr := &taskReports{}
	r := New(store, task.NewExecutor(elevate.None, nil), testGuard(t, 1, priv), nil, nil, nil, tr.fn(), nil)
	r.SetBootAge(func() (time.Duration, bool) { return 2 * time.Hour, true })

	r.ResumePending()

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if !tr.called || tr.state != "failed" {
		t.Fatalf("report: called=%v state=%q", tr.called, tr.state)
	}
	if tr.errMsg == "" {
		t.Fatal("expected a failure reason")
	}
	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("stale marker not deleted: %+v", list)
	}
}

func TestResumeGuardNotLoadedDefers(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "resume"))
	priv := testKey(t)

	m := &Marker{
		RunID: "tr_defer", Kind: KindTask, TaskID: "task_1", TaskVersion: 1,
		StartIdx:  0,
		Steps:     []*pb.TaskStep{{Kind: "command", Name: "echo", Command: "/bin/echo"}},
		Decision:  signedDecision(priv, "tr_defer", 1),
		CreatedAt: time.Now().Add(-time.Minute).Unix(),
	}
	if err := store.Save(m); err != nil {
		t.Fatal(err)
	}

	// Guard with no bundle loaded: resume must defer (keep the marker).
	g := guardrail.NewGuard("agent_1", t.TempDir())
	tr := &taskReports{}
	r := New(store, task.NewExecutor(elevate.None, nil), g, nil, nil, nil, tr.fn(), nil)
	r.SetBootAge(func() (time.Duration, bool) { return 30 * time.Second, true })

	r.ResumePending()

	tr.mu.Lock()
	called := tr.called
	tr.mu.Unlock()
	if called {
		t.Fatal("report sent before the policy bundle loaded")
	}
	list, _ := store.List()
	if len(list) != 1 {
		t.Fatalf("marker should be kept for the next bundle push: %d", len(list))
	}
}

func TestResumeDeniedByPolicy(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "resume"))
	priv := testKey(t)

	m := &Marker{
		RunID: "tr_denied", Kind: KindTask, TaskID: "task_1", TaskVersion: 1,
		StartIdx: 0,
		Steps:    []*pb.TaskStep{{Kind: "command", Name: "echo", Command: "/bin/echo"}},
		// Decision signed against bundle v1; guard is now on v2 → stale.
		Decision:  signedDecision(priv, "tr_denied", 1),
		CreatedAt: time.Now().Add(-time.Minute).Unix(),
	}
	if err := store.Save(m); err != nil {
		t.Fatal(err)
	}

	tr := &taskReports{}
	r := New(store, task.NewExecutor(elevate.None, nil), testGuard(t, 2, priv), nil, nil, nil, tr.fn(), nil)
	r.SetBootAge(func() (time.Duration, bool) { return 30 * time.Second, true })

	r.ResumePending()

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if !tr.called || tr.state != "failed" {
		t.Fatalf("report: called=%v state=%q", tr.called, tr.state)
	}
	if tr.errMsg == "" {
		t.Fatal("expected a denial reason")
	}
	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("denied marker not deleted: %+v", list)
	}
}
