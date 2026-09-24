package jobs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/agent/guardrail"
	"github.com/blawesom/partout/internal/agent/task"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
)

// testKey generates a throwaway server Ed25519 signing key for tests.
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return priv
}

// testGuard builds a guard populated with a policy bundle (version v,
// default-allow rule set, server key priv.Public()).
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

// signedDecision signs an allow decision bound to runID + bundle version v.
func signedDecision(priv ed25519.PrivateKey, runID string, v uint64) *pb.Decision {
	sig := policy.SignDecision(priv, runID, v, policy.EffectAllow, nil, "admin")
	return &pb.Decision{
		RunId: runID, BundleVersion: v, Effect: policy.EffectAllow,
		Sig: sig, ActorRole: "admin",
	}
}

func echoAssignment(jobID string) *Assignment {
	return &Assignment{
		JobID: jobID, Name: "echo job", Cron: "* * * * *",
		Timezone: "UTC", TaskID: "task_1", TaskVersion: 1,
		Steps: []*pb.TaskStep{
			{Kind: "command", Name: "echo", Command: "/bin/echo", Args: []string{"hello"}},
		},
		OverlapPolicy: "skip", FailurePolicy: "no_retry",
	}
}

// TestSchedulerApplyAndPersist verifies that a job assignment is applied,
// persisted (including the signed decision), and re-loaded on restart.
func TestSchedulerApplyAndPersist(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	s := New(tmp, exec, nil, nil)

	a := &Assignment{
		JobID: "job_1", Name: "test job", Cron: "*/5 * * * *",
		Timezone: "UTC", TaskID: "task_1", TaskVersion: 1,
		Steps:         []*pb.TaskStep{{Kind: "command", Name: "echo", Command: "echo"}},
		OverlapPolicy: "skip", FailurePolicy: "no_retry",
		Decision: signedDecision(testKey(t), "job_1", 3),
	}
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// It should be persisted to disk.
	list := s.List()
	if len(list) != 1 || list[0].JobID != "job_1" {
		t.Fatalf("List: got %d, want 1", len(list))
	}
	if list[0].Decision == nil {
		t.Fatal("List: decision not preserved")
	}

	// Simulate a restart: load from disk into a fresh scheduler.
	s2 := New(tmp, task.NewExecutor(nil), nil, nil)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	list2 := s2.List()
	if len(list2) != 1 || list2[0].JobID != "job_1" {
		t.Fatalf("List: got %d, want 1", len(list2))
	}
	if list2[0].Decision == nil || list2[0].Decision.BundleVersion != 3 {
		t.Fatal("Load: decision not restored from disk")
	}

	// Remove.
	s.Remove("job_1")
	if len(s.List()) != 0 {
		t.Fatalf("Remove: still listed after remove")
	}
}

// TestSchedulerBadCron verifies a bad cron expression is rejected.
func TestSchedulerBadCron(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	s := New(tmp, exec, nil, nil)

	a := &Assignment{JobID: "job_1", Cron: "not-a-cron", TaskID: "task_1"}
	if err := s.Apply(a); err == nil {
		t.Fatal("Apply: expected error for bad cron, got nil")
	}
}

// waitForReport blocks until n reports arrive (5s deadline).
func waitForReport(reports *[]*Report, mu *sync.Mutex, n int, t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := len(*reports)
		mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no job run report received")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSchedulerRunNow verifies a manual run with a valid signed decision
// fires the task and reports success.
func TestSchedulerRunNow(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	priv := testKey(t)

	var mu sync.Mutex
	var reports []*Report
	s := New(tmp, exec, func(r *Report) {
		mu.Lock()
		reports = append(reports, r)
		mu.Unlock()
	}, nil)
	s.SetGuard(testGuard(t, 7, priv))

	a := echoAssignment("job_1")
	a.Decision = signedDecision(priv, "job_1", 7)
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := s.RunNow("job_1"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}

	waitForReport(&reports, &mu, 1, t)
	mu.Lock()
	r := reports[0]
	mu.Unlock()
	if r.JobID != "job_1" {
		t.Fatalf("report job_id=%q, want job_1", r.JobID)
	}
	if r.State != "succeeded" {
		t.Fatalf("report state=%q, want succeeded (err=%s)", r.State, r.Error)
	}
	if r.Trigger != "manual" {
		t.Fatalf("report trigger=%q, want manual", r.Trigger)
	}
}

// TestSchedulerFireNoDecisionDenied verifies fail-closed: an assignment
// without a signed decision (e.g. pre-upgrade legacy) never executes.
func TestSchedulerFireNoDecisionDenied(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	priv := testKey(t)

	var mu sync.Mutex
	var reports []*Report
	s := New(tmp, exec, func(r *Report) {
		mu.Lock()
		reports = append(reports, r)
		mu.Unlock()
	}, nil)
	s.SetGuard(testGuard(t, 1, priv))

	a := echoAssignment("job_1") // no Decision
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := s.RunNow("job_1"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	waitForReport(&reports, &mu, 1, t)
	mu.Lock()
	r := reports[0]
	mu.Unlock()
	if r.State != "denied" {
		t.Fatalf("report state=%q, want denied (err=%s)", r.State, r.Error)
	}
}

// TestSchedulerFireNoGuardDenied verifies fail-closed when a decision is
// present but no guard is available to verify it.
func TestSchedulerFireNoGuardDenied(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	priv := testKey(t)

	var mu sync.Mutex
	var reports []*Report
	s := New(tmp, exec, func(r *Report) {
		mu.Lock()
		reports = append(reports, r)
		mu.Unlock()
	}, nil) // no SetGuard

	a := echoAssignment("job_1")
	a.Decision = signedDecision(priv, "job_1", 1)
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := s.RunNow("job_1"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	waitForReport(&reports, &mu, 1, t)
	mu.Lock()
	r := reports[0]
	mu.Unlock()
	if r.State != "denied" {
		t.Fatalf("report state=%q, want denied (err=%s)", r.State, r.Error)
	}
}

// TestSchedulerFireStaleBundleDenied verifies a decision signed against an
// older policy bundle version is rejected after a bundle update (the job
// must be re-saved to re-authorize).
func TestSchedulerFireStaleBundleDenied(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	priv := testKey(t)

	var mu sync.Mutex
	var reports []*Report
	s := New(tmp, exec, func(r *Report) {
		mu.Lock()
		reports = append(reports, r)
		mu.Unlock()
	}, nil)
	s.SetGuard(testGuard(t, 2, priv)) // guard now at bundle v2

	a := echoAssignment("job_1")
	a.Decision = signedDecision(priv, "job_1", 1) // signed against v1
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := s.RunNow("job_1"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	waitForReport(&reports, &mu, 1, t)
	mu.Lock()
	r := reports[0]
	mu.Unlock()
	if r.State != "denied" {
		t.Fatalf("report state=%q, want denied (err=%s)", r.State, r.Error)
	}
}

// TestSchedulerFireBadSignatureDenied verifies a decision with an invalid
// signature (wrong key) is rejected.
func TestSchedulerFireBadSignatureDenied(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	priv := testKey(t)
	other := testKey(t)

	var mu sync.Mutex
	var reports []*Report
	s := New(tmp, exec, func(r *Report) {
		mu.Lock()
		reports = append(reports, r)
		mu.Unlock()
	}, nil)
	s.SetGuard(testGuard(t, 1, priv)) // guard knows priv's public key

	a := echoAssignment("job_1")
	a.Decision = signedDecision(other, "job_1", 1) // signed by the wrong key
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := s.RunNow("job_1"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	waitForReport(&reports, &mu, 1, t)
	mu.Lock()
	r := reports[0]
	mu.Unlock()
	if r.State != "denied" {
		t.Fatalf("report state=%q, want denied (err=%s)", r.State, r.Error)
	}
}
