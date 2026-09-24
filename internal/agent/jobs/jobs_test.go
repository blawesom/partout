package jobs

import (
	"sync"
	"testing"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/agent/task"
)

// TestSchedulerApplyAndPersist verifies that a job assignment is applied,
// persisted, and re-loaded on restart.
func TestSchedulerApplyAndPersist(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)
	s := New(tmp, exec, nil, nil)

	a := &Assignment{
		JobID: "job_1", Name: "test job", Cron: "*/5 * * * *",
		Timezone: "UTC", TaskID: "task_1", TaskVersion: 1,
		Steps: []*pb.TaskStep{{Kind: "command", Name: "echo", Command: "echo"}},
		OverlapPolicy: "skip", FailurePolicy: "no_retry",
	}
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// It should be persisted to disk.
	list := s.List()
	if len(list) != 1 || list[0].JobID != "job_1" {
		t.Fatalf("List: got %d, want 1", len(list))
	}

	// Simulate a restart: load from disk into a fresh scheduler.
	s2 := New(tmp, task.NewExecutor(nil), nil, nil)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	list2 := s2.List()
	if len(list2) != 1 || list2[0].JobID != "job_1" {
		t.Fatalf("Load: got %d, want 1", len(list2))
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

// TestSchedulerRunNow verifies a manual run fires the task and reports.
func TestSchedulerRunNow(t *testing.T) {
	tmp := t.TempDir()
	exec := task.NewExecutor(nil)

	var mu sync.Mutex
	var reports []*Report
	s := New(tmp, exec, func(r *Report) {
		mu.Lock()
		reports = append(reports, r)
		mu.Unlock()
	}, nil)

	a := &Assignment{
		JobID: "job_1", Name: "echo job", Cron: "* * * * *",
		Timezone: "UTC", TaskID: "task_1", TaskVersion: 1,
		Steps: []*pb.TaskStep{
			{Kind: "command", Name: "echo", Command: "/bin/echo", Args: []string{"hello"}},
		},
		OverlapPolicy: "skip", FailurePolicy: "no_retry",
	}
	if err := s.Apply(a); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := s.RunNow("job_1"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}

	// Wait for the report.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(reports)
		mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no job run report received")
		}
		time.Sleep(50 * time.Millisecond)
	}

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