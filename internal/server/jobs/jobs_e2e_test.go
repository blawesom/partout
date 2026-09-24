package jobs_test

import (
	"context"
	"io"
	"log"
	"testing"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/jobs"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// --- store tests -----------------------------------------------------------

func TestJobCRUD(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create a task first (FK).
	if err := st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	stepsJSON := `[{"kind":"command","name":"echo","command":"echo","args":["hi"]}]`
	if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_test", Version: 1, StepsJSON: stepsJSON}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}

	job := &store.Job{
		ID: "job_test", Name: "test job", TaskID: "task_test", TaskVersion: 1,
		Cron: "*/5 * * * *", Selector: "all", MaxRunSeconds: 60, Enabled: true,
	}
	if err := st.CreateJob(job); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	// Get.
	fetched, err := st.GetJob("job_test")
	if err != nil || fetched == nil {
		t.Fatalf("GetJob: %v %v", err, fetched)
	}
	if fetched.Name != "test job" || fetched.Cron != "*/5 * * * *" {
		t.Fatalf("bad job: %+v", fetched)
	}

	// Update.
	fetched.Cron = "*/10 * * * *"
	if err := st.UpdateJob(fetched); err != nil {
		t.Fatalf("UpdateJob: %v", err)
	}
	refetched, _ := st.GetJob("job_test")
	if refetched.Cron != "*/10 * * * *" {
		t.Fatalf("cron=%q, want */10 * * * *", refetched.Cron)
	}

	// List.
	listed, err := st.ListJobs()
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d jobs, want 1", len(listed))
	}

	// Delete.
	if err := st.DeleteJob("job_test"); err != nil {
		t.Fatalf("DeleteJob: %v", err)
	}
	deleted, _ := st.GetJob("job_test")
	if deleted != nil {
		t.Fatalf("job still exists after delete")
	}
}

func TestJobRunCRUD(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateJob(&store.Job{
		ID: "job_test", Name: "test", TaskID: "task_test", TaskVersion: 1,
		Cron: "* * * * *", Selector: "all",
	}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	run := &store.JobRun{
		ID: "jr_test", JobID: "job_test", AgentID: "ag_test",
		TaskID: "task_test", TaskVersion: 1,
		ScheduledAt: 100, StartedAt: 101, FinishedAt: 102,
		State: "succeeded", Trigger: "cron",
	}
	if err := st.CreateJobRun(run); err != nil {
		t.Fatalf("CreateJobRun: %v", err)
	}

	fetched, err := st.GetJobRun("jr_test")
	if err != nil || fetched == nil {
		t.Fatalf("GetJobRun: %v %v", err, fetched)
	}
	if fetched.State != "succeeded" {
		t.Fatalf("state=%q, want succeeded", fetched.State)
	}

	runs, err := st.JobRunsForJob("job_test", 10)
	if err != nil {
		t.Fatalf("JobRunsForJob: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("listed %d runs, want 1", len(runs))
	}

	all, err := st.ListJobRuns(10)
	if err != nil {
		t.Fatalf("ListJobRuns: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("listed %d runs, want 1", len(all))
	}
}

func TestJobAssignmentCRUD(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateJob(&store.Job{
		ID: "job_test", Name: "test", TaskID: "task_test", TaskVersion: 1,
		Cron: "* * * * *", Selector: "all",
	}); err != nil {
		t.Fatal(err)
	}

	if err := st.AssignJob(&store.JobAssignment{JobID: "job_test", AgentID: "ag_test"}); err != nil {
		t.Fatalf("AssignJob: %v", err)
	}

	// For agent.
	forAgent, err := st.JobAssignmentsForAgent("ag_test")
	if err != nil {
		t.Fatalf("JobAssignmentsForAgent: %v", err)
	}
	if len(forAgent) != 1 || forAgent[0].JobID != "job_test" {
		t.Fatalf("bad agent assignments: %+v", forAgent)
	}

	// For job.
	forJob, err := st.JobAssignmentsForJob("job_test")
	if err != nil {
		t.Fatalf("JobAssignmentsForJob: %v", err)
	}
	if len(forJob) != 1 || forJob[0].AgentID != "ag_test" {
		t.Fatalf("bad job assignments: %+v", forJob)
	}

	// Update state.
	if err := st.UpdateJobAssignmentState("job_test", "ag_test", "succeeded", 100); err != nil {
		t.Fatalf("UpdateJobAssignmentState: %v", err)
	}
	forJob, _ = st.JobAssignmentsForJob("job_test")
	if forJob[0].LastRunState != "succeeded" {
		t.Fatalf("last_run_state=%q, want succeeded", forJob[0].LastRunState)
	}

	// Unassign.
	if err := st.UnassignJob("job_test", "ag_test"); err != nil {
		t.Fatalf("UnassignJob: %v", err)
	}
	forJob, _ = st.JobAssignmentsForJob("job_test")
	if len(forJob) != 0 {
		t.Fatalf("listed %d assignments after unassign, want 0", len(forJob))
	}
}

// --- controller test (selector resolution + dispatch) ----------------------

func TestControllerCreateResolvesSelector(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Enroll a host with a tag.
	if err := st.UpsertAgent(store.Agent{ID: "ag_test", UUID: "uuid", ED25519Pub: "eA==", X25519Pub: "eA=="}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetTag("ag_test", "env", "test"); err != nil {
		t.Fatalf("SetTags: %v", err)
	}

	// Create a task.
	if err := st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: "task_test", Version: 1,
		StepsJSON: `[{"kind":"command","name":"echo","command":"echo"}]`}); err != nil {
		t.Fatal(err)
	}

	// Controller without a stream (SendJobAssign will fail, but the job row
	// + assignment should still be recorded).
	sseB := sse.New()
	lg := log.New(io.Discard, "jobs:", 0)
	ctrl := jobs.New(st, nil, sseB, lg)

	job, err := ctrl.Create(context.Background(), jobs.Job{
		Name: "cron job", TaskID: "task_test",
		Cron: "* * * * *", Selector: "tag:env=test",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The assignment should be recorded even though the stream send failed.
	assignments, err := st.JobAssignmentsForJob(job.ID)
	if err != nil {
		t.Fatalf("JobAssignmentsForJob: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("listed %d assignments, want 1", len(assignments))
	}
}

// Verify the JobRunResultHook wiring (OnRunResult records a run row).
func TestControllerOnRunResult(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateTask(&store.Task{ID: "task_test", Name: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateJob(&store.Job{
		ID: "job_test", Name: "test", TaskID: "task_test", TaskVersion: 1,
		Cron: "* * * * *", Selector: "all",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AssignJob(&store.JobAssignment{JobID: "job_test", AgentID: "ag_test"}); err != nil {
		t.Fatal(err)
	}

	sseB := sse.New()
	lg := log.New(io.Discard, "jobs:", 0)
	ctrl := jobs.New(st, nil, sseB, lg)

	// Simulate an agent reporting a job run.
	ctrl.OnRunResult("ag_test", &pb.JobRunResult{
		RunId: "jr_1", JobId: "job_test", State: "succeeded",
		ScheduledAt: 100, StartedAt: 101, FinishedAt: 102, Trigger: "cron",
	})

	// The run row should be recorded.
	run, err := st.GetJobRun("jr_1")
	if err != nil || run == nil {
		t.Fatalf("GetJobRun: %v %v", err, run)
	}
	if run.State != "succeeded" || run.TaskID != "task_test" {
		t.Fatalf("bad run: %+v", run)
	}

	// The assignment's last-run state should be updated.
	assignments, _ := st.JobAssignmentsForJob("job_test")
	if len(assignments) != 1 || assignments[0].LastRunState != "succeeded" {
		t.Fatalf("bad assignment: %+v", assignments)
	}
}
