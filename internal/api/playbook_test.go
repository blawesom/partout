package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/server/tasks"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestPlaybookRunFansOutToSelector is the API E2E for POST
// /api/v1/playbooks/{id}/run: a playbook's pinned task runs on every host
// the selector matches (the fixture agent answers task runs).
func TestPlaybookRunFansOutToSelector(t *testing.T) {
	apiH, streamH, srv := startAPITest(t)

	// The shared fixture leaves the tasks controller off; wire it here.
	apiH.SetTasks(tasks.New(apiH.Store(), streamH, sse.New(), nil))

	// Seed a task (v1) + a playbook pointing at it with a matching selector.
	if err := apiH.Store().CreateTask(&store.Task{ID: "task_pb", Name: "pb task"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := apiH.Store().UpsertTaskVersion(&store.TaskVersion{TaskID: "task_pb", Version: 1,
		StepsJSON: `[{"kind":"command","command":"uptime"}]`}); err != nil {
		t.Fatalf("UpsertTaskVersion: %v", err)
	}
	if err := apiH.Store().CreatePlaybook(&store.Playbook{
		ID: "pb_test", Name: "pb", TaskID: "task_pb", TaskVersion: 1,
		Selector: "role:test",
	}); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	resp, err := http.Post(srv.URL+"/api/v1/playbooks/pb_test/run",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST playbook run: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		PlaybookID string `json:"playbook_id"`
		Runs       []struct {
			RunID   string `json:"run_id"`
			AgentID string `json:"agent_id"`
			State   string `json:"state"`
		} `json:"runs"`
		Errors []string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.PlaybookID != "pb_test" {
		t.Fatalf("playbook_id = %q", body.PlaybookID)
	}
	if len(body.Runs) != 1 {
		t.Fatalf("runs = %+v, want 1 (fixture has one matching host)", body.Runs)
	}
	if body.Runs[0].AgentID != "ag_api" || body.Runs[0].State != "succeeded" {
		t.Fatalf("run = %+v, want ag_api succeeded", body.Runs[0])
	}
	if len(body.Errors) != 0 {
		t.Fatalf("errors = %v", body.Errors)
	}
}
