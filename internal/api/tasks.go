// REST handlers for tasks and playbooks (M3, PRD §5.5).
//
// Routes:
//
//	GET  /api/v1/tasks                  (viewer) — list tasks
//	POST /api/v1/tasks                  (operator) — create a task (v1)
//	GET  /api/v1/tasks/{id}             (viewer) — task + latest steps
//	POST /api/v1/tasks/{id}/run         (operator) — run task on a host
//	GET  /api/v1/tasks/runs             (viewer) — list runs
//	GET  /api/v1/tasks/runs/{id}        (viewer) — run + steps
//	GET  /api/v1/playbooks              (viewer) — list playbooks
//	POST /api/v1/playbooks              (operator) — create a playbook
package api

import (
	"encoding/json"
	"net/http"

	"github.com/blawesom/partout/internal/id"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/tasks"
	"github.com/blawesom/partout/internal/store"
)

// RegisterTasks wires the task and playbook REST routes.
func (h *Handler) RegisterTasks(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/tasks", h.requireRole(roleViewer)(http.HandlerFunc(h.taskList)))
	mux.Handle("POST /api/v1/tasks", h.requireRole(roleOperator)(http.HandlerFunc(h.taskCreate)))
	mux.Handle("GET /api/v1/tasks/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.taskGet)))
	mux.Handle("POST /api/v1/tasks/{id}/run", h.requireRole(roleOperator)(http.HandlerFunc(h.taskRun)))
	mux.Handle("GET /api/v1/tasks/runs", h.requireRole(roleViewer)(http.HandlerFunc(h.taskRuns)))
	mux.Handle("GET /api/v1/tasks/runs/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.taskRunGet)))
	mux.Handle("GET /api/v1/playbooks", h.requireRole(roleViewer)(http.HandlerFunc(h.playbookList)))
	mux.Handle("POST /api/v1/playbooks", h.requireRole(roleOperator)(http.HandlerFunc(h.playbookCreate)))
}

// taskActor derives the requester identity (username + role).
func (h *Handler) taskActor(r *http.Request) (string, string) {
	return h.actorFor(r)
}

func (h *Handler) taskList(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "tasks_disabled", "tasks not initialized", nil)
		return
	}
	tasks, err := h.st.ListTasks(50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, map[string]any{
			"id": t.ID, "name": t.Name, "description": t.Description,
			"created": t.Created, "updated": t.Updated,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) taskCreate(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "tasks_disabled", "tasks not initialized", nil)
		return
	}
	var body struct {
		Name        string           `json:"name"`
		Description string           `json:"description"`
		Steps       []store.TaskStep `json:"steps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if body.Name == "" || len(body.Steps) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "name and steps required", nil)
		return
	}
	id := "task_" + id.New("task")
	task := &store.Task{ID: id, Name: body.Name, Description: body.Description}
	if err := h.st.CreateTask(task); err != nil {
		writeError(w, http.StatusConflict, "exists", "task already exists", nil)
		return
	}
	stepsJSON, _ := json.Marshal(body.Steps)
	ver := &store.TaskVersion{TaskID: id, Version: 1, StepsJSON: string(stepsJSON)}
	if err := h.st.UpsertTaskVersion(ver); err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "version": 1})
}

func (h *Handler) taskGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, err := h.st.Task(id)
	if err != nil || task == nil {
		writeError(w, http.StatusNotFound, "not_found", "task not found", nil)
		return
	}
	ver, _ := h.st.LatestTaskVersion(id)
	steps, _ := store.DecodeTaskSteps(ver.StepsJSON)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": task.ID, "name": task.Name, "description": task.Description,
		"version": ver.Version, "steps": steps, "created": task.Created,
	})
}

func (h *Handler) taskRun(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "tasks_disabled", "tasks not initialized", nil)
		return
	}
	id := r.PathValue("id")
	var body struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if body.AgentID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id required", nil)
		return
	}
	ver, err := h.st.LatestTaskVersion(id)
	if err != nil || ver == nil {
		writeError(w, http.StatusNotFound, "not_found", "no task version", nil)
		return
	}
	steps, err := store.DecodeTaskSteps(ver.StepsJSON)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	// Convert store.TaskStep → pb.TaskStep.
	pbSteps := make([]*pb.TaskStep, 0, len(steps))
	for _, s := range steps {
		pbSteps = append(pbSteps, &pb.TaskStep{
			Kind: s.Kind, Name: s.Name, When: s.When,
			Command: s.Command, Args: s.Args, Env: s.Env,
			Path: s.Path, Content: s.Content, Template: s.Template, Vars: s.Vars,
			Mode: s.Mode, Package: s.Package, State: s.State,
			Service: s.Service, User: s.User, Group: s.Group, Expr: s.Expr,
		})
	}
	principal, role := h.taskActor(r)
	run, err := h.tasks.Run(r.Context(), body.AgentID, id, ver.Version, pbSteps,
		tasks.Actor{Principal: principal, Role: role})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run_id": run.ID, "state": run.State})
}

func (h *Handler) taskRuns(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "tasks_disabled", "tasks not initialized", nil)
		return
	}
	runs, err := h.tasks.ListRuns(50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(runs))
	for _, r2 := range runs {
		out = append(out, map[string]any{
			"id": r2.ID, "task_id": r2.TaskID, "task_version": r2.TaskVersion,
			"agent_id": r2.AgentID, "state": r2.State,
			"started": r2.Started, "finished": r2.Finished, "error": r2.Error,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) taskRunGet(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "tasks_disabled", "tasks not initialized", nil)
		return
	}
	id := r.PathValue("id")
	run, err := h.tasks.GetRun(id)
	if err != nil || run == nil {
		writeError(w, http.StatusNotFound, "not_found", "run not found", nil)
		return
	}
	steps, _ := h.tasks.ListSteps(id)
	stepsOut := make([]map[string]any, 0, len(steps))
	for _, s := range steps {
		stepsOut = append(stepsOut, map[string]any{
			"index": s.StepIdx, "kind": s.Kind, "name": s.Name,
			"state": s.State, "detail": s.Detail,
			"started": s.Started, "finished": s.Finished,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": run.ID, "task_id": run.TaskID, "task_version": run.TaskVersion,
		"agent_id": run.AgentID, "state": run.State,
		"started": run.Started, "finished": run.Finished, "error": run.Error,
		"steps": stepsOut,
	})

}

func (h *Handler) playbookList(w http.ResponseWriter, r *http.Request) {
	playbooks, err := h.st.ListPlaybooks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(playbooks))
	for _, p := range playbooks {
		out = append(out, map[string]any{
			"id": p.ID, "name": p.Name, "task_id": p.TaskID,
			"task_version": p.TaskVersion, "selector": p.Selector, "created": p.Created,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) playbookCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		TaskID      string `json:"task_id"`
		TaskVersion int    `json:"task_version"`
		Selector    string `json:"selector"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if body.Name == "" || body.TaskID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "name and task_id required", nil)
		return
	}
	// Default to latest version if not specified.
	if body.TaskVersion == 0 {
		ver, err := h.st.LatestTaskVersion(body.TaskID)
		if err != nil || ver == nil {
			writeError(w, http.StatusNotFound, "not_found", "no task version", nil)
			return
		}
		body.TaskVersion = ver.Version
	}
	p := &store.Playbook{
		ID: "pb_" + id.New("pb"), Name: body.Name, TaskID: body.TaskID,
		TaskVersion: body.TaskVersion, Selector: body.Selector,
	}
	if err := h.st.CreatePlaybook(p); err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": p.ID})
}
