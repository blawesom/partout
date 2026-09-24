// REST handlers for scheduled jobs (M3, PRD §5.4).
//
// Routes:
//
//	GET    /api/v1/jobs              (viewer) — list jobs
//	POST   /api/v1/jobs              (operator) — create a job
//	GET    /api/v1/jobs/{id}         (viewer) — job detail
//	PUT    /api/v1/jobs/{id}         (operator) — update a job
//	DELETE /api/v1/jobs/{id}         (operator) — delete a job
//	GET    /api/v1/jobs/{id}/runs    (viewer) — job runs
//	POST   /api/v1/jobs/{id}/run     (operator) — dispatch a manual run on a host
package api

import (
	"encoding/json"
	"net/http"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/jobs"
)

// RegisterJobs wires the job REST routes.
func (h *Handler) RegisterJobs(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/jobs", h.requireRole(roleViewer)(http.HandlerFunc(h.jobList)))
	mux.Handle("POST /api/v1/jobs", h.requireRole(roleOperator)(http.HandlerFunc(h.jobCreate)))
	mux.Handle("GET /api/v1/jobs/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.jobGet)))
	mux.Handle("PUT /api/v1/jobs/{id}", h.requireRole(roleOperator)(http.HandlerFunc(h.jobUpdate)))
	mux.Handle("DELETE /api/v1/jobs/{id}", h.requireRole(roleOperator)(http.HandlerFunc(h.jobDelete)))
	mux.Handle("GET /api/v1/jobs/{id}/runs", h.requireRole(roleViewer)(http.HandlerFunc(h.jobRuns)))
	mux.Handle("POST /api/v1/jobs/{id}/run", h.requireRole(roleOperator)(http.HandlerFunc(h.jobRun)))
	mux.Handle("GET /api/v1/jobs/runs", h.requireRole(roleViewer)(http.HandlerFunc(h.jobRunsList)))
}

func (h *Handler) jobList(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeError(w, http.StatusServiceUnavailable, "jobs_disabled", "jobs not initialized", nil)
		return
	}
	jobs, err := h.jobs.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, map[string]any{
			"id": j.ID, "name": j.Name, "task_id": j.TaskID,
			"task_version": j.TaskVersion, "cron": j.Cron,
			"selector": j.Selector, "enabled": j.Enabled,
			"created": j.Created, "updated": j.Updated,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) jobCreate(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeError(w, http.StatusServiceUnavailable, "jobs_disabled", "jobs not initialized", nil)
		return
	}
	var spec jobs.Job
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if spec.Name == "" || spec.Cron == "" || spec.TaskID == "" || spec.Selector == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "name, cron, task_id, and selector required", nil)
		return
	}
	job, err := h.jobs.Create(r.Context(), spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": job.ID})
}

func (h *Handler) jobGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := h.jobs.Get(id)
	if err != nil || job == nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	out := map[string]any{
		"id": job.ID, "name": job.Name, "task_id": job.TaskID,
		"task_version": job.TaskVersion, "cron": job.Cron,
		"selector": job.Selector, "max_run_s": job.MaxRunSeconds,
		"enabled": job.Enabled, "created": job.Created, "updated": job.Updated,
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) jobUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var spec jobs.Job
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	job, err := h.jobs.Update(r.Context(), id, spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": job.ID, "updated": job.Updated})
}

func (h *Handler) jobDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.jobs.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (h *Handler) jobRuns(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	runs, err := h.jobs.RunsForJob(id, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(runs))
	for _, r2 := range runs {
		out = append(out, map[string]any{
			"id": r2.ID, "agent_id": r2.AgentID, "state": r2.State,
			"scheduled_at": r2.ScheduledAt, "started_at": r2.StartedAt,
			"finished_at": r2.FinishedAt, "trigger": r2.Trigger, "error": r2.Error,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) jobRun(w http.ResponseWriter, r *http.Request) {
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
	if err := h.jobs.RunNow(r.Context(), id, body.AgentID); err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dispatched": id, "agent": body.AgentID})
}

// JobRunResultHook is called by the stream handler when an agent reports a job run.
func (h *Handler) JobRunResultHook(agentID string, r *pb.JobRunResult) {
	if h.jobs != nil {
		h.jobs.OnRunResult(agentID, r)
	}
}

// ListJobRuns is a convenience endpoint for all job runs across all jobs.
func (h *Handler) jobRunsList(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeError(w, http.StatusServiceUnavailable, "jobs_disabled", "jobs not initialized", nil)
		return
	}
	runs, err := h.jobs.ListRuns(100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(runs))
	for _, r2 := range runs {
		out = append(out, map[string]any{
			"id": r2.ID, "job_id": r2.JobID, "agent_id": r2.AgentID,
			"state": r2.State, "trigger": r2.Trigger, "created": r2.ScheduledAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}