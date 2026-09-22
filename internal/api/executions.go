// Package api — executions, output, and audit endpoints (PRD §10.2).
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/store"
)

// RegisterExecutions adds executions/output/audit endpoints to mux.
func (h *Handler) RegisterExecutions(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/executions", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListExecutions)))
	mux.Handle("POST /api/v1/executions", h.requireRole(roleOperator)(http.HandlerFunc(h.handleCreateExecution)))
	mux.Handle("GET /api/v1/executions/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetExecution)))
	mux.Handle("POST /api/v1/executions/{id}/cancel", h.requireRole(roleOperator)(http.HandlerFunc(h.handleCancelExecution)))
	mux.Handle("GET /api/v1/executions/{id}/output", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetOutput)))
	mux.Handle("GET /api/v1/audit", h.requireRole(roleViewer)(http.HandlerFunc(h.handleAudit)))
}

// ---- /api/v1/executions ----------------------------------------------------

func (h *Handler) handleListExecutions(w http.ResponseWriter, r *http.Request) {
	limit, cursor := pageParams(r, 50)

	execs, err := h.st.ExecutionsPage(limit, cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list executions", nil)
		return
	}

	entries := make([]map[string]any, 0, len(execs))
	for _, e := range execs {
		entries = append(entries, execToMap(e))
	}

	var next string
	if len(entries) == limit {
		next = execs[len(execs)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "next_cursor": next})
}

// handleCreateExecution dispatches a new command (PRD R4).
func (h *Handler) handleCreateExecution(w http.ResponseWriter, r *http.Request) {
	var req control.DispatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	if req.Selector == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "selector is required", nil)
		return
	}
	// Inject the requester's RBAC role so the policy engine can gate on it
	// (actor_roles in the rule match). The client-provided value is ignored.
	req.ActorRole = h.roleFor(r)
	res, err := h.ctrl.Dispatch(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusConflict, "conflict", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) handleGetExecution(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e, err := h.st.GetExecution(id)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "execution not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get execution", nil)
		return
	}
	detail, err := execDetail(h, e)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to build execution detail", nil)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *Handler) handleCancelExecution(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := h.ctrl.CancelExecution(id, "api")
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "execution not found", nil)
			return
		}
		writeError(w, http.StatusConflict, "conflict", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) handleGetOutput(w http.ResponseWriter, r *http.Request) {
	execID := r.PathValue("id")
	streamParam := r.URL.Query().Get("stream")
	runID := r.URL.Query().Get("run_id")

	if _, err := h.st.GetExecution(execID); isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "execution not found", nil)
		return
	}

	runs, err := h.st.ListRunsForExecution(execID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list runs", nil)
		return
	}

	if runID != "" {
		// single run
		var ok bool
		for _, run := range runs {
			if run.ID == runID {
				ok = true
				break
			}
		}
		if !ok {
			writeError(w, http.StatusNotFound, "not_found", "run not found", nil)
			return
		}
		out, err := h.runOutput(runID, streamParam)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to get output", nil)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	// all runs
	out := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		o, err := h.runOutput(run.ID, streamParam)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to get output", nil)
			return
		}
		o["run_id"] = run.ID
		o["agent_id"] = run.AgentID
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, out)
}

// runOutput returns the output for a single run.
func (h *Handler) runOutput(runID, streamParam string) (map[string]any, error) {
	chunks, err := h.st.ListOutput(runID)
	if err != nil {
		return nil, err
	}
	stdout, stderr := []byte{}, []byte{}
	for _, c := range chunks {
		if c.Stream == "stderr" {
			stderr = append(stderr, c.Data...)
		} else {
			stdout = append(stdout, c.Data...)
		}
	}
	out := map[string]any{}
	if streamParam == "" || streamParam == "stdout" {
		out["stdout"] = string(stdout)
	}
	if streamParam == "" || streamParam == "stderr" {
		out["stderr"] = string(stderr)
	}
	return out, nil
}

// ---- /api/v1/audit ---------------------------------------------------------

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, cursorStr := pageParams(r, 100)
	var cursor int64
	if cursorStr != "" {
		cursor, _ = strconv.ParseInt(cursorStr, 10, 64)
	}
	kind := r.URL.Query().Get("kind")
	actor := r.URL.Query().Get("actor")
	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		since, _ = strconv.ParseInt(s, 10, 64)
	}

	events, err := h.st.AuditPage(kind, actor, since, limit, cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list audit", nil)
		return
	}
	entries := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		entries = append(entries, map[string]any{
			"ts":       ev.TS,
			"kind":     ev.Kind,
			"actor":    ev.Actor,
			"agent_id": ev.AgentID,
			"payload":  ev.Payload,
		})
	}
	var next string
	if len(entries) == limit && len(entries) > 0 {
		// use ts of last event as cursor
		next = strconv.FormatInt(events[len(events)-1].TS, 10)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "next_cursor": next})
}

// ---- helpers -----------------------------------------------------------------

func execToMap(e *store.Execution) map[string]any {
	m := map[string]any{
		"id":         e.ID,
		"selector":   e.Selector,
		"cmd":        e.Cmd,
		"created":    e.Created,
		"created_by": e.CreatedBy,
		"state":      e.State,
	}
	if e.ArgsJSON != "" {
		var args []string
		if json.Unmarshal([]byte(e.ArgsJSON), &args) == nil {
			m["args"] = args
		}
	}
	return m
}

func execDetail(h *Handler, e *store.Execution) (map[string]any, error) {
	d := execToMap(e)
	runs, err := h.st.ListRunsForExecution(e.ID)
	if err != nil {
		return nil, err
	}
	runList := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		runList = append(runList, map[string]any{
			"run_id":      run.ID,
			"agent_id":    run.AgentID,
			"state":       run.State,
			"exit_code":   run.ExitCode.Int32,
			"duration_ms": run.DurationMS.Int64,
		})
	}
	d["runs"] = runList
	return d, nil
}
