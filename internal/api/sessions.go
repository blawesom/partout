// REST handlers for PTY sessions (M2, PRD §5.2.2).
//
// Routes (auth: open/input/resize/close = operator+, list/get/replay = viewer+):
//
//	POST /api/v1/sessions                 {agent_id, cmd, args, cols, rows, record}
//	POST /api/v1/sessions/{id}/input     {data_b64}
//	POST /api/v1/sessions/{id}/resize    {cols, rows}
//	POST /api/v1/sessions/{id}/close
//	GET  /api/v1/sessions?agent_id=
//	GET  /api/v1/sessions/{id}
//	GET  /api/v1/sessions/{id}/replay
//
// Live output is delivered via the SSE stream (session.data / session.result
// events); the REST surface is control-plane only.
package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/blawesom/partout/internal/server/sessions"
	"github.com/blawesom/partout/internal/store"
)

// RegisterSessions wires the session REST routes. Routes return 503 until
// SetSessions installs the manager.
func (h *Handler) RegisterSessions(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/sessions", h.requireRole(roleOperator)(http.HandlerFunc(h.sessionOpen)))
	mux.Handle("POST /api/v1/sessions/{id}/input", h.requireRole(roleOperator)(http.HandlerFunc(h.sessionInput)))
	mux.Handle("POST /api/v1/sessions/{id}/resize", h.requireRole(roleOperator)(http.HandlerFunc(h.sessionResize)))
	mux.Handle("POST /api/v1/sessions/{id}/close", h.requireRole(roleOperator)(http.HandlerFunc(h.sessionClose)))
	mux.Handle("GET /api/v1/sessions", h.requireRole(roleViewer)(http.HandlerFunc(h.sessionList)))
	mux.Handle("GET /api/v1/sessions/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.sessionGet)))
	mux.Handle("GET /api/v1/sessions/{id}/replay", h.requireRole(roleViewer)(http.HandlerFunc(h.sessionReplay)))
}

type sessionOpenBody struct {
	AgentID string   `json:"agent_id"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args,omitempty"`
	Cols    int32    `json:"cols,omitempty"`
	Rows    int32    `json:"rows,omitempty"`
	Record  bool     `json:"record"`
}

func (h *Handler) sessionOpen(w http.ResponseWriter, r *http.Request) {
	if h.sess == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions_disabled", "sessions subsystem not initialized", nil)
		return
	}
	var body sessionOpenBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid json: "+err.Error(), nil)
		return
	}
	if body.AgentID == "" || body.Cmd == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id and cmd required", nil)
		return
	}
	principal, role := h.actorFor(r)
	req := sessions.OpenRequest{
		AgentID: body.AgentID, Cmd: body.Cmd, Args: body.Args,
		Cols: body.Cols, Rows: body.Rows, Record: body.Record,
		Actor: principal, Role: role,
	}
	sess, err := h.sess.Open(r.Context(), req)
	if err != nil {
		h.sessionErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionJSON(sess))
}

func (h *Handler) sessionInput(w http.ResponseWriter, r *http.Request) {
	if h.sess == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions_disabled", "sessions subsystem not initialized", nil)
		return
	}
	var body struct {
		DataB64 string `json:"data_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid json: "+err.Error(), nil)
		return
	}
	data, err := base64.StdEncoding.DecodeString(body.DataB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "data_b64: "+err.Error(), nil)
		return
	}
	if err := h.sess.Input(r.PathValue("id"), data); err != nil {
		h.sessionErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) sessionResize(w http.ResponseWriter, r *http.Request) {
	if h.sess == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions_disabled", "sessions subsystem not initialized", nil)
		return
	}
	var body struct {
		Cols int32 `json:"cols"`
		Rows int32 `json:"rows"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid json: "+err.Error(), nil)
		return
	}
	if err := h.sess.Resize(r.PathValue("id"), body.Cols, body.Rows); err != nil {
		h.sessionErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) sessionClose(w http.ResponseWriter, r *http.Request) {
	if h.sess == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions_disabled", "sessions subsystem not initialized", nil)
		return
	}
	if err := h.sess.Close(r.PathValue("id")); err != nil {
		h.sessionErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) sessionList(w http.ResponseWriter, r *http.Request) {
	if h.sess == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions_disabled", "sessions subsystem not initialized", nil)
		return
	}
	list, err := h.sess.List(r.URL.Query().Get("agent_id"), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		out = append(out, sessionJSON(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (h *Handler) sessionGet(w http.ResponseWriter, r *http.Request) {
	if h.sess == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions_disabled", "sessions subsystem not initialized", nil)
		return
	}
	sess, err := h.sess.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "session not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, sessionJSON(sess))
}

func (h *Handler) sessionReplay(w http.ResponseWriter, r *http.Request) {
	if h.sess == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions_disabled", "sessions subsystem not initialized", nil)
		return
	}
	recs, err := h.sess.Replay(r.PathValue("id"))
	if err != nil {
		h.sessionErr(w, err)
		return
	}
	frames := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		frames = append(frames, map[string]any{
			"seq":      rec.Seq,
			"data_b64": base64.StdEncoding.EncodeToString(rec.Data),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"frames": frames})
}

// isPolicyDeny reports whether err is a policy denial (→ HTTP 403).
func isPolicyDeny(err error) bool {
	return err != nil && strings.Contains(err.Error(), "denied by policy")
}

// sessionErr maps session errors to HTTP codes.
func (h *Handler) sessionErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case isPolicyDeny(err):
		writeError(w, http.StatusForbidden, "denied", msg, nil)
	case strings.Contains(msg, "not found") || strings.Contains(msg, "not open") || strings.Contains(msg, "not recorded"):
		writeError(w, http.StatusNotFound, "not_found", msg, nil)
	case strings.Contains(msg, "no active session") || strings.Contains(msg, "stream closed") || strings.Contains(msg, "dispatch"):
		writeError(w, http.StatusBadGateway, "agent_unavailable", msg, nil)
	default:
		writeError(w, http.StatusInternalServerError, "internal", msg, nil)
	}
}

// sessionJSON serializes a store session row for the API.
func sessionJSON(s *store.Session) map[string]any {
	out := map[string]any{
		"session_id": s.ID, "agent_id": s.AgentID, "cmd": s.Cmd,
		"cols": s.Cols, "rows": s.Rows, "record": s.Record,
		"state": s.State, "actor": s.Actor, "opened_unix": s.Opened,
	}
	if s.ArgsJSON != "" {
		var args []string
		if err := json.Unmarshal([]byte(s.ArgsJSON), &args); err == nil {
			out["args"] = args
		}
	}
	if s.ExitCode.Valid {
		out["exit_code"] = s.ExitCode.Int32
	}
	if s.Error != "" {
		out["error"] = s.Error
	}
	if s.Closed.Valid {
		out["closed_unix"] = s.Closed.Int64
	}
	return out
}
