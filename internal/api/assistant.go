// Package api — assistant endpoints (R26, M9): endpoint config (admin),
// capabilities probe, sessions, and the SSE chat turn. Routes return 503
// until SetAssistant installs the service (same pattern as secrets/MCP).
package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blawesom/partout/internal/server/assistant"
	"github.com/blawesom/partout/internal/store"
)

// SetAssistant installs the LLM assistant service (R26, M9).
func (h *Handler) SetAssistant(svc *assistant.Service) { h.assistant = svc }

// assistantEnabled reports whether the assistant is configured and enabled
// (for the capability probe).
func (h *Handler) assistantEnabled() bool {
	cfg, err := h.assistant.Config()
	return err == nil && cfg.Enabled
}

// RegisterAssistant adds the assistant routes to mux.
func (h *Handler) RegisterAssistant(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/assistant/config", h.requireRole(roleViewer)(http.HandlerFunc(h.handleAssistantConfigGet)))
	mux.Handle("PUT /api/v1/assistant/config", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleAssistantConfigPut)))
	mux.Handle("POST /api/v1/assistant/config/reset-key", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleAssistantKeyReset)))
	mux.Handle("GET /api/v1/assistant/capabilities", h.requireRole(roleOperator)(http.HandlerFunc(h.handleAssistantProbe)))
	mux.Handle("GET /api/v1/assistant/sessions", h.requireRole(roleViewer)(http.HandlerFunc(h.handleAssistantSessionsList)))
	mux.Handle("POST /api/v1/assistant/sessions", h.requireRole(roleViewer)(http.HandlerFunc(h.handleAssistantSessionCreate)))
	mux.Handle("GET /api/v1/assistant/sessions/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleAssistantSessionGet)))
	mux.Handle("POST /api/v1/assistant/sessions/{id}/chat", h.requireRole(roleViewer)(http.HandlerFunc(h.handleAssistantChat)))
	mux.Handle("POST /api/v1/assistant/sessions/{id}/cancel", h.requireRole(roleViewer)(http.HandlerFunc(h.handleAssistantCancel)))
}

func (h *Handler) assistantUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "assistant_disabled",
		"assistant not configured (Settings > Assistant)", nil)
}

// handleAssistantConfigGet returns the endpoint config. Admins see
// everything; the key is never returned (write-only, Decision 18/19).
func (h *Handler) handleAssistantConfigGet(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	cfg, err := h.assistant.Config()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to read config", nil)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// handleAssistantConfigPut updates the endpoint config (admin).
func (h *Handler) handleAssistantConfigPut(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	var body struct {
		BaseURL        string `json:"base_url"`
		Model          string `json:"model"`
		APIKey         string `json:"api_key"` // write-only; empty keeps the stored key
		MaxToolCalls   int    `json:"max_tool_calls"`
		TimeoutS       int    `json:"timeout_s"`
		DefaultProfile string `json:"default_profile"`
		Enabled        bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	// Enablement hard gate (docs/assistant.md §4): refuse to enable against
	// an endpoint that does not answer or does not support tool calling —
	// no emulation fallback.
	if body.Enabled {
		if err := h.assistant.SaveConfig(&assistant.ConfigView{
			BaseURL: body.BaseURL, Model: body.Model, KeySet: body.APIKey != "",
			MaxToolCalls: body.MaxToolCalls, TimeoutS: body.TimeoutS,
			DefaultProfile: body.DefaultProfile, Enabled: false,
		}, body.APIKey); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
			return
		}
		if _, err := h.assistant.Probe(r.Context()); err != nil {
			// Roll back to disabled; report the probe failure verbatim.
			_ = h.assistant.SaveConfig(&assistant.ConfigView{
				BaseURL: body.BaseURL, Model: body.Model,
				MaxToolCalls: body.MaxToolCalls, TimeoutS: body.TimeoutS,
				DefaultProfile: body.DefaultProfile, Enabled: false,
			}, "")
			writeError(w, http.StatusBadRequest, "probe_failed",
				fmt.Sprintf("endpoint did not pass the capabilities probe (tool calling required): %v", err), nil)
			return
		}
	}
	user, _ := h.actorFor(r)
	if err := h.assistant.SaveConfig(&assistant.ConfigView{
		BaseURL: body.BaseURL, Model: body.Model, KeySet: body.APIKey != "",
		MaxToolCalls: body.MaxToolCalls, TimeoutS: body.TimeoutS,
		DefaultProfile: body.DefaultProfile, Enabled: body.Enabled,
	}, body.APIKey); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	h.audit("assistant.config", user, map[string]string{
		"base_url": body.BaseURL, "model": body.Model, "enabled": fmt.Sprint(body.Enabled),
	})
	cfg, _ := h.assistant.Config()
	writeJSON(w, http.StatusOK, cfg)
}

// handleAssistantKeyReset clears the stored endpoint key (admin).
func (h *Handler) handleAssistantKeyReset(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	if err := h.assistant.ResetKey(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to reset key", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("assistant.key_reset", actor, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAssistantProbe runs the capabilities probe against the configured
// endpoint (operator; used by the settings card).
func (h *Handler) handleAssistantProbe(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	res, err := h.assistant.Probe(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "probe_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleAssistantSessionCreate starts a session. The requested profile is
// capped by the caller's role (viewer → readonly regardless).
func (h *Handler) handleAssistantSessionCreate(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	var body struct {
		Profile string `json:"profile"`
	}
	_ = decodeJSON(r, &body) // empty body is fine (default profile)
	user, role := h.actorFor(r)
	ss, err := h.assistant.CreateSession(user, role, body.Profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create session", nil)
		return
	}
	h.audit("assistant.session", user, map[string]string{"session_id": ss.ID, "profile": ss.Profile})
	writeJSON(w, http.StatusOK, sessionToMap(ss))
}

// handleAssistantSessionsList lists the caller's sessions (admin sees all).
func (h *Handler) handleAssistantSessionsList(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	user, role := h.actorFor(r)
	target := r.URL.Query().Get("user")
	if target != "" && role == "admin" {
		user = target
	}
	sessions, err := h.st.ListAssistantSessions(user, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list sessions", nil)
		return
	}
	items := make([]map[string]any, 0, len(sessions))
	for _, ss := range sessions {
		items = append(items, sessionToMap(ss))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleAssistantSessionGet returns a session + transcript. The owner and
// admins may read (the approvals visibility split, Decision 18).
func (h *Handler) handleAssistantSessionGet(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	ss, err := h.st.GetAssistantSession(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such session", nil)
		return
	}
	user, role := h.actorFor(r)
	if ss.UserID != user && role != "admin" {
		writeError(w, http.StatusNotFound, "not_found", "no such session", nil)
		return
	}
	msgs, err := h.st.ListAssistantMessages(ss.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to read transcript", nil)
		return
	}
	items := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		it := map[string]any{
			"id": m.ID, "role": m.Role, "content": m.Content,
			"tool_name": m.ToolName, "tool_args": m.ToolArgs, "created": m.Created,
		}
		// Feedback parity: the transcript carries the parsed tool-result ids
		// so a reloaded session renders the same approval cards / execution
		// chips the live turn did.
		if m.Meta != "" {
			var meta map[string]any
			if json.Unmarshal([]byte(m.Meta), &meta) == nil {
				it["meta"] = meta
			}
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sessionToMap(ss), "messages": items})
}

// handleAssistantCancel aborts the in-flight turn of a session (owner).
func (h *Handler) handleAssistantCancel(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	ss, err := h.st.GetAssistantSession(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such session", nil)
		return
	}
	user, _ := h.actorFor(r)
	if ss.UserID != user {
		writeError(w, http.StatusNotFound, "not_found", "no such session", nil)
		return
	}
	h.assistant.Cancel(ss.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAssistantChat runs one user turn and streams the events as SSE
// (event-level: assistant_delta, tool_call, tool_result, approval_required,
// egress, done — docs/assistant.md §4). The request context IS the cancel
// path: disconnecting the fetch aborts the loop server-side.
func (h *Handler) handleAssistantChat(w http.ResponseWriter, r *http.Request) {
	if h.assistant == nil {
		h.assistantUnavailable(w)
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if body.Text == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "text is required", nil)
		return
	}
	ss, err := h.st.GetAssistantSession(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such session", nil)
		return
	}
	user, role := h.actorFor(r)
	if ss.UserID != user {
		writeError(w, http.StatusNotFound, "not_found", "no such session", nil)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal_error", "streaming unsupported", nil)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // reverse proxies: do not buffer SSE

	emit := func(ev assistant.Event) {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
		flusher.Flush()
	}
	if err := h.assistant.RunTurn(r.Context(), ss.ID, body.Text, bearerToken(r), user, role, emit); err != nil {
		// Errors after the stream started are delivered as events; errors
		// before it (config, ownership) keep the structured JSON shape.
		if r.Context().Err() == nil {
			ev := assistant.Event{Type: "error", Content: err.Error()}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func sessionToMap(ss *store.AssistantSession) map[string]any {
	return map[string]any{
		"id": ss.ID, "user_id": ss.UserID, "profile": ss.Profile,
		"created": ss.Created, "updated": ss.Updated,
	}
}
