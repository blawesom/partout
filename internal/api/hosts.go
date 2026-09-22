// Package api — hosts & groups endpoints (PRD §10.2, §10.3).
package api

import (
	"net/http"

	"github.com/blawesom/partout/internal/store"
)

// RegisterHosts adds hosts and groups endpoints to mux.
func (h *Handler) RegisterHosts(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/hosts", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListHosts)))
	mux.Handle("GET /api/v1/hosts/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetHost)))
	mux.Handle("GET /api/v1/hosts/{id}/facts", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetFacts)))
	mux.Handle("PUT /api/v1/hosts/{id}/facts", h.requireRole(roleOperator)(http.HandlerFunc(h.handlePutFacts)))

	mux.Handle("GET /api/v1/groups", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGroups)))
	mux.Handle("POST /api/v1/groups", h.requireRole(roleOperator)(http.HandlerFunc(h.handleGroups)))
}

// hostEntry is the host object returned by the REST API.
type hostEntry struct {
	ID        string            `json:"id"`
	UUID      string            `json:"uuid"`
	State     string            `json:"state"`
	Version   string            `json:"version"`
	FirstSeen int64             `json:"first_seen"`
	LastSeen  int64             `json:"last_seen"`
	Tags      map[string]string `json:"tags,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
}

func (h *Handler) hostEntry(id string) (hostEntry, error) {
	ag, err := h.st.Agent(id)
	if err != nil {
		return hostEntry{}, err
	}
	e := hostEntry{
		ID: ag.ID, UUID: ag.UUID, State: ag.State,
		Version: ag.Version, FirstSeen: ag.FirstSeen, LastSeen: ag.LastSeen,
	}
	e.Tags, _ = h.st.Tags(id)
	e.Roles, _ = h.st.Roles(id)
	return e, nil
}

func (h *Handler) handleListHosts(w http.ResponseWriter, r *http.Request) {
	limit, cursor := pageParams(r, 100)

	agents, err := h.st.HostsPage(limit, cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list hosts", nil)
		return
	}

	entries := make([]hostEntry, 0, len(agents))
	for _, ag := range agents {
		e, _ := h.hostEntry(ag.ID)
		entries = append(entries, e)
	}

	var next string
	if len(entries) == limit {
		next = entries[len(entries)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "next_cursor": next})
}

func (h *Handler) handleGetHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e, err := h.hostEntry(id)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get host", nil)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (h *Handler) handleGetFacts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, err := h.st.LatestFacts(id)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "no facts for host", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get facts", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id": id,
		"ts":      f.TS,
		"facts":   f.Data,
	})
}

func (h *Handler) handlePutFacts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var facts map[string]string
	if err := decodeJSON(r, &facts); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	if _, err := h.st.Agent(id); isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	if err := h.st.UpsertFacts(store.Facts{AgentID: id, TS: 0, Data: facts}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to update facts", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// ---- groups ----------------------------------------------------------------

// groupEntry is a named selector (arch §10.3).
type groupEntry struct {
	Name     string `json:"name"`
	Selector string `json:"selector"`
}

func (h *Handler) handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		m, err := h.st.Groups()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to list groups", nil)
			return
		}
		out := make([]groupEntry, 0, len(m))
		for name, sel := range m {
			out = append(out, groupEntry{Name: name, Selector: sel})
		}
		writeJSON(w, http.StatusOK, out)

	case "POST":
		var req struct {
			Name     string `json:"name"`
			Selector string `json:"selector"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
			return
		}
		if req.Name == "" || req.Selector == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "name and selector required", nil)
			return
		}
		if err := h.st.UpsertGroup(store.Group{Name: req.Name, Selector: req.Selector}); err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to create group", nil)
			return
		}
		writeJSON(w, http.StatusCreated, groupEntry{Name: req.Name, Selector: req.Selector})

	default:
		writeError(w, http.StatusMethodNotAllowed, "bad_request", "method not allowed", nil)
	}
}
