// Package api — hosts & groups endpoints (PRD §10.2, §10.3).
package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/blawesom/partout/internal/store"
)

// RegisterHosts adds hosts and groups endpoints to mux.
func (h *Handler) RegisterHosts(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/hosts", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListHosts)))
	mux.Handle("GET /api/v1/hosts/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetHost)))
	mux.Handle("DELETE /api/v1/hosts/{id}", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleDeleteHost)))
	mux.Handle("GET /api/v1/hosts/{id}/facts", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetFacts)))
	mux.Handle("PUT /api/v1/hosts/{id}/facts", h.requireRole(roleOperator)(http.HandlerFunc(h.handlePutFacts)))
	mux.Handle("PUT /api/v1/hosts/{id}/tags/{key}", h.requireRole(roleOperator)(http.HandlerFunc(h.handlePutHostTag)))
	mux.Handle("DELETE /api/v1/hosts/{id}/tags/{key}", h.requireRole(roleOperator)(http.HandlerFunc(h.handleDeleteHostTag)))
	mux.Handle("PUT /api/v1/hosts/{id}/roles/{role}", h.requireRole(roleOperator)(http.HandlerFunc(h.handleAddHostRole)))
	mux.Handle("DELETE /api/v1/hosts/{id}/roles/{role}", h.requireRole(roleOperator)(http.HandlerFunc(h.handleDeleteHostRole)))

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
	Hostname  string            `json:"hostname,omitempty"`
	OS        string            `json:"os,omitempty"`
	Name      string            `json:"name,omitempty"`
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
	// The partout-generated agent id (ag_…) is unique but not human-meaningful.
	// Prefer an operator-assigned name tag, then the reported hostname, then the
	// host's primary role, then a service tag, and only fall back to the id.
	if f, err := h.st.LatestFacts(id); err == nil {
		e.Hostname = f.Data["host.hostname"]
		e.OS = hostOS(f.Data)
	}
	e.Name = e.displayName()
	return e, nil
}

// hostOS composes a short OS label (e.g. "Ubuntu 22.04") from the
// os-release facts the agent reports; "" when the distro is unknown.
func hostOS(facts map[string]string) string {
	name, ver := facts["host.distro_name"], facts["host.distro_version"]
	switch {
	case name != "" && ver != "":
		return name + " " + ver
	case name != "":
		return name
	default:
		return facts["host.distro"]
	}
}

// displayName returns a human-friendly host label, falling back to the id.
func (e hostEntry) displayName() string {
	if n := e.Tags["name"]; n != "" {
		return n
	}
	if e.Hostname != "" {
		return e.Hostname
	}
	if len(e.Roles) > 0 {
		return e.Roles[0]
	}
	if n := e.Tags["service"]; n != "" {
		return n
	}
	return e.ID
}

func (h *Handler) handleListHosts(w http.ResponseWriter, r *http.Request) {
	// B2 (ui-guidelines S1): ?selector=<expr> returns the resolved host set
	// for a preview before dispatch. Resolution is server-authoritative; the
	// UI renders exactly what this returns. An unparseable selector is a 400
	// and an empty set is an explicit {count:0}, never a silent no-op.
	if sel := r.URL.Query().Get("selector"); sel != "" {
		hosts, err := store.NewResolver(h.st).ResolveSelector(sel)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid selector: "+err.Error(), nil)
			return
		}
		items := make([]map[string]any, 0, len(hosts))
		for _, hst := range hosts {
			items = append(items, map[string]any{
				"id":    hst.ID,
				"tags":  hst.Tags,
				"roles": hst.Roles,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": len(items), "items": items})
		return
	}

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

// handleDeleteHost removes an agent and all cascaded rows (PRD R7 / B3).
// A deleted agent can never re-authenticate — the stream handshake looks the
// UUID up in the store — so removal doubles as revocation.
func (h *Handler) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !h.hostExists(w, id) {
		return
	}
	if err := h.st.DeleteAgent(id); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to delete host", nil)
		return
	}
	// Tell a live agent it was removed so it stops itself (its client-side
	// close ends the stream). Harmless when the agent is already offline.
	if h.streamH != nil {
		h.streamH.RevokeAgent(id, "host deleted")
	}
	actor, _ := h.actorFor(r)
	h.audit("host.deleted", actor, map[string]string{"agent_id": id})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---- tags & roles -----------------------------------------------------------

// validateLabelName checks a tag key or role name for selector safety: both
// appear in selector expressions (tag:<key>[=value], role:<name>), so the
// characters that would break parsing are rejected.
func validateLabelName(kind, s string) error {
	if s == "" {
		return fmt.Errorf("%s required", kind)
	}
	if len(s) > 64 {
		return fmt.Errorf("%s too long (max 64)", kind)
	}
	if strings.ContainsAny(s, ",= ") {
		return fmt.Errorf("%s may not contain ',', '=' or spaces", kind)
	}
	return nil
}

// hostExists reports whether the agent row is present (404 shape).
func (h *Handler) hostExists(w http.ResponseWriter, id string) bool {
	if _, err := h.st.Agent(id); isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return false
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get host", nil)
		return false
	}
	return true
}

// writeHostEntry re-reads and returns the host after a mutation.
func (h *Handler) writeHostEntry(w http.ResponseWriter, id string) {
	e, err := h.hostEntry(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get host", nil)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// handlePutHostTag sets (or replaces) a host tag. A missing or empty value
// makes the tag key-only.
func (h *Handler) handlePutHostTag(w http.ResponseWriter, r *http.Request) {
	id, key := r.PathValue("id"), r.PathValue("key")
	if err := validateLabelName("tag key", key); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if !h.hostExists(w, id) {
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	_ = decodeJSON(r, &body) // optional body: no body = key-only tag
	if len(body.Value) > 256 {
		writeError(w, http.StatusBadRequest, "bad_request", "tag value too long (max 256)", nil)
		return
	}
	if err := h.st.SetTag(id, key, body.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to set tag", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("host.tag.set", actor, map[string]string{"agent_id": id, "key": key, "value": body.Value})
	h.writeHostEntry(w, id)
}

// handleDeleteHostTag removes a host tag.
func (h *Handler) handleDeleteHostTag(w http.ResponseWriter, r *http.Request) {
	id, key := r.PathValue("id"), r.PathValue("key")
	if err := validateLabelName("tag key", key); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if !h.hostExists(w, id) {
		return
	}
	if err := h.st.DeleteTag(id, key); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to delete tag", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("host.tag.delete", actor, map[string]string{"agent_id": id, "key": key})
	h.writeHostEntry(w, id)
}

// handleAddHostRole adds a role to a host.
func (h *Handler) handleAddHostRole(w http.ResponseWriter, r *http.Request) {
	id, role := r.PathValue("id"), r.PathValue("role")
	if err := validateLabelName("role", role); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if !h.hostExists(w, id) {
		return
	}
	if err := h.st.SetRole(id, role); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to add role", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("host.role.add", actor, map[string]string{"agent_id": id, "role": role})
	h.writeHostEntry(w, id)
}

// handleDeleteHostRole removes a role from a host.
func (h *Handler) handleDeleteHostRole(w http.ResponseWriter, r *http.Request) {
	id, role := r.PathValue("id"), r.PathValue("role")
	if err := validateLabelName("role", role); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if !h.hostExists(w, id) {
		return
	}
	if err := h.st.DeleteRole(id, role); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to remove role", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("host.role.delete", actor, map[string]string{"agent_id": id, "role": role})
	h.writeHostEntry(w, id)
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
