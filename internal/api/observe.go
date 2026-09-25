// Package api — observe-layer read endpoints (M5, R18–R20; PRD §10.3).
//
// Read-only views over the structured observe facts merged into each
// host's host_facts JSON document. Cross-host aggregation with
// label/agent filters; the UI (M7) and MCP tools read these.
package api

import (
	"net/http"
	"strconv"

	"github.com/blawesom/partout/internal/server/observe"
)

// RegisterObserve adds the observe-layer read endpoints to mux.
func (h *Handler) RegisterObserve(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/services", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListServices)))
	mux.Handle("GET /api/v1/certificates", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListCertificates)))
	mux.Handle("GET /api/v1/configs", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListConfigs)))
}

// hostDocs pairs an agent id with its parsed host_facts document.
type hostDoc struct {
	agentID string
	doc     *observe.Document
}

// observeDocs loads the latest host_facts document for every host that has
// the requested structured domain present.
func (h *Handler) observeDocs(domainKey string) ([]hostDoc, error) {
	agents, err := h.st.Agents()
	if err != nil {
		return nil, err
	}
	out := make([]hostDoc, 0, len(agents))
	for _, ag := range agents {
		blob, err := h.st.LatestHostFactsJSON(ag.ID)
		if err != nil || blob == "" {
			continue
		}
		doc, err := observe.ParseDocument(blob)
		if err != nil {
			continue // malformed document: skipped (logged by the store layer on M6)
		}
		if _, ok := doc.Structured[domainKey]; !ok {
			continue
		}
		out = append(out, hostDoc{agentID: ag.ID, doc: doc})
	}
	return out, nil
}

// ---- services (R18) ---------------------------------------------------------

// handleListServices: GET /api/v1/services[?label=][&state=][&name=][&agent_id=]
func (h *Handler) handleListServices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	label := q.Get("label")
	state := q.Get("state")
	name := q.Get("name")
	agentID := q.Get("agent_id")

	docs, err := h.observeDocs(observe.KeyServices)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list services", nil)
		return
	}

	type unitEntry struct {
		HostID string           `json:"host_id"`
		Unit   observe.UnitFact `json:"unit"`
	}
	items := make([]unitEntry, 0)
	for _, hd := range docs {
		if agentID != "" && hd.agentID != agentID {
			continue
		}
		sf := hd.doc.Services()
		if sf == nil {
			continue
		}
		for _, u := range sf.Units {
			if label != "" && !hasLabel(u.Labels, label) {
				continue
			}
			if state != "" && u.State != state {
				continue
			}
			if name != "" && u.Name != name {
				continue
			}
			items = append(items, unitEntry{HostID: hd.agentID, Unit: u})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// ---- certificates (R20) -----------------------------------------------------

// handleListCertificates: GET /api/v1/certificates[?agent_id=][&days_remaining_lt=]
func (h *Handler) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	agentID := q.Get("agent_id")
	var maxDays int64
	if v := q.Get("days_remaining_lt"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "days_remaining_lt must be an integer", nil)
			return
		}
		maxDays = n
	}

	docs, err := h.observeDocs(observe.KeyCerts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list certificates", nil)
		return
	}

	type certEntry struct {
		HostID string           `json:"host_id"`
		Cert   observe.CertFact `json:"cert"`
	}
	items := make([]certEntry, 0)
	for _, hd := range docs {
		if agentID != "" && hd.agentID != agentID {
			continue
		}
		cf := hd.doc.Certificates()
		if cf == nil {
			continue
		}
		for _, c := range cf.Items {
			if maxDays > 0 && c.DaysRemaining > maxDays {
				continue
			}
			items = append(items, certEntry{HostID: hd.agentID, Cert: c})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// ---- configs (R19) ----------------------------------------------------------

// handleListConfigs: GET /api/v1/configs[?agent_id=][&kind=haproxy|nginx]
func (h *Handler) handleListConfigs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	agentID := q.Get("agent_id")
	kind := q.Get("kind")

	docs, err := h.observeDocs(observe.KeyConfigs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list configs", nil)
		return
	}

	type configEntry struct {
		HostID string                 `json:"host_id"`
		Kind   string                 `json:"kind"`
		Config *observe.HAProxyConfig `json:"haproxy,omitempty"`
		Nginx  *observe.NginxConfig   `json:"nginx,omitempty"`
	}
	items := make([]configEntry, 0)
	for _, hd := range docs {
		if agentID != "" && hd.agentID != agentID {
			continue
		}
		cf := hd.doc.Configs()
		if cf == nil {
			continue
		}
		if kind == "haproxy" {
			if cf.HAProxy == nil || !cf.HAProxy.Present {
				continue
			}
			items = append(items, configEntry{HostID: hd.agentID, Kind: "haproxy", Config: cf.HAProxy})
		} else if kind == "nginx" {
			if cf.Nginx == nil || !cf.Nginx.Present {
				continue
			}
			items = append(items, configEntry{HostID: hd.agentID, Kind: "nginx", Nginx: cf.Nginx})
		} else {
			e := configEntry{HostID: hd.agentID}
			switch {
			case cf.HAProxy != nil && cf.HAProxy.Present:
				e.Kind = "haproxy"
				e.Config = cf.HAProxy
			case cf.Nginx != nil && cf.Nginx.Present:
				e.Kind = "nginx"
				e.Nginx = cf.Nginx
			default:
				continue
			}
			items = append(items, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
