package api

// M5.1: security scan REST surface. Findings are server-derived (agent
// update list + OSV correlation); there is no write path for them.

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// RegisterSecurity wires the security REST routes.
func (h *Handler) RegisterSecurity(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/security", h.requireRole(roleViewer)(http.HandlerFunc(h.securityList)))
	mux.Handle("POST /api/v1/security/scan", h.requireRole(roleAdmin)(http.HandlerFunc(h.securityScan)))
}

// securityList returns per-host scan meta + findings for every host that
// has ever been scanned.
func (h *Handler) securityList(w http.ResponseWriter, r *http.Request) {
	if h.pkgs == nil {
		writeError(w, http.StatusServiceUnavailable, "packages_disabled", "packages subsystem not initialized", nil)
		return
	}
	metas, err := h.st.AllSecurityScanMeta()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}
	type findingOut struct {
		Pkg       string  `json:"pkg"`
		Installed string  `json:"installed"`
		Available string  `json:"available"`
		VulnCount int     `json:"vuln_count"`
		MaxCVSS   float64 `json:"max_cvss"`
		VulnIDs   string  `json:"vuln_ids"`
		UpdatedAt int64   `json:"updated_at"`
	}
	type hostOut struct {
		AgentID         string       `json:"agent_id"`
		ScannedAt       int64        `json:"scanned_at"`
		UpdatesTotal    int          `json:"updates_total"`
		SecurityUpdates int          `json:"security_updates"`
		Findings        []findingOut `json:"findings"`
	}
	items := make([]hostOut, 0, len(metas))
	for _, m := range metas {
		ho := hostOut{
			AgentID: m.AgentID, ScannedAt: m.ScannedAt,
			UpdatesTotal: m.UpdatesTotal, SecurityUpdates: m.SecurityUpdates,
			Findings: []findingOut{},
		}
		if fs, err := h.st.SecurityFindingsFor(m.AgentID); err == nil {
			for _, f := range fs {
				ho.Findings = append(ho.Findings, findingOut{
					Pkg: f.Pkg, Installed: f.Installed, Available: f.Available,
					VulnCount: f.VulnCount, MaxCVSS: f.MaxCVSS,
					VulnIDs: f.VulnIDs, UpdatedAt: f.UpdatedAt,
				})
			}
		}
		items = append(items, ho)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// securityScan triggers one scan pass now (admin). The periodic loop
// (PARTOUT_SECURITY_SCAN_S) runs independently; this is the "scan now"
// button and the debug/ops escape hatch.
func (h *Handler) securityScan(w http.ResponseWriter, r *http.Request) {
	if h.pkgs == nil {
		writeError(w, http.StatusServiceUnavailable, "packages_disabled", "packages subsystem not initialized", nil)
		return
	}
	actor, _ := h.actorFor(r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if agentID := r.URL.Query().Get("agent_id"); agentID != "" {
		if err := h.pkgs.SecurityScanAgent(ctx, agentID); err != nil {
			writeError(w, http.StatusInternalServerError, "scan_failed", err.Error(), nil)
			return
		}
		h.audit("security.scan", actor, map[string]string{"agent_id": agentID})
		writeJSON(w, http.StatusOK, map[string]any{"scanned": 1, "ok": true})
		return
	}
	n, err := h.pkgs.SecurityScan(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scan_failed", err.Error(), nil)
		return
	}
	h.audit("security.scan", actor, map[string]string{"scanned": strconv.Itoa(n)})
	writeJSON(w, http.StatusOK, map[string]any{"scanned": n, "ok": true})
}
