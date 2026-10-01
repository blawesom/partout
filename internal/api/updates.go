// Package api — update release store (M8.1, PRD §11).
//
// The server is store-and-forward, NOT the trust anchor: it checks artifact
// integrity (sha256 of the bytes equals the declared digest) and serves
// artifacts, but it does not validate the release signature. Every
// consumer — the agent at swap time, `partout ctl update verify` — verifies
// the Ed25519 signature against the operator-provisioned release public
// key before anything is executed.
package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/release"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/server/updates"
	"github.com/blawesom/partout/internal/store"
)

// maxReleaseArtifact caps one artifact at 100 MiB (the binary is ~19 MB;
// the cap is a DoS guard, not a target).
const maxReleaseArtifact = 100 << 20

// RegisterUpdates adds the M8.1 release-store endpoints.
func (h *Handler) RegisterUpdates(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/updates/releases", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListReleases)))
	mux.Handle("POST /api/v1/updates/releases", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleUploadRelease)))
	mux.Handle("GET /api/v1/updates/releases/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetRelease)))
	mux.Handle("GET /api/v1/updates/releases/{id}/artifact", h.requireRole(roleOperator)(http.HandlerFunc(h.handleReleaseArtifact)))
	mux.Handle("DELETE /api/v1/updates/releases/{id}", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleDeleteRelease)))
	// M8.1 step 2: canary apply + one-time artifact download grants.
	mux.Handle("POST /api/v1/updates/apply", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleApplyUpdate)))
	mux.Handle("GET /api/v1/updates/grants/{token}", http.HandlerFunc(h.handleGrantArtifact))
	// M8.1 step 3: rollout runs (canary -> waves, operator retry/skip/abort).
	mux.Handle("POST /api/v1/updates/runs", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleCreateUpdateRun)))
	mux.Handle("GET /api/v1/updates/runs", h.requireRole(roleViewer)(http.HandlerFunc(h.handleListUpdateRuns)))
	mux.Handle("GET /api/v1/updates/runs/{id}", h.requireRole(roleViewer)(http.HandlerFunc(h.handleGetUpdateRun)))
	mux.Handle("POST /api/v1/updates/runs/{id}/retry", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleUpdateRunAction)))
	mux.Handle("POST /api/v1/updates/runs/{id}/start", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleUpdateRunAction)))
	mux.Handle("POST /api/v1/updates/runs/{id}/skip", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleUpdateRunAction)))
	mux.Handle("POST /api/v1/updates/runs/{id}/abort", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleUpdateRunAction)))
}

// releaseEntry is the wire shape (never includes the artifact).
type releaseEntry struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Arch       string `json:"arch"`
	Kind       string `json:"kind"`
	SHA256     string `json:"sha256"`
	Signature  string `json:"signature"`
	Size       int64  `json:"size"`
	UploadedBy string `json:"uploaded_by,omitempty"`
	Created    int64  `json:"created"`
}

func releaseEntryFromMeta(m store.ReleaseMeta) releaseEntry {
	return releaseEntry{
		ID: m.ID, Version: m.Version, Arch: m.Arch, Kind: m.Kind,
		SHA256: m.SHA256, Signature: m.Signature, Size: m.Size,
		UploadedBy: m.UploadedBy, Created: m.Created,
	}
}

func releaseEntryFromRelease(rel store.Release) releaseEntry {
	return releaseEntry{
		ID: rel.ID, Version: rel.Version, Arch: rel.Arch, Kind: rel.Kind,
		SHA256: rel.SHA256, Signature: rel.Signature, Size: int64(len(rel.Artifact)),
		UploadedBy: rel.UploadedBy, Created: rel.Created,
	}
}

func (h *Handler) handleListReleases(w http.ResponseWriter, r *http.Request) {
	items, err := h.st.ListReleases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list releases", nil)
		return
	}
	out := make([]releaseEntry, 0, len(items))
	for _, m := range items {
		out = append(out, releaseEntryFromMeta(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "items": out})
}

type uploadReleaseBody struct {
	Version     string `json:"version"`
	Arch        string `json:"arch"`
	Kind        string `json:"kind"`
	SHA256      string `json:"sha256"`
	Signature   string `json:"signature"`
	ArtifactB64 string `json:"artifact_b64"`
}

func (h *Handler) handleUploadRelease(w http.ResponseWriter, r *http.Request) {
	var body uploadReleaseBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}

	m := release.Manifest{
		Version: strings.TrimSpace(body.Version),
		Arch:    strings.TrimSpace(body.Arch),
		Kind:    strings.TrimSpace(body.Kind),
		SHA256:  strings.ToLower(strings.TrimSpace(body.SHA256)),
	}
	art, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body.ArtifactB64))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "artifact_b64 is not valid base64", nil)
		return
	}
	if len(art) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "artifact is empty", nil)
		return
	}
	if len(art) > maxReleaseArtifact {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large",
			"artifact exceeds "+strconv.Itoa(maxReleaseArtifact>>20)+" MiB cap", nil)
		return
	}
	sum := sha256.Sum256(art)
	if m.SHA256 == "" {
		// Undeclared (UI upload): the server computes the digest from the
		// bytes it stored. The signature still binds it — consumers
		// recompute from the artifact they fetch.
		m.SHA256 = hex.EncodeToString(sum[:])
	} else if hex.EncodeToString(sum[:]) != m.SHA256 {
		writeError(w, http.StatusBadRequest, "bad_request",
			"artifact sha256 mismatch (got "+hex.EncodeToString(sum[:])+")", nil)
		return
	}
	if err := m.Valid(); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body.Signature))
	if err != nil || len(sig) != 64 {
		// GA: unsigned releases are the exception (PARTOUT_ALLOW_UNSIGNED_
		// RELEASES=true, default false). The sha256 integrity check still
		// binds the artifact; a signature adds provenance.
		if strings.TrimSpace(body.Signature) == "" && h.allowUnsigned {
			sig = nil
		} else {
			msg := "signature must be base64 of a 64-byte Ed25519 signature"
			if strings.TrimSpace(body.Signature) == "" {
				msg = "unsigned releases are disabled (set PARTOUT_ALLOW_UNSIGNED_RELEASES=true); a signature is required"
			}
			writeError(w, http.StatusBadRequest, "bad_request", msg, nil)
			return
		}
	}
	// Optional registration-time verification (PARTOUT_RELEASE_VERIFY_KEY):
	// when the server holds the release public key, the signature must
	// verify against it — a wrong-key or wrong-manifest signing mistake
	// fails here, not mid-rollout. The agent still verifies independently;
	// without this key the server stays store-and-forward.
	if h.releaseVerifyKey != nil {
		if sig == nil {
			writeError(w, http.StatusBadRequest, "bad_request",
				"signature required: the server is configured with a release verification key (PARTOUT_RELEASE_VERIFY_KEY)", nil)
			return
		}
		if !release.Verify(h.releaseVerifyKey, m, sig) {
			writeError(w, http.StatusBadRequest, "bad_request",
				"signature does not verify against the configured release key (wrong key or wrong manifest?)", nil)
			return
		}
	}
	// Version is stored EXACTLY as given: the release key signs the exact
	// "version|arch|kind|sha256" string, so a silently-normalized stored
	// version would no longer verify. Both version conventions coexist
	// (GitHub releases stamp "0.9.4"; the one-command update path
	// "v2.0.0-e2e"), so matching is done v-insensitively everywhere
	// (version.Equal) rather than by forcing a form here.
	if _, err := h.st.GetReleaseByVer(m.Version, m.Arch, m.Kind); err == nil {
		writeError(w, http.StatusConflict, "conflict",
			"release "+m.Version+" ("+m.Arch+", "+m.Kind+") already exists", nil)
		return
	}

	rid := id.New("rel")
	rel := store.Release{
		ID: rid, Version: m.Version, Arch: m.Arch, Kind: m.Kind,
		SHA256: m.SHA256, Signature: body.Signature, Artifact: art,
	}
	if actor, _ := h.actorFor(r); actor != "" {
		rel.UploadedBy = actor
	}
	if err := h.st.InsertRelease(rel); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store release", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("update.upload", actor, map[string]string{
		"id": rid, "version": m.Version, "arch": m.Arch, "kind": m.Kind, "sha256": m.SHA256,
	})

	// M8.1.1: a new agent release pre-arms a PARKED draft rollout (whole
	// fleet, one canary, default waves). Inert until an operator presses
	// start — the change always needs a human, but the fleet can never be
	// silently forgotten behind a new release.
	resp := map[string]string{"id": rid, "status": "uploaded"}
	if rel.Kind == "agent" && h.autoDraftRollouts && h.updatesMgr != nil {
		if run := h.updatesMgr.MaybeDraft(rel, actor); run != nil {
			resp["draft_run"] = run.ID
			h.audit("update.run.drafted_auto", actor, map[string]string{"run": run.ID, "version": m.Version, "release": rid})
		}
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handler) handleGetRelease(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rel, err := h.st.GetRelease(id)
	if errors.Is(err, store.ErrNoRelease) {
		writeError(w, http.StatusNotFound, "not_found", "release not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get release", nil)
		return
	}
	writeJSON(w, http.StatusOK, releaseEntryFromRelease(rel))
}

func (h *Handler) handleReleaseArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rel, err := h.st.GetRelease(id)
	if errors.Is(err, store.ErrNoRelease) {
		writeError(w, http.StatusNotFound, "not_found", "release not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get release", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("update.artifact.download", actor, map[string]string{
		"id": rel.ID, "version": rel.Version, "kind": rel.Kind,
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(rel.Artifact)))
	w.Header().Set("X-Partout-Sha256", rel.SHA256)
	w.Header().Set("X-Partout-Version", rel.Version)
	w.Header().Set("X-Partout-Signature", rel.Signature)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rel.Artifact)
}

func (h *Handler) handleDeleteRelease(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ok, err := h.st.DeleteRelease(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to delete release", nil)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "release not found", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("update.release.deleted", actor, map[string]string{"id": id})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---- M8.1 step 2: canary apply + artifact download grants ------------------

type applyUpdateBody struct {
	AgentID   string `json:"agent_id"`
	ReleaseID string `json:"release_id"`
}

// handleApplyUpdate dispatches a signed update directive to one connected
// agent (the canary path). The agent verifies the release signature against
// its own provisioned key before downloading or executing anything.
func (h *Handler) handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	var body applyUpdateBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	body.AgentID = strings.TrimSpace(body.AgentID)
	body.ReleaseID = strings.TrimSpace(body.ReleaseID)
	if body.AgentID == "" || body.ReleaseID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id and release_id are required", nil)
		return
	}
	rel, err := h.st.GetRelease(body.ReleaseID)
	if errors.Is(err, store.ErrNoRelease) {
		writeError(w, http.StatusNotFound, "not_found", "release not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get release", nil)
		return
	}
	if rel.Kind != string(release.KindAgent) {
		writeError(w, http.StatusBadRequest, "bad_request",
			"only agent-kind releases can be applied to a host (got kind="+rel.Kind+")", nil)
		return
	}
	if _, err := h.st.Agent(body.AgentID); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get host", nil)
		return
	}
	grant, err := h.streamH.IssueUpdateGrant(body.AgentID, rel.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to mint update grant", nil)
		return
	}
	dir := &proto.UpdateDirective{
		ReleaseId: rel.ID, Version: rel.Version, Arch: rel.Arch, Kind: rel.Kind,
		Sha256: rel.SHA256, Signature: rel.Signature, Grant: grant,
		Unsigned: rel.Signature == "",
	}
	if err := h.streamH.SendUpdateDirective(body.AgentID, dir); err != nil {
		if errors.Is(err, stream.ErrAgentOffline) {
			writeError(w, http.StatusConflict, "agent_offline",
				"host is not connected (queued rollout delivery lands in M8.1 step 3)", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to dispatch update", nil)
		return
	}
	actor, _ := h.actorFor(r)
	h.audit("update.apply", actor, map[string]string{
		"agent_id": body.AgentID, "release_id": rel.ID, "version": rel.Version,
		"unsigned": fmt.Sprintf("%t", rel.Signature == ""),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "dispatched", "agent_id": body.AgentID, "release_id": rel.ID})
}

// handleGrantArtifact streams a release artifact to the holder of a valid
// one-time grant. The grant is the credential (no RBAC role); it is
// single-use, TTL-bound, and minted only for a specific agent+release. This
// keeps the ~19 MB binary off the control stream.
func (h *Handler) handleGrantArtifact(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	agentID, releaseID, ok := h.streamH.RedeemUpdateGrant(tok)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "grant unknown, expired, or already used", nil)
		return
	}
	rel, err := h.st.GetRelease(releaseID)
	if errors.Is(err, store.ErrNoRelease) {
		writeError(w, http.StatusNotFound, "not_found", "release not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to get release", nil)
		return
	}
	_ = agentID // bound at mint; the stream already delivered the directive to this agent
	h.audit("update.artifact.grant", agentID, map[string]string{
		"release_id": rel.ID, "version": rel.Version, "kind": rel.Kind,
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(rel.Artifact)))
	w.Header().Set("X-Partout-Sha256", rel.SHA256)
	w.Header().Set("X-Partout-Version", rel.Version)
	w.Header().Set("X-Partout-Signature", rel.Signature)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rel.Artifact)
}

// ---- M8.1 step 3: rollout runs --------------------------------------------

// runEntry is the wire shape of a run (no artifact).
type runEntry struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	ReleaseID    string `json:"release_id"`
	Arch         string `json:"arch"`
	Selector     string `json:"selector"`
	CanaryHosts  string `json:"canary_hosts,omitempty"`
	CanaryCount  int    `json:"canary_count"`
	WavePct      int    `json:"wave_pct"`
	Status       string `json:"status"`
	CurrentWave  int    `json:"current_wave"`
	TotalHosts   int    `json:"total_hosts"`
	DoneHosts    int    `json:"done_hosts"`
	FailedHosts  int    `json:"failed_hosts"`
	SkippedHosts int    `json:"skipped_hosts"`
	Error        string `json:"error,omitempty"`
	ApprovalID   string `json:"approval_id,omitempty"`
	CreatedBy    string `json:"created_by"`
	Created      int64  `json:"created"`
}

func runEntryFrom(r *store.UpdateRun) runEntry {
	return runEntry{
		ID: r.ID, Version: r.Version, ReleaseID: r.ReleaseID, Arch: r.Arch,
		Selector: r.Selector, CanaryHosts: r.CanaryHosts, CanaryCount: r.CanaryCount,
		WavePct: r.WavePct, Status: r.Status, CurrentWave: r.CurrentWave,
		TotalHosts: r.TotalHosts, DoneHosts: r.DoneHosts, FailedHosts: r.FailedHosts,
		SkippedHosts: r.SkippedHosts, Error: r.Error, ApprovalID: r.ApprovalID,
		CreatedBy: r.CreatedBy, Created: r.CreatedAt,
	}
}

type runHostEntry struct {
	ID      string `json:"id"`
	HostID  string `json:"host_id"`
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	Updated int64  `json:"updated"`
}

func runHostEntryFrom(hh *store.UpdateHost) runHostEntry {
	return runHostEntry{ID: hh.ID, HostID: hh.HostID, Status: hh.Status, Version: hh.Version, Error: hh.Error, Updated: hh.UpdatedAt}
}

type createRunBody struct {
	ReleaseID   string   `json:"release_id"`
	Version     string   `json:"version"`
	Selector    string   `json:"selector"`
	Canary      int      `json:"canary"`
	WavePct     int      `json:"wave_pct"`
	CanaryHosts []string `json:"canary_hosts"`
}

func (h *Handler) handleCreateUpdateRun(w http.ResponseWriter, r *http.Request) {
	if h.updatesMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "update rollout not configured", nil)
		return
	}
	var b createRunBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid body: "+err.Error(), nil)
		return
	}
	actor, actorRole := h.actorFor(r)
	p := updates.Params{
		ReleaseID: b.ReleaseID, Version: b.Version, Selector: b.Selector,
		Canary: b.Canary, WavePct: b.WavePct, CanaryHosts: b.CanaryHosts,
		Actor: actor, ActorRole: actorRole,
	}
	run, req, err := h.updatesMgr.StartRun(p)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNoRelease):
			writeError(w, http.StatusNotFound, "no_release", err.Error(), nil)
		default:
			writeError(w, http.StatusBadRequest, "run_rejected", err.Error(), nil)
		}
		return
	}
	if req != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"run_id": run.ID, "state": "pending_approval", "approval_id": req.ID,
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"run_id": run.ID, "state": run.Status})
}

func (h *Handler) handleListUpdateRuns(w http.ResponseWriter, r *http.Request) {
	if h.updatesMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "update rollout not configured", nil)
		return
	}
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	runs, err := h.st.ListUpdateRuns(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error(), nil)
		return
	}
	items := make([]runEntry, 0, len(runs))
	for _, rr := range runs {
		items = append(items, runEntryFrom(rr))
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(items), "items": items})
}

func (h *Handler) handleGetUpdateRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := h.st.GetUpdateRun(id)
	if err != nil || run == nil {
		writeError(w, http.StatusNotFound, "no_run", "no such run: "+id, nil)
		return
	}
	hosts, err := h.st.ListUpdateHosts(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error(), nil)
		return
	}
	items := make([]runHostEntry, 0, len(hosts))
	for _, hh := range hosts {
		items = append(items, runHostEntryFrom(hh))
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": runEntryFrom(run), "hosts": items})
}

func (h *Handler) handleUpdateRunAction(w http.ResponseWriter, r *http.Request) {
	if h.updatesMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "update rollout not configured", nil)
		return
	}
	id := r.PathValue("id")
	actor, _ := h.actorFor(r)
	action := ""
	if strings.HasSuffix(r.URL.Path, "/retry") {
		action = "retry"
	} else if strings.HasSuffix(r.URL.Path, "/start") {
		action = "start"
	} else if strings.HasSuffix(r.URL.Path, "/skip") {
		action = "skip"
	} else if strings.HasSuffix(r.URL.Path, "/abort") {
		action = "abort"
	}
	var err error
	switch action {
	case "retry":
		err = h.updatesMgr.Retry(id, actor)
	case "start":
		err = h.updatesMgr.Start(id, actor)
	case "skip":
		err = h.updatesMgr.Skip(id, actor)
	case "abort":
		err = h.updatesMgr.Abort(id, actor)
	}
	if err != nil {
		writeError(w, http.StatusConflict, "run_action_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run_id": id, "action": action})
}
