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
	"net/http"
	"strconv"
	"strings"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/release"
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
		writeError(w, http.StatusBadRequest, "bad_request",
			"signature must be base64 of a 64-byte Ed25519 signature", nil)
		return
	}
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
	writeJSON(w, http.StatusCreated, map[string]string{"id": rid, "status": "uploaded"})
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
