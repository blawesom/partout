// REST handlers for file operations (M2, PRD §5.3).
//
// Routes (auth: reads = viewer+, writes = operator+):
//
//	GET  /api/v1/files/stat?agent_id=&path=
//	GET  /api/v1/files/list?agent_id=&path=
//	GET  /api/v1/files/download?agent_id=&path=
//	POST /api/v1/files/upload    {agent_id, path, content_b64, mode}
//	POST /api/v1/files/edit      {agent_id, path, expected_sha256, content_b64}
//	POST /api/v1/files/perm      {agent_id, path, mode, owner, group}
package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/files"
)

// RegisterFiles wires the file REST routes. Routes return 503 until
// SetFiles installs the controller.
func (h *Handler) RegisterFiles(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/files/stat", h.requireRole(roleViewer)(http.HandlerFunc(h.fileStat)))
	mux.Handle("GET /api/v1/files/list", h.requireRole(roleViewer)(http.HandlerFunc(h.fileList)))
	mux.Handle("GET /api/v1/files/download", h.requireRole(roleViewer)(http.HandlerFunc(h.fileDownload)))
	mux.Handle("POST /api/v1/files/upload", h.requireRole(roleOperator)(http.HandlerFunc(h.fileUpload)))
	mux.Handle("POST /api/v1/files/edit", h.requireRole(roleOperator)(http.HandlerFunc(h.fileEdit)))
	mux.Handle("POST /api/v1/files/perm", h.requireRole(roleOperator)(http.HandlerFunc(h.filePerm)))
}

// fileActor derives the requester identity (RBAC role = principal).
func (h *Handler) fileActor(r *http.Request) files.Actor {
	return files.Actor{Principal: h.roleFor(r), Role: h.roleFor(r)}
}

func (h *Handler) fileStat(w http.ResponseWriter, r *http.Request) {
	if h.files == nil {
		writeError(w, http.StatusServiceUnavailable, "files_disabled", "files subsystem not initialized", nil)
		return
	}
	agentID, path := r.URL.Query().Get("agent_id"), r.URL.Query().Get("path")
	if agentID == "" || path == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id and path required", nil)
		return
	}
	st, err := h.files.Stat(r.Context(), agentID, path, h.fileActor(r))
	if err != nil {
		h.fileErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, statJSON(st))
}

func (h *Handler) fileList(w http.ResponseWriter, r *http.Request) {
	if h.files == nil {
		writeError(w, http.StatusServiceUnavailable, "files_disabled", "files subsystem not initialized", nil)
		return
	}
	agentID, path := r.URL.Query().Get("agent_id"), r.URL.Query().Get("path")
	if agentID == "" || path == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id and path required", nil)
		return
	}
	entries, truncated, err := h.files.List(r.Context(), agentID, path, h.fileActor(r))
	if err != nil {
		h.fileErr(w, err)
		return
	}
	list := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		list = append(list, map[string]any{
			"name": e.Name, "is_dir": e.IsDir, "is_symlink": e.IsSymlink,
			"size": e.Size, "mtime_unix": e.MtimeUnix, "mode": e.Mode,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": list, "truncated": truncated})
}

func (h *Handler) fileDownload(w http.ResponseWriter, r *http.Request) {
	if h.files == nil {
		writeError(w, http.StatusServiceUnavailable, "files_disabled", "files subsystem not initialized", nil)
		return
	}
	agentID, path := r.URL.Query().Get("agent_id"), r.URL.Query().Get("path")
	if agentID == "" || path == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id and path required", nil)
		return
	}
	actor := h.fileActor(r)
	st, err := h.files.Stat(r.Context(), agentID, path, actor)
	if err != nil {
		h.fileErr(w, err)
		return
	}
	if st.IsDir {
		writeError(w, http.StatusBadRequest, "bad_request", "path is a directory", nil)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size, 10))
	if _, err := h.files.Download(r.Context(), agentID, path, w, actor); err != nil {
		h.log.Printf("files: download %s@%s: %v", path, agentID, err)
	}
}

type fileWriteBody struct {
	AgentID        string `json:"agent_id"`
	Path           string `json:"path"`
	ContentB64     string `json:"content_b64,omitempty"`
	Mode           string `json:"mode,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	Owner          string `json:"owner,omitempty"`
	Group          string `json:"group,omitempty"`
}

func (h *Handler) decodeWriteBody(w http.ResponseWriter, r *http.Request) (*fileWriteBody, bool) {
	var body fileWriteBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid json: "+err.Error(), nil)
		return nil, false
	}
	if body.AgentID == "" || body.Path == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent_id and path required", nil)
		return nil, false
	}
	return &body, true
}

func (h *Handler) fileUpload(w http.ResponseWriter, r *http.Request) {
	if h.files == nil {
		writeError(w, http.StatusServiceUnavailable, "files_disabled", "files subsystem not initialized", nil)
		return
	}
	body, ok := h.decodeWriteBody(w, r)
	if !ok {
		return
	}
	content, err := base64.StdEncoding.DecodeString(body.ContentB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "content_b64: "+err.Error(), nil)
		return
	}
	sha, err := h.files.Upload(r.Context(), body.AgentID, body.Path, bytes.NewReader(content), int64(len(content)), body.Mode, h.fileActor(r))
	if err != nil {
		h.fileErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sha256": sha})
}

func (h *Handler) fileEdit(w http.ResponseWriter, r *http.Request) {
	if h.files == nil {
		writeError(w, http.StatusServiceUnavailable, "files_disabled", "files subsystem not initialized", nil)
		return
	}
	body, ok := h.decodeWriteBody(w, r)
	if !ok {
		return
	}
	if body.ExpectedSHA256 == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "expected_sha256 required (compare-and-swap)", nil)
		return
	}
	content, err := base64.StdEncoding.DecodeString(body.ContentB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "content_b64: "+err.Error(), nil)
		return
	}
	sha, err := h.files.Edit(r.Context(), body.AgentID, body.Path, body.ExpectedSHA256, content, h.fileActor(r))
	if err != nil {
		h.fileErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sha256": sha})
}

func (h *Handler) filePerm(w http.ResponseWriter, r *http.Request) {
	if h.files == nil {
		writeError(w, http.StatusServiceUnavailable, "files_disabled", "files subsystem not initialized", nil)
		return
	}
	body, ok := h.decodeWriteBody(w, r)
	if !ok {
		return
	}
	if body.Mode == "" && body.Owner == "" && body.Group == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "mode, owner, or group required", nil)
		return
	}
	if err := h.files.SetPerm(r.Context(), body.AgentID, body.Path, body.Mode, body.Owner, body.Group, h.fileActor(r)); err != nil {
		h.fileErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// statJSON serializes a FileStat for the API.
func statJSON(st *pb.FileStat) map[string]any {
	return map[string]any{
		"size": st.Size, "mode": st.Mode,
		"owner": st.Owner, "group": st.Group, "mtime_unix": st.MtimeUnix,
		"sha256": st.Sha256,
		"is_dir": st.IsDir, "is_symlink": st.IsSymlink,
	}
}

// fileErr maps file op errors to HTTP codes.
func (h *Handler) fileErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "denied"):
		writeError(w, http.StatusForbidden, "denied", msg, nil)
	case strings.Contains(msg, files.ErrConflict.Error()):
		writeError(w, http.StatusConflict, "checksum_mismatch", msg, nil)
	case strings.Contains(msg, "no such file") || strings.Contains(msg, "not found"):
		writeError(w, http.StatusNotFound, "not_found", msg, nil)
	case strings.Contains(msg, "exceeds") || strings.Contains(msg, "cap"):
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", msg, nil)
	case strings.Contains(msg, "symlink") || strings.Contains(msg, "invalid path") || strings.Contains(msg, "absolute path"):
		writeError(w, http.StatusBadRequest, "bad_path", msg, nil)
	case strings.Contains(msg, "no active session") || strings.Contains(msg, "stream closed") || strings.Contains(msg, "deadline exceeded"):
		writeError(w, http.StatusBadGateway, "agent_unavailable", msg, nil)
	default:
		writeError(w, http.StatusInternalServerError, "internal", msg, nil)
	}
}
