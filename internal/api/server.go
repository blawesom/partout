// REST handlers for server operations (ops plane).
//
// POST /api/v1/server/backup (admin): trigger the same atomic hot snapshot
// `ctl db-backup` and the systemd partout-backup.timer run (VACUUM INTO,
// WAL-safe, server may be serving) — so a remote operator can snapshot
// before a risky change without shell access to the server box. Naming and
// retention follow scripts/backup.sh.
package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// SetBackupDir installs the snapshot destination (default: <db dir>/backups,
// the same directory the systemd timer uses — set in main.go).
func (h *Handler) SetBackupDir(dir string) { h.backupDir = dir }

func (h *Handler) handleServerBackup(w http.ResponseWriter, r *http.Request) {
	if h.backupDir == "" {
		writeError(w, http.StatusServiceUnavailable, "backup_unavailable",
			"backup directory not configured on this server", nil)
		return
	}
	if err := os.MkdirAll(h.backupDir, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error",
			"create backup dir: "+err.Error(), nil)
		return
	}
	out := filepath.Join(h.backupDir,
		fmt.Sprintf("partout.db.%s.bak", time.Now().UTC().Format("20060102T150405Z")))
	if err := h.st.BackupTo(out); err != nil {
		writeError(w, http.StatusInternalServerError, "backup_failed", err.Error(), nil)
		return
	}
	size := int64(0)
	if fi, err := os.Stat(out); err == nil {
		size = fi.Size()
	}
	principal, _ := h.actorFor(r)
	h.audit("server.backup", principal, map[string]string{
		"path": out, "bytes": fmt.Sprint(size),
	})
	writeJSON(w, http.StatusOK, map[string]any{"path": out, "bytes": size})
}
