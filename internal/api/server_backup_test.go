// POST /server/backup: the control-plane snapshot trigger. Must produce
// the same artifact `ctl db-backup` / the systemd timer make (VACUUM INTO,
// valid SQLite with the schema present) and audit the act.
package api

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"

	_ "modernc.org/sqlite"
)

func TestServerBackupEndpoint(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpsertAgent(store.Agent{ID: "ag_bk", UUID: "u"}); err != nil {
		t.Fatal(err)
	}
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := New(st, h, sseB, log.New(io.Discard, "api: ", 0))
	dir := t.TempDir()
	apiH.SetBackupDir(filepath.Join(dir, "backups"))
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/api/v1/server/backup", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /server/backup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var body struct {
		Path  string `json:"path"`
		Bytes int64  `json:"bytes"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if !strings.HasPrefix(body.Path, filepath.Join(dir, "backups")) || body.Bytes == 0 {
		t.Fatalf("body = %+v", body)
	}
	// The snapshot is a valid SQLite database with the schema.
	snap, err := sql.Open("sqlite", "file:"+body.Path+"?mode=ro")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer snap.Close()
	var n int
	if err := snap.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("snapshot agents = %d err=%v (want 1)", n, err)
	}
	// Audited.
	var actor string
	if err := st.DB().QueryRow(`SELECT actor FROM audit_events WHERE kind='server.backup' ORDER BY ts DESC LIMIT 1`).Scan(&actor); err != nil || actor != "local" {
		t.Fatalf("audit actor = %q err=%v (want local)", actor, err)
	}
}
