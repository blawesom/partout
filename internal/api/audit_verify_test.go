// GET /api/v1/audit/verify tests (PRD Decision 5, 1.0 gate): the endpoint
// reports chain health over HTTP and names the first broken row.
package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// startAuditVerifyAPI builds a store + API handler + httptest server.
func startAuditVerifyAPI(t *testing.T) (*store.Store, *httptest.Server) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	streamH := stream.NewHandler(st, sseB, nil)
	apiH := api.New(st, streamH, sseB, nil)
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)
	return st, srv
}

// TestAuditVerifyEndpoint_OK appends rows through the store and expects
// {ok:true, rows_checked:N} from the verify endpoint.
func TestAuditVerifyEndpoint_OK(t *testing.T) {
	st, srv := startAuditVerifyAPI(t)

	for i := range 5 {
		if err := st.AppendAudit(store.AuditEvent{
			TS:      int64(1700000000 + i),
			Kind:    "test.event",
			Actor:   "tester",
			Payload: "{}",
		}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	resp, err := http.Get(srv.URL + "/api/v1/audit/verify")
	if err != nil {
		t.Fatalf("GET verify: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		OK          bool  `json:"ok"`
		RowsChecked int64 `json:"rows_checked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.OK || out.RowsChecked != 5 {
		t.Fatalf("verify = {ok:%v rows:%d}, want {ok:true rows:5}", out.OK, out.RowsChecked)
	}
}

// TestAuditVerifyEndpoint_Tampered tampers with a row behind the store's
// back and expects {ok:false, broken_row_id} naming it.
func TestAuditVerifyEndpoint_Tampered(t *testing.T) {
	st, srv := startAuditVerifyAPI(t)

	for i := range 5 {
		if err := st.AppendAudit(store.AuditEvent{
			TS:      int64(1700000000 + i),
			Kind:    "test.event",
			Actor:   "tester",
			Payload: "{}",
		}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	if _, err := st.DB().Exec(`UPDATE audit_events SET payload='{"tampered":true}' WHERE id=3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	resp, err := http.Get(srv.URL + "/api/v1/audit/verify")
	if err != nil {
		t.Fatalf("GET verify: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		RowsChecked int64  `json:"rows_checked"`
		BrokenRowID int64  `json:"broken_row_id"`
		Reason      string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.OK || out.BrokenRowID != 3 {
		t.Fatalf("verify = {ok:%v broken_row_id:%d}, want {ok:false broken_row_id:3}", out.OK, out.BrokenRowID)
	}
	if out.Reason == "" {
		t.Error("empty failure reason")
	}
}

// TestAuditVerifyEndpoint_HeadKeyID: with an audit key installed, the verify
// response's head carries the key id (so an operator can tell WHICH key
// verifies algo=2 rows) plus last_id/last_hash.
func TestAuditVerifyEndpoint_HeadKeyID(t *testing.T) {
	st, srv := startAuditVerifyAPI(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	st.SetAuditKey(key)
	st.SetAuditKeyID("id:deadbeefcafe0123")

	for i := range 3 {
		if err := st.AppendAudit(store.AuditEvent{TS: int64(1700000000 + i), Kind: "test.event", Actor: "tester", Payload: "{}"}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	resp, err := http.Get(srv.URL + "/api/v1/audit/verify")
	if err != nil {
		t.Fatalf("GET verify: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool  `json:"ok"`
		RowsChecked int64 `json:"rows_checked"`
		Head        struct {
			LastID   int64  `json:"last_id"`
			LastHash string `json:"last_hash"`
			KeyID    string `json:"key_id"`
		} `json:"head"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.OK || out.RowsChecked != 3 {
		t.Fatalf("verify = {ok:%v rows:%d}, want {ok:true rows:3}", out.OK, out.RowsChecked)
	}
	if out.Head.KeyID != "id:deadbeefcafe0123" {
		t.Fatalf("head.key_id = %q, want id:deadbeefcafe0123", out.Head.KeyID)
	}
	if out.Head.LastID != 3 || out.Head.LastHash == "" {
		t.Fatalf("head = (%d, %q), want (3, non-empty)", out.Head.LastID, out.Head.LastHash)
	}
}
