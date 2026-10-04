// Secrets bootstrap API (Setup checklist): POST /api/v1/secrets/bootstrap
// enables the feature at runtime — key file created 0600 in the data dir,
// capability probe flips to true, a second call 409s, and the assistant
// (built keyless) adopts the key so an endpoint API key can be sealed
// immediately after.
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/server/assistant"
	"github.com/blawesom/partout/internal/server/mcp"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func TestSecretsBootstrap(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := New(st, h, sseB, log.New(io.Discard, "api: ", 0))
	apiH.SetAssistant(assistant.New(st, mcp.NewLocalAPI(apiH), nil, log.New(io.Discard, "as: ", 0)))
	keyPath := filepath.Join(t.TempDir(), "secret.key")
	apiH.SetSecretsKeyPath(keyPath)
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)

	// Before: feature off, list 503.
	if getCap(t, srv, "secrets") {
		t.Fatalf("caps.secrets should be false before bootstrap")
	}
	resp, err := http.Get(srv.URL + "/api/v1/secrets")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("list before bootstrap: status %d, want 503", resp.StatusCode)
	}

	// Bootstrap: 200, key file 0600.
	resp, err = http.Post(srv.URL+"/api/v1/secrets/bootstrap", "application/json", nil)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	var body struct {
		Status  string `json:"status"`
		KeyFile string `json:"key_file"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body.Status != "enabled" {
		t.Fatalf("bootstrap: status %d body %v", resp.StatusCode, body)
	}
	if body.KeyFile != keyPath {
		t.Fatalf("bootstrap key_file = %q, want %q", body.KeyFile, keyPath)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %o, want 0600", perm)
	}

	// After: capability on, list 200.
	if !getCap(t, srv, "secrets") {
		t.Fatalf("caps.secrets should be true after bootstrap")
	}
	resp, err = http.Get(srv.URL + "/api/v1/secrets")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list after bootstrap: status %d, want 200", resp.StatusCode)
	}

	// Second bootstrap: 409 (never rotates).
	resp, err = http.Post(srv.URL+"/api/v1/secrets/bootstrap", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second bootstrap: status %d, want 409", resp.StatusCode)
	}

	// The assistant adopted the key: an endpoint API key can now be sealed
	// (before bootstrap this PUT 400s with ErrKeyStoreUnavailable).
	putCfg := func(apiKey string) int {
		body := fmt.Sprintf(`{"base_url":"http://127.0.0.1:1/v1","model":"m","api_key":%q,"default_profile":"readonly"}`, apiKey)
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/assistant/config", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT config: %v", err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if code := putCfg("sk-test"); code != http.StatusOK {
		t.Fatalf("PUT assistant config with api_key after bootstrap: status %d, want 200 (key adopted)", code)
	}
	resp, err = http.Get(srv.URL + "/api/v1/assistant/config")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		KeySet bool `json:"key_set"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)
	resp.Body.Close()
	if !cfg.KeySet {
		t.Fatalf("assistant key_set should be true (sealed under the bootstrapped master)")
	}
}

func getCap(t *testing.T, srv *httptest.Server, name string) bool {
	t.Helper()
	resp, err := http.Get(srv.URL + "/api/v1/capabilities")
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	var caps map[string]bool
	_ = json.NewDecoder(resp.Body).Decode(&caps)
	resp.Body.Close()
	return caps[name]
}
