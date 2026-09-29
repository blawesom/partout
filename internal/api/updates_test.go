package api_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/cryptoutil"
	"github.com/blawesom/partout/internal/release"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// signedArtifact builds a fake binary plus its valid signature.
func signedArtifact(t *testing.T, version, kind string) (artifact []byte, m release.Manifest, sigB64 string) {
	t.Helper()
	kp, err := cryptoutil.NewKeyPairEd25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	artifact = []byte("fake partout release binary " + version)
	sum := sha256.Sum256(artifact)
	m = release.Manifest{
		Version: version, Arch: "linux-amd64", Kind: kind,
		SHA256: hex.EncodeToString(sum[:]),
	}
	sigB64 = base64.StdEncoding.EncodeToString(release.Sign(kp.Priv, m))
	return artifact, m, sigB64
}

func releaseUploadBody(m release.Manifest, sigB64 string, artifact []byte) string {
	return `{"version":"` + m.Version + `","arch":"` + m.Arch + `","kind":"` + m.Kind +
		`","sha256":"` + m.SHA256 + `","signature":"` + sigB64 +
		`","artifact_b64":"` + base64.StdEncoding.EncodeToString(artifact) + `"}`
}

// TestUpdateReleaseLifecycle verifies the M8.1 release store: upload (with
// sha256 + signature checks), list, get, artifact download with integrity
// headers, duplicate conflict, and delete.
func TestUpdateReleaseLifecycle(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	streamH := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := api.New(st, streamH, sseB, log.New(io.Discard, "api: ", 0))
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)

	artifact, m, sigB64 := signedArtifact(t, "v0.9.0", "agent")

	// Upload → 201.
	code, e := labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases",
		releaseUploadBody(m, sigB64, artifact))
	if code != http.StatusCreated {
		t.Fatalf("upload = %d: %v", code, e)
	}
	rid, _ := e["id"].(string)
	if !strings.HasPrefix(rid, "rel_") {
		t.Fatalf("id = %q, want rel_ prefix", rid)
	}

	// List → one row, no artifact bytes in the payload.
	code, list := labelsReq(t, "GET", srv.URL+"/api/v1/updates/releases", "")
	if code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	if list["count"].(float64) != 1 {
		t.Fatalf("count = %v", list["count"])
	}
	items, _ := list["items"].([]any)
	row, _ := items[0].(map[string]any)
	if row["version"] != "v0.9.0" || row["kind"] != "agent" || row["sha256"] != m.SHA256 {
		t.Errorf("row = %v", row)
	}
	if _, hasArtifact := row["artifact"]; hasArtifact {
		t.Error("list row must not include the artifact")
	}

	// Get by id → 200.
	code, got := labelsReq(t, "GET", srv.URL+"/api/v1/updates/releases/"+rid, "")
	if code != http.StatusOK || got["version"] != "v0.9.0" {
		t.Fatalf("get = %d %v", code, got)
	}

	// Artifact → bytes match and integrity headers are present.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/updates/releases/"+rid+"/artifact", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	defer resp.Body.Close()
	gotBytes, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(gotBytes, artifact) {
		t.Fatalf("artifact bytes mismatch (%d vs %d)", len(gotBytes), len(artifact))
	}
	if resp.Header.Get("X-Partout-Sha256") != m.SHA256 {
		t.Errorf("X-Partout-Sha256 = %q", resp.Header.Get("X-Partout-Sha256"))
	}
	if resp.Header.Get("X-Partout-Signature") != sigB64 {
		t.Error("X-Partout-Signature missing/incorrect")
	}

	// Duplicate (same version/arch/kind) → 409.
	code, e = labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases",
		releaseUploadBody(m, sigB64, artifact))
	if code != http.StatusConflict {
		t.Errorf("duplicate upload = %d (%v), want 409", code, e)
	}

	// sha256 mismatch → 400.
	bad := releaseUploadBody(m, sigB64, artifact)
	bad = strings.Replace(bad, `"sha256":"`+m.SHA256, `"sha256":"0`+m.SHA256[1:], 1)
	if code, _ = labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases", bad); code != http.StatusBadRequest {
		t.Errorf("sha mismatch = %d, want 400", code)
	}

	// Garbage signature → 400.
	badSig := releaseUploadBody(release.Manifest{Version: "v0.9.1", Arch: m.Arch, Kind: m.Kind, SHA256: m.SHA256}, "!!not-base64!!", artifact)
	if code, _ = labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases", badSig); code != http.StatusBadRequest {
		t.Errorf("bad signature = %d, want 400", code)
	}

	// Bad kind → 400.
	badKind := releaseUploadBody(release.Manifest{Version: "v0.9.2", Arch: m.Arch, Kind: "daemon", SHA256: m.SHA256}, sigB64, artifact)
	if code, _ = labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases", badKind); code != http.StatusBadRequest {
		t.Errorf("bad kind = %d, want 400", code)
	}

	// Unknown id → 404 (get, artifact, delete).
	if code, _ = labelsReq(t, "GET", srv.URL+"/api/v1/updates/releases/rel_nope", ""); code != http.StatusNotFound {
		t.Errorf("get unknown = %d, want 404", code)
	}
	if code, _ = labelsReq(t, "GET", srv.URL+"/api/v1/updates/releases/rel_nope/artifact", ""); code != http.StatusNotFound {
		t.Errorf("artifact unknown = %d, want 404", code)
	}
	if code, _ = labelsReq(t, "DELETE", srv.URL+"/api/v1/updates/releases/rel_nope", ""); code != http.StatusNotFound {
		t.Errorf("delete unknown = %d, want 404", code)
	}

	// Delete → 200, then 404, list empties.
	code, _ = labelsReq(t, "DELETE", srv.URL+"/api/v1/updates/releases/"+rid, "")
	if code != http.StatusOK {
		t.Fatalf("delete = %d", code)
	}
	if code, _ = labelsReq(t, "DELETE", srv.URL+"/api/v1/updates/releases/"+rid, ""); code != http.StatusNotFound {
		t.Errorf("re-delete = %d, want 404", code)
	}
	code, list = labelsReq(t, "GET", srv.URL+"/api/v1/updates/releases", "")
	if code != http.StatusOK || list["count"].(float64) != 0 {
		t.Errorf("list after delete = %d %v", code, list)
	}

	// Audit trail: upload + download + delete all recorded.
	audit, err := st.ListAudit("", 50)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	kinds := map[string]bool{}
	for _, a := range audit {
		kinds[a.Kind] = true
	}
	for _, want := range []string{"update.upload", "update.artifact.download", "update.release.deleted"} {
		if !kinds[want] {
			t.Errorf("audit missing kind %q (have %v)", want, kinds)
		}
	}
}
