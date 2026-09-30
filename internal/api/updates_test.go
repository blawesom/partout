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

func updateTestServer(t *testing.T) (*store.Store, *stream.Handler, *httptest.Server) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	sh := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := api.New(st, sh, sseB, log.New(io.Discard, "api: ", 0))
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)
	return st, sh, srv
}

// TestUpdateApplyOffline verifies the canary apply endpoint: dispatch to a
// not-connected agent is 409 (queued delivery lands in step 3), unknown
// release is 404, and a server-kind release is refused for host apply.
func TestUpdateApplyOffline(t *testing.T) {
	st, _, srv := updateTestServer(t)

	if err := st.UpsertAgent(store.Agent{ID: "ag_up", UUID: "u-up"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	artifact := []byte("fake binary")
	sum := sha256.Sum256(artifact)
	if err := st.InsertRelease(store.Release{
		ID: "rel_a", Version: "v1", Arch: "linux-amd64", Kind: "agent",
		SHA256: hex.EncodeToString(sum[:]), Signature: strings.Repeat("A", 88),
		Artifact: artifact, UploadedBy: "admin",
	}); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}
	if err := st.InsertRelease(store.Release{
		ID: "rel_s", Version: "v1", Arch: "linux-amd64", Kind: "server",
		SHA256: hex.EncodeToString(sum[:]), Signature: strings.Repeat("A", 88),
		Artifact: artifact, UploadedBy: "admin",
	}); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}

	// Offline agent → 409.
	code, e := labelsReq(t, "POST", srv.URL+"/api/v1/updates/apply",
		`{"agent_id":"ag_up","release_id":"rel_a"}`)
	if code != http.StatusConflict {
		t.Errorf("apply offline = %d (%v), want 409", code, e)
	}
	// Unknown release → 404.
	if code, _ := labelsReq(t, "POST", srv.URL+"/api/v1/updates/apply",
		`{"agent_id":"ag_up","release_id":"rel_nope"}`); code != http.StatusNotFound {
		t.Errorf("apply unknown release = %d, want 404", code)
	}
	// Unknown host → 404.
	if code, _ := labelsReq(t, "POST", srv.URL+"/api/v1/updates/apply",
		`{"agent_id":"ag_nope","release_id":"rel_a"}`); code != http.StatusNotFound {
		t.Errorf("apply unknown host = %d, want 404", code)
	}
	// Server-kind release → 400 (never applied to a host).
	if code, _ := labelsReq(t, "POST", srv.URL+"/api/v1/updates/apply",
		`{"agent_id":"ag_up","release_id":"rel_s"}`); code != http.StatusBadRequest {
		t.Errorf("apply server-kind = %d, want 400", code)
	}
}

// TestUpdateGrantArtifact verifies the one-time artifact download: a minted
// grant streams the exact artifact with integrity headers, and the grant
// cannot be reused.
func TestUpdateGrantArtifact(t *testing.T) {
	st, sh, srv := updateTestServer(t)

	artifact := []byte("grant artifact bytes")
	sum := sha256.Sum256(artifact)
	if err := st.InsertRelease(store.Release{
		ID: "rel_g", Version: "v2", Arch: "linux-amd64", Kind: "agent",
		SHA256: hex.EncodeToString(sum[:]), Signature: strings.Repeat("B", 88),
		Artifact: artifact, UploadedBy: "admin",
	}); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}

	tok, err := sh.IssueUpdateGrant("ag_up", "rel_g")
	if err != nil {
		t.Fatalf("IssueUpdateGrant: %v", err)
	}

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/updates/grants/"+tok, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("grant download: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, artifact) {
		t.Fatalf("grant download = %d, %d bytes (want %d)", resp.StatusCode, len(got), len(artifact))
	}
	if resp.Header.Get("X-Partout-Sha256") != hex.EncodeToString(sum[:]) {
		t.Error("X-Partout-Sha256 header missing/incorrect")
	}

	// Single-use: the same grant 401s on reuse.
	req2, _ := http.NewRequest("GET", srv.URL+"/api/v1/updates/grants/"+tok, nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("grant reuse = %d, want 401", resp2.StatusCode)
	}

	// Unknown grant → 401.
	req3, _ := http.NewRequest("GET", srv.URL+"/api/v1/updates/grants/deadbeef", nil)
	resp3, _ := http.DefaultClient.Do(req3)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("unknown grant = %d, want 401", resp3.StatusCode)
	}
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

// TestUpdateReleaseUnsignedBeta: M8.1 beta policy — an empty signature is
// accepted only while unsigned releases are allowed; otherwise 400.
func TestUpdateReleaseUnsignedBeta(t *testing.T) {
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

	artifact, m, _ := signedArtifact(t, "v0.9.1", "agent")

	// Flag off (default in tests) → unsigned upload refused.
	code, e := labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases",
		releaseUploadBody(m, "", artifact))
	if code != http.StatusBadRequest {
		t.Fatalf("unsigned upload, flag off = %d, want 400: %v", code, e)
	}

	// Flag on (beta default) → unsigned upload accepted, listed as unsigned.
	apiH.SetAllowUnsignedReleases(true)
	code, e = labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases",
		releaseUploadBody(m, "", artifact))
	if code != http.StatusCreated {
		t.Fatalf("unsigned upload, flag on = %d: %v", code, e)
	}
	rid, _ := e["id"].(string)

	code, got := labelsReq(t, "GET", srv.URL+"/api/v1/updates/releases/"+rid, "")
	if code != http.StatusOK {
		t.Fatalf("get = %d", code)
	}
	if got["signature"] != "" {
		t.Errorf("signature = %q, want empty", got["signature"])
	}
	if got["sha256"] != m.SHA256 {
		t.Errorf("sha256 = %v, want %s", got["sha256"], m.SHA256)
	}

	// A signed upload still works with the flag on (verification unchanged).
	art2, m2, sigB64 := signedArtifact(t, "v0.9.2", "agent")
	code, e = labelsReq(t, "POST", srv.URL+"/api/v1/updates/releases",
		releaseUploadBody(m2, sigB64, art2))
	if code != http.StatusCreated {
		t.Fatalf("signed upload, flag on = %d: %v", code, e)
	}
}
