package agent

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testTempSuffix mirrors fs.tempSuffix (unexported): upload temp names must
// contain it or fs.UploadAbort's checkTemp rejects them.
const testTempSuffix = ".partout-tmp-"

// newUploadsTestAgent builds a bare Agent with just the upload-tracking
// fields wired (white-box: the Run loop is not started).
func newUploadsTestAgent(t *testing.T) *Agent {
	t.Helper()
	return &Agent{
		log:     log.New(io.Discard, "agent: ", 0),
		uploads: make(map[string]uploadReg),
	}
}

func mkTemp(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name+testTempSuffix+"deadbeef")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestUploadRegistrationStreamScoped: a registration from an old stream
// generation must not authorize CHUNK/COMMIT/ABORT on the new stream.
func TestUploadRegistrationStreamScoped(t *testing.T) {
	a := newUploadsTestAgent(t)
	dir := t.TempDir()
	temp := mkTemp(t, dir, "up1")

	a.streamGen.Store(1)
	if err := a.registerUpload(temp); err != nil {
		t.Fatalf("registerUpload: %v", err)
	}
	if !a.knownUpload(temp) {
		t.Fatal("current-gen registration should be known")
	}

	// Generation bumps (reconnect) but the entry is still in the map (a BEGIN
	// racing the teardown): the generation check alone must reject it.
	a.streamGen.Store(2)
	if a.knownUpload(temp) {
		t.Fatal("old-generation registration must NOT be known on the new stream (gen check)")
	}

	// Stream teardown then clears the map and removes the temp file.
	a.clearStreamUploads()
	if a.knownUpload(temp) {
		t.Fatal("cleared registration must not be known")
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("teardown must remove the orphaned temp file, stat err = %v", err)
	}
	if len(a.uploads) != 0 {
		t.Fatalf("uploads map not cleared: %d entries", len(a.uploads))
	}
}

// TestUploadRegistrationCap: BEGIN beyond maxLiveUploads is rejected.
func TestUploadRegistrationCap(t *testing.T) {
	a := newUploadsTestAgent(t)
	dir := t.TempDir()
	a.streamGen.Store(1)
	for i := 0; i < maxLiveUploads; i++ {
		temp := mkTemp(t, dir, "cap")
		_ = temp
		p := filepath.Join(dir, "cap"+testTempSuffix+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := a.registerUpload(p); err != nil {
			t.Fatalf("registerUpload %d: %v", i, err)
		}
	}
	extra := mkTemp(t, dir, "over")
	if err := a.registerUpload(extra); err == nil {
		t.Fatalf("registration beyond cap %d must fail", maxLiveUploads)
	}
}

// TestUploadRegistrationTTL: an abandoned registration older than uploadTTL
// is expired (and its temp removed) on the next BEGIN.
func TestUploadRegistrationTTL(t *testing.T) {
	a := newUploadsTestAgent(t)
	dir := t.TempDir()
	old := mkTemp(t, dir, "old")
	a.streamGen.Store(1)
	a.uploadsMu.Lock()
	a.uploads[old] = uploadReg{gen: 1, since: time.Now().Add(-2 * uploadTTL)}
	a.uploadsMu.Unlock()

	fresh := mkTemp(t, dir, "fresh")
	if err := a.registerUpload(fresh); err != nil {
		t.Fatalf("registerUpload: %v", err)
	}
	if a.knownUpload(old) {
		t.Fatal("expired registration must not be known")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("expired registration's temp file must be removed")
	}
	if !a.knownUpload(fresh) {
		t.Fatal("fresh registration must be known")
	}
}

// TestForgetUploadIfGone: registration is dropped only when the temp file is
// confirmed gone; a surviving temp keeps the registration (retry/abort).
func TestForgetUploadIfGone(t *testing.T) {
	a := newUploadsTestAgent(t)
	dir := t.TempDir()
	temp := mkTemp(t, dir, "fg")
	a.streamGen.Store(1)
	if err := a.registerUpload(temp); err != nil {
		t.Fatal(err)
	}

	// Temp still exists → registration kept.
	a.forgetUploadIfGone(temp)
	if !a.knownUpload(temp) {
		t.Fatal("registration must be kept while the temp file exists")
	}

	// Temp removed → registration dropped.
	if err := os.Remove(temp); err != nil {
		t.Fatal(err)
	}
	a.forgetUploadIfGone(temp)
	if a.knownUpload(temp) {
		t.Fatal("registration must be dropped once the temp file is gone")
	}
}
