package fs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newRoot builds a fresh file root (temp dir) for tests.
func newRoot(t *testing.T) string {
	t.Helper()
	root, err := PrepareFileRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// ---- PrepareFileRoot -------------------------------------------------------

func TestPrepareFileRootCreatesMissing(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "does-not-exist-yet")
	got, err := PrepareFileRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(got)
	if err != nil || !info.IsDir() {
		t.Fatalf("root not created: %v", err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("mode = %v, want 0750", info.Mode().Perm())
	}
}

func TestPrepareFileRootRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link-root")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareFileRoot(link); err == nil {
		t.Fatal("expected error for symlink root")
	}
}

func TestPrepareFileRootRejectsNonDir(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareFileRoot(f); err == nil {
		t.Fatal("expected error for non-directory root")
	}
}

// ---- ResolvePath -----------------------------------------------------------

func TestResolvePathRootItself(t *testing.T) {
	root := newRoot(t)
	for _, in := range []string{"", "/", "."} {
		got, err := ResolvePath(root, in)
		if err != nil {
			t.Fatalf("ResolvePath(%q): %v", in, err)
		}
		if got != root {
			t.Errorf("ResolvePath(%q) = %q, want the root", in, got)
		}
	}
}

func TestResolvePathTraversalRejected(t *testing.T) {
	root := newRoot(t)
	for _, in := range []string{"..", "../x", "a/../../etc", "/../../etc"} {
		if _, err := ResolvePath(root, in); !errors.Is(err, ErrBadPath) {
			t.Errorf("ResolvePath(%q) = %v, want ErrBadPath", in, err)
		}
	}
}

func TestResolvePathSymlinkEscapesRejected(t *testing.T) {
	root := newRoot(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the root pointing outside must be rejected.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(filepath.Join(outside, "secret"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolvePath(root, "escape"); !errors.Is(err, ErrBadPath) {
		t.Errorf("symlink escape: %v, want ErrBadPath", err)
	}
	// Symlinked intermediate component.
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(sub, "linkdir")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolvePath(root, "sub/linkdir/secret"); !errors.Is(err, ErrBadPath) {
		t.Errorf("symlink intermediate: %v, want ErrBadPath", err)
	}
}

func TestResolvePathAllowsMissingFinal(t *testing.T) {
	root := newRoot(t)
	// Intermediates must exist; only the final component may be missing
	// (an upload target).
	if err := os.MkdirAll(filepath.Join(root, "new", "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ResolvePath(root, "new/dir/target.txt")
	if err != nil {
		t.Fatalf("missing final component should be allowed (upload): %v", err)
	}
	if want := filepath.Join(root, "new/dir/target.txt"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolvePathRejectsMissingIntermediate(t *testing.T) {
	root := newRoot(t)
	if _, err := ResolvePath(root, "nope/here.txt"); !errors.Is(err, ErrBadPath) {
		t.Errorf("missing intermediate: %v, want ErrBadPath", err)
	}
}

func TestResolvePathRejectsNonDirIntermediate(t *testing.T) {
	root := newRoot(t)
	f := filepath.Join(root, "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolvePath(root, "afile/child"); !errors.Is(err, ErrBadPath) {
		t.Errorf("non-dir intermediate: %v, want ErrBadPath", err)
	}
}

func TestResolvePathMissingRoot(t *testing.T) {
	if _, err := ResolvePath("", "x"); !errors.Is(err, ErrRootUnavailable) {
		t.Errorf("empty root: %v, want ErrRootUnavailable", err)
	}
}

// ---- operations against the root ------------------------------------------

func TestStatPath(t *testing.T) {
	root := newRoot(t)
	p := "hello.txt"
	content := []byte("hello world")
	if err := os.WriteFile(filepath.Join(root, p), content, 0o640); err != nil {
		t.Fatal(err)
	}
	st, err := StatPath(root, p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", st.Size, len(content))
	}
	if st.Mode != "0640" {
		t.Errorf("mode = %q, want 0640", st.Mode)
	}
	if st.IsDir {
		t.Error("IsDir should be false")
	}
	h := sha256.Sum256(content)
	if st.SHA256 != hex.EncodeToString(h[:]) {
		t.Errorf("sha256 = %s, want %s", st.SHA256, hex.EncodeToString(h[:]))
	}
	if st.Owner == "" || st.Group == "" {
		t.Errorf("owner/group empty: %+v", st)
	}

	// Directory: the root itself.
	dst, err := StatPath(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !dst.IsDir {
		t.Error("IsDir should be true for the root")
	}
	if dst.SHA256 != "" {
		t.Error("sha256 should be empty for a directory")
	}
}

func TestStatPathRejectsEscape(t *testing.T) {
	root := newRoot(t)
	if _, err := StatPath(root, "../../etc/passwd"); !errors.Is(err, ErrBadPath) {
		t.Errorf("escape: %v, want ErrBadPath", err)
	}
}

func TestList(t *testing.T) {
	root := newRoot(t)
	for i, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte{byte(i)}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, truncated, err := List(root, "", Config{})
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("unexpected truncation")
	}
	if len(entries) != 3 {
		t.Fatalf("len = %d, want 3", len(entries))
	}
	// Truncation.
	entries, truncated, err = List(root, "", Config{MaxListEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("expected truncation")
	}
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2", len(entries))
	}
}

func TestListRejectsFile(t *testing.T) {
	root := newRoot(t)
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := List(root, "f", Config{}); err == nil {
		t.Fatal("expected error listing a file")
	}
}

func TestDownloadAt(t *testing.T) {
	root := newRoot(t)
	content := make([]byte, 1000)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(root, "blob.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{MaxChunk: 300}.fill()
	p := "blob.bin"

	// First chunk.
	data, size, done, err := DownloadAt(root, p, 0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if size != 1000 {
		t.Errorf("size = %d, want 1000", size)
	}
	if done {
		t.Error("done should be false after first chunk")
	}
	if len(data) != 300 {
		t.Fatalf("chunk len = %d, want 300", len(data))
	}
	if !bytes.Equal(data, content[:300]) {
		t.Error("first chunk content mismatch")
	}

	// Reassemble.
	var got []byte
	off := int64(0)
	for {
		data, _, done, err := DownloadAt(root, p, off, cfg)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, data...)
		off += int64(len(data))
		if done {
			break
		}
	}
	if !bytes.Equal(got, content) {
		t.Error("reassembled content mismatch")
	}

	// Offset at end.
	data, _, done, err = DownloadAt(root, p, 1000, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !done || len(data) != 0 {
		t.Errorf("at end: done=%v len=%d, want done=true len=0", done, len(data))
	}

	// Offset beyond size.
	if _, _, _, err := DownloadAt(root, p, 2000, cfg); err == nil {
		t.Error("expected error for offset beyond size")
	}
}

func TestUploadRoundTrip(t *testing.T) {
	root := newRoot(t)
	target := "upload.txt"
	content := make([]byte, 700)
	for i := range content {
		content[i] = byte('a' + i%26)
	}
	cfg := Config{}.fill()

	temp, err := UploadBegin(root, target, int64(len(content)), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)
	// The temp must live inside the root (atomic commit on the same fs).
	if rel, err := filepath.Rel(root, temp); err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		t.Fatalf("temp %q not inside root %q", temp, root)
	}

	// Upload in 300-byte chunks.
	var off int64
	for off < int64(len(content)) {
		end := off + 300
		if end > int64(len(content)) {
			end = int64(len(content))
		}
		recv, err := UploadChunk(temp, off, content[off:end], cfg)
		if err != nil {
			t.Fatal(err)
		}
		if recv != end {
			t.Fatalf("received = %d, want %d", recv, end)
		}
		off = end
	}

	h := sha256.Sum256(content)
	gotSha, err := UploadCommit(root, temp, target, "0644", int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if gotSha != hex.EncodeToString(h[:]) {
		t.Errorf("committed sha = %s, want %s", gotSha, hex.EncodeToString(h[:]))
	}
	got, err := os.ReadFile(filepath.Join(root, target))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Error("committed content mismatch")
	}
}

func TestUploadRejectsEscapeTarget(t *testing.T) {
	root := newRoot(t)
	cfg := Config{}.fill()
	if _, err := UploadBegin(root, "../outside.txt", 10, cfg); !errors.Is(err, ErrBadPath) {
		t.Errorf("escape target: %v, want ErrBadPath", err)
	}
}

func TestUploadRejectsBadOffset(t *testing.T) {
	root := newRoot(t)
	cfg := Config{}.fill()
	temp, err := UploadBegin(root, "x", 100, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)
	if _, err := UploadChunk(temp, 50, []byte("abc"), cfg); err == nil {
		t.Fatal("expected error for offset != current size")
	}
}

func TestUploadEnforcesSizeCap(t *testing.T) {
	root := newRoot(t)
	cfg := Config{MaxTransfer: 100}.fill()
	if _, err := UploadBegin(root, "big", 101, cfg); err == nil {
		t.Fatal("expected error: total size exceeds cap")
	}
	temp, err := UploadBegin(root, "big", 100, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)
	if _, err := UploadChunk(temp, 0, make([]byte, 101), cfg); err == nil {
		t.Fatal("expected error: chunk would exceed cap")
	}
}

func TestUploadAbort(t *testing.T) {
	root := newRoot(t)
	cfg := Config{}.fill()
	temp, err := UploadBegin(root, "y", 10, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := UploadAbort(temp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatal("temp should be removed")
	}
	// Aborting a non-temp file must fail.
	other := filepath.Join(root, "not-a-temp")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UploadAbort(other); err == nil {
		t.Fatal("expected error aborting non-temp file")
	}
}

func TestEditCAS(t *testing.T) {
	root := newRoot(t)
	p := "edit.txt"
	orig := []byte("version 1")
	if err := os.WriteFile(filepath.Join(root, p), orig, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.fill()

	origSha, _ := hashFile(filepath.Join(root, p))
	origShaHex := hex.EncodeToString(origSha)

	// Wrong expected sha → conflict.
	if _, err := EditCAS(root, p, "deadbeef", []byte("v2"), cfg); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	// Correct expected sha → success.
	newSha, err := EditCAS(root, p, origShaHex, []byte("version 2"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(root, p))
	if string(got) != "version 2" {
		t.Fatalf("content = %q", got)
	}
	h, _ := hashFile(filepath.Join(root, p))
	if newSha != hex.EncodeToString(h) {
		t.Error("returned sha mismatch")
	}
}

func TestEditCASSizeCap(t *testing.T) {
	root := newRoot(t)
	p := "e.txt"
	if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{MaxEditSize: 4}.fill()
	if _, err := EditCAS(root, p, "", []byte("012345"), cfg); err == nil {
		t.Fatal("expected error: content exceeds cap")
	}
}

func TestEditCASRejectsEscape(t *testing.T) {
	root := newRoot(t)
	if _, err := EditCAS(root, "../../etc/cron.d/evil", "", []byte("x"), Config{}); !errors.Is(err, ErrBadPath) {
		t.Errorf("escape: %v, want ErrBadPath", err)
	}
}

func TestSetPerm(t *testing.T) {
	root := newRoot(t)
	p := "perm.txt"
	if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetPerm(root, p, "0600", "", ""); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(filepath.Join(root, p))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	// Nothing to change.
	if err := SetPerm(root, p, "", "", ""); err == nil {
		t.Fatal("expected error: nothing to change")
	}
	// Bad mode.
	if err := SetPerm(root, p, "9999", "", ""); err == nil {
		t.Fatal("expected error for bad mode")
	}
}

// TestSetPermRejectsOwnership: the file surface is unprivileged; ownership
// changes are rejected even for root (no-escape invariant).
func TestSetPermRejectsOwnership(t *testing.T) {
	root := newRoot(t)
	p := "own.txt"
	if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetPerm(root, p, "", "root", ""); err == nil {
		t.Fatal("expected error: ownership change not allowed")
	}
	if err := SetPerm(root, p, "", "", "root"); err == nil {
		t.Fatal("expected error: ownership change not allowed")
	}
	if err := SetPerm(root, p, "0644", "root", ""); err == nil {
		t.Fatal("expected error: ownership change not allowed")
	}
}

func TestSetPermRejectsEscape(t *testing.T) {
	root := newRoot(t)
	if err := SetPerm(root, "../outside.txt", "0600", "", ""); !errors.Is(err, ErrBadPath) {
		t.Errorf("escape: %v, want ErrBadPath", err)
	}
}

func TestUploadRejectsSymlinkTarget(t *testing.T) {
	root := newRoot(t)
	real := filepath.Join(root, "real.txt")
	if err := os.WriteFile(real, []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.fill()
	if _, err := UploadBegin(root, "link.txt", 10, cfg); err == nil {
		t.Fatal("expected error: symlink target")
	}
}

func TestDownloadRejectsSymlink(t *testing.T) {
	root := newRoot(t)
	real := filepath.Join(root, "real.bin")
	if err := os.WriteFile(real, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.bin")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DownloadAt(root, "link.bin", 0, Config{}.fill()); err == nil {
		t.Fatal("expected error: symlink download")
	}
}

// ---- deprecated SafePath (absolute, non-root) ------------------------------

func TestSafePathStillWorksAbsolute(t *testing.T) {
	dir := t.TempDir()
	if _, err := SafePath("relative/path"); err == nil {
		t.Fatal("expected error for relative path")
	}
	if _, err := SafePath(filepath.Join(dir, "does-not-exist")); err != nil {
		t.Fatalf("missing final component should be allowed: %v", err)
	}
}
