package fs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSafePathRejectsRelative(t *testing.T) {
	if _, err := SafePath("relative/path"); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestSafePathRejectsSymlinkComponents(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// Intermediate symlink component.
	if _, err := SafePath(filepath.Join(link, "file")); err == nil {
		t.Fatal("expected error for symlink intermediate component")
	}
	// Final component is a symlink.
	if _, err := SafePath(link); err == nil {
		t.Fatal("expected error for symlink final component")
	}
}

func TestSafePathAllowsMissingFinal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "does-not-exist")
	if _, err := SafePath(p); err != nil {
		t.Fatalf("missing final component should be allowed: %v", err)
	}
}

func TestSafePathRejectsNonDirectoryIntermediate(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SafePath(filepath.Join(file, "child")); err == nil {
		t.Fatal("expected error for non-directory intermediate")
	}
}

func TestStatPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hello.txt")
	content := []byte("hello world")
	if err := os.WriteFile(p, content, 0o640); err != nil {
		t.Fatal(err)
	}
	st, err := StatPath(p)
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

	// Directory.
	dst, err := StatPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !dst.IsDir {
		t.Error("IsDir should be true for a directory")
	}
	if dst.SHA256 != "" {
		t.Error("sha256 should be empty for a directory")
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	for i, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte{byte(i)}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, truncated, err := List(dir, Config{})
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
	entries, truncated, err = List(dir, Config{MaxListEntries: 2})
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
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := List(p, Config{}); err == nil {
		t.Fatal("expected error listing a file")
	}
}

func TestDownloadAt(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 1000)
	for i := range content {
		content[i] = byte(i % 251)
	}
	p := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{MaxChunk: 300}.fill()

	// First chunk.
	data, size, done, err := DownloadAt(p, 0, cfg)
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
		data, _, done, err := DownloadAt(p, off, cfg)
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
	data, _, done, err = DownloadAt(p, 1000, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !done || len(data) != 0 {
		t.Errorf("at end: done=%v len=%d, want done=true len=0", done, len(data))
	}

	// Offset beyond size.
	if _, _, _, err := DownloadAt(p, 2000, cfg); err == nil {
		t.Error("expected error for offset beyond size")
	}
}

func TestUploadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "upload.txt")
	content := make([]byte, 700)
	for i := range content {
		content[i] = byte('a' + i%26)
	}
	cfg := Config{}.fill()

	temp, err := UploadBegin(target, int64(len(content)), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

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
	gotSha, err := UploadCommit(temp, target, "0644", int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if gotSha != hex.EncodeToString(h[:]) {
		t.Errorf("committed sha = %s, want %s", gotSha, hex.EncodeToString(h[:]))
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Error("committed content mismatch")
	}
}

func TestUploadRejectsBadOffset(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x")
	cfg := Config{}.fill()
	temp, err := UploadBegin(target, 100, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)
	if _, err := UploadChunk(temp, 50, []byte("abc"), cfg); err == nil {
		t.Fatal("expected error for offset != current size")
	}
}

func TestUploadEnforcesSizeCap(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "big")
	cfg := Config{MaxTransfer: 100}.fill()
	if _, err := UploadBegin(target, 101, cfg); err == nil {
		t.Fatal("expected error: total size exceeds cap")
	}
	temp, err := UploadBegin(target, 100, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)
	if _, err := UploadChunk(temp, 0, make([]byte, 101), cfg); err == nil {
		t.Fatal("expected error: chunk would exceed cap")
	}
}

func TestUploadAbort(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "y")
	cfg := Config{}.fill()
	temp, err := UploadBegin(target, 10, cfg)
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
	other := filepath.Join(dir, "not-a-temp")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UploadAbort(other); err == nil {
		t.Fatal("expected error aborting non-temp file")
	}
}

func TestEditCAS(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "edit.txt")
	orig := []byte("version 1")
	if err := os.WriteFile(p, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.fill()

	origSha, _ := hashFile(p)
	origShaHex := hex.EncodeToString(origSha)

	// Wrong expected sha → conflict.
	if _, err := EditCAS(p, "deadbeef", []byte("v2"), cfg); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	// Correct expected sha → success.
	newSha, err := EditCAS(p, origShaHex, []byte("version 2"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "version 2" {
		t.Fatalf("content = %q", got)
	}
	h, _ := hashFile(p)
	if newSha != hex.EncodeToString(h) {
		t.Error("returned sha mismatch")
	}
}

func TestEditCASSizeCap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "e.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{MaxEditSize: 4}.fill()
	if _, err := EditCAS(p, "", []byte("012345"), cfg); err == nil {
		t.Fatal("expected error: content exceeds cap")
	}
}

func TestSetPerm(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "perm.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetPerm(p, "0600", "", ""); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(p)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	// Nothing to change.
	if err := SetPerm(p, "", "", ""); err == nil {
		t.Fatal("expected error: nothing to change")
	}
	// Bad mode.
	if err := SetPerm(p, "9999", "", ""); err == nil {
		t.Fatal("expected error for bad mode")
	}
	// Unknown user.
	if err := SetPerm(p, "", "no-such-user-xyz", ""); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestSetPermOwnership(t *testing.T) {
	// chown only works as root; skip otherwise.
	if syscall.Getuid() != 0 {
		t.Skip("chown requires root")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "own.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetPerm(p, "0644", "root", "root"); err != nil {
		t.Fatalf("SetPerm chown root:root: %v", err)
	}
}

func TestUploadRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(real, []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.fill()
	if _, err := UploadBegin(link, 10, cfg); err == nil {
		t.Fatal("expected error: symlink target")
	}
}

func TestDownloadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(real, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DownloadAt(link, 0, Config{}.fill()); err == nil {
		t.Fatal("expected error: symlink download")
	}
}
