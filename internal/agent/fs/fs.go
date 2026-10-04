// Package fs implements the agent-side file operations (PRD §5.3, arch §6.1):
// stat, list, chunked download, atomic upload, compare-and-swap edit, and
// permission changes.
//
// File root (docs/spec-file-root.md): every path is root-relative and
// resolved against the file root (default /home/partout). The root gates
// WHERE operations can happen; role/policy gate WHAT. No caller — no role,
// flag, or parameter — can reach a path outside the root through this
// package. Outside-the-root file work is a command, not a file op.
//
// Path safety (PRD §7 "Path safety", D4 strict + the file root):
//
//   - No `..` component survives cleaning (traversal is rejected).
//   - No path component (including the final one) may be a symlink; any
//     symlink anywhere in the path is rejected. This prevents symlink
//     traversal across the transfer boundary (a maliciously placed link
//     cannot redirect a transfer outside its apparent location) — including
//     symlinks that would escape the root.
//   - Intermediate components must exist and be real directories.
//   - The fully resolved path is re-checked to be under the canonical root.
//
// Transfers are bounded: DefaultMaxTransfer (256 MiB) caps uploads and the
// per-chunk size is DefaultMaxChunk (256 KiB) (D3, env-configurable upstream).
// Uploads write to a sibling temp file and commit with an atomic rename.
// Edits are compare-and-swap on sha256 (PRD §5.3) with an atomic write.
package fs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultFileRoot is the hardcoded default file root. It is deliberately a
// fixed path, NOT derived from the agent user's home directory: on the
// standard server/embedded install that home is /var/lib/partout, which
// contains the database, the root CA, and the server identity — a
// home-derived default would expose that state to the file surface.
const DefaultFileRoot = "/home/partout"

// ErrRootUnavailable is returned when the file root is missing/unusable: the
// file surface is disabled (fail closed). The agent maps it to code 503.
var ErrRootUnavailable = errors.New("fs: file root unavailable")

// PrepareFileRoot canonicalizes the file root: applies the default, resolves
// symlinks in the parent chain, verifies the root is a real directory (no
// symlink), and creates it (0750) when missing. The returned path is the
// canonical root used for containment checks.
func PrepareFileRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		root = DefaultFileRoot
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("fs: file root: %w", err)
	}
	info, err := os.Lstat(abs)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("fs: file root %s: symlink not allowed", abs)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("fs: file root %s: not a directory", abs)
		}
		canonical, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return "", fmt.Errorf("fs: file root %s: %w", abs, err)
		}
		return canonical, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("fs: file root %s: %w", abs, err)
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return "", fmt.Errorf("fs: create file root %s: %w", abs, err)
	}
	info, err = os.Lstat(abs)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("fs: file root %s: not a directory after create", abs)
	}
	return abs, nil
}

// ResolvePath resolves a root-relative path against the canonical file root
// and returns the absolute path. It implements the spec-file-root
// resolution algorithm:
//
//  1. empty path = the root itself (allowed for stat/list);
//  2. Clean; reject any surviving `..` (traversal);
//  3. join onto the root and require the result to stay under it;
//  4. walk each existing component (Lstat): no symlink anywhere,
//     intermediate components must be real directories, the final component
//     may be missing (upload target) but must not be a symlink if present;
//  5. final containment re-check (defense in depth).
//
// A nil/empty root is always an error (fail closed).
func ResolvePath(root, path string) (string, error) {
	if root == "" {
		return "", ErrRootUnavailable
	}
	rel := strings.TrimPrefix(path, "/")
	rel = filepath.Clean(rel)
	switch rel {
	case ".", "":
		return root, nil // the root itself
	case "..":
		return "", fmt.Errorf("%w: path traversal", ErrBadPath)
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path traversal", ErrBadPath)
	}
	full := filepath.Join(root, rel)
	if r, err := filepath.Rel(root, full); err == nil && (r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator))) {
		return "", fmt.Errorf("%w: path escapes file root", ErrBadPath)
	}
	// Walk the components exactly as before (Lstat each; no symlink
	// components; real intermediate directories).
	parts := strings.Split(rel, string(filepath.Separator))
	prefix := root
	for i, p := range parts {
		prefix = filepath.Join(prefix, p)
		isFinal := i == len(parts)-1
		info, err := os.Lstat(prefix)
		if err != nil {
			if os.IsNotExist(err) {
				if isFinal {
					return full, nil // target may not exist yet (upload)
				}
				return "", fmt.Errorf("%w: missing intermediate directory", ErrBadPath)
			}
			return "", fmt.Errorf("fs: %s: %w", prefix, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: symlink not allowed in path: %s", ErrBadPath, p)
		}
		if !isFinal && !info.IsDir() {
			return "", fmt.Errorf("%w: not a directory: %s", ErrBadPath, p)
		}
	}
	return full, nil
}

// Proposed defaults (D3), env-configurable via the server.
const (
	DefaultMaxTransfer    int64 = 256 << 20 // 256 MiB max upload
	DefaultMaxChunk       int64 = 256 << 10 // 256 KiB per chunk
	DefaultMaxListEntries       = 2048      // directory listing cap
	DefaultMaxEditSize    int64 = 1 << 20   // 1 MiB — CAS edits are for small text files
)

// Suffix on agent-side upload temp files (same directory as the target).
const tempSuffix = ".partout-tmp-"

// Config bounds the operations. Zero values select the defaults.
type Config struct {
	MaxTransfer    int64
	MaxChunk       int64
	MaxListEntries int
	MaxEditSize    int64
}

func (c Config) fill() Config {
	if c.MaxTransfer <= 0 {
		c.MaxTransfer = DefaultMaxTransfer
	}
	if c.MaxChunk <= 0 {
		c.MaxChunk = DefaultMaxChunk
	}
	if c.MaxListEntries <= 0 {
		c.MaxListEntries = DefaultMaxListEntries
	}
	if c.MaxEditSize <= 0 {
		c.MaxEditSize = DefaultMaxEditSize
	}
	return c
}

// Config returns the filled-in config.
func (c Config) Filled() Config { return c.fill() }

// SafePath validates path against the transfer path-safety rules and returns
// the cleaned path. It requires an absolute path, rejects any symlink
// component, and requires intermediate components to be real directories.
// The final component may be missing (an upload target) but must not be a
// symlink if it exists.
//
// Deprecated: kept for the few non-file-surface callers (tests, tooling).
// The file surface uses ResolvePath (file root). New code must take a root.
func SafePath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: path must be absolute", ErrBadPath)
	}
	clean := filepath.Clean(path)
	parts := strings.Split(clean, string(filepath.Separator))
	prefix := ""
	for i, p := range parts {
		if p == "" {
			continue // leading separator of an absolute path
		}
		prefix += string(filepath.Separator) + p
		isFinal := i == len(parts)-1
		info, err := os.Lstat(prefix)
		if err != nil {
			if os.IsNotExist(err) {
				if isFinal {
					return clean, nil // target may not exist yet (upload)
				}
				return "", fmt.Errorf("fs: %w", err)
			}
			return "", fmt.Errorf("fs: %s: %w", prefix, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: symlink not allowed in path: %s", ErrBadPath, prefix)
		}
		if !isFinal && !info.IsDir() {
			return "", fmt.Errorf("%w: not a directory: %s", ErrBadPath, prefix)
		}
	}
	return clean, nil
}

// Stat is the result of a stat request (PRD §5.3: mode, owner, group, size,
// mtime, sha256).
type Stat struct {
	Size      int64
	Mode      string // octal, e.g. "0644"
	Owner     string
	Group     string
	MtimeUnix int64
	SHA256    string // regular files only; "" otherwise
	IsDir     bool
	IsSymlink bool
}

// StatPath returns file metadata for path (root-relative; the file root
// gates where). Symlinks are rejected (consistent with ResolvePath).
func StatPath(root, path string) (*Stat, error) {
	clean, err := ResolvePath(root, path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	st := &Stat{
		Size:      info.Size(),
		Mode:      fmt.Sprintf("%04o", info.Mode().Perm()),
		MtimeUnix: info.ModTime().Unix(),
		IsDir:     info.IsDir(),
		IsSymlink: info.Mode()&os.ModeSymlink != 0,
	}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		if u, err := user.LookupId(strconv.FormatUint(uint64(sys.Uid), 10)); err == nil {
			st.Owner = u.Username
		} else {
			st.Owner = strconv.FormatUint(uint64(sys.Uid), 10)
		}
		if g, err := user.LookupGroupId(strconv.FormatUint(uint64(sys.Gid), 10)); err == nil {
			st.Group = g.Name
		} else {
			st.Group = strconv.FormatUint(uint64(sys.Gid), 10)
		}
	}
	if info.Mode().IsRegular() {
		h, err := hashFile(clean)
		if err != nil {
			return nil, fmt.Errorf("fs: stat hash: %w", err)
		}
		st.SHA256 = hex.EncodeToString(h)
	}
	return st, nil
}

// Entry is one directory listing row.
type Entry struct {
	Name      string
	IsDir     bool
	IsSymlink bool
	Size      int64
	MtimeUnix int64
	Mode      string
}

// List returns up to cfg.MaxListEntries directory entries (sorted by name,
// as ReadDir provides). truncated is true when the directory holds more.
func List(root, dir string, cfg Config) ([]Entry, bool, error) {
	cfg = cfg.fill()
	clean, err := ResolvePath(root, dir)
	if err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("fs: not a directory: %s", clean)
	}
	infos, err := os.ReadDir(clean)
	if err != nil {
		return nil, false, fmt.Errorf("fs: %w", err)
	}
	truncated := len(infos) > cfg.MaxListEntries
	if truncated {
		infos = infos[:cfg.MaxListEntries]
	}
	out := make([]Entry, 0, len(infos))
	for _, e := range infos {
		fi, err := e.Info()
		if err != nil {
			continue // entry vanished mid-list
		}
		out = append(out, Entry{
			Name:      e.Name(),
			IsDir:     e.IsDir(),
			IsSymlink: fi.Mode()&os.ModeSymlink != 0,
			Size:      fi.Size(),
			MtimeUnix: fi.ModTime().Unix(),
			Mode:      fmt.Sprintf("%04o", fi.Mode().Perm()),
		})
	}
	return out, truncated, nil
}

// DownloadAt reads up to cfg.MaxChunk bytes of path starting at offset.
// done is true when there is no more data after this chunk.
func DownloadAt(root, path string, offset int64, cfg Config) ([]byte, int64, bool, error) {
	cfg = cfg.fill()
	clean, err := ResolvePath(root, path)
	if err != nil {
		return nil, 0, false, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, false, fmt.Errorf("fs: not a regular file: %s", clean)
	}
	size := info.Size()
	if offset < 0 || offset > size {
		return nil, size, true, fmt.Errorf("fs: offset %d out of range (size %d)", offset, size)
	}
	if offset == size {
		return nil, size, true, nil
	}
	// O_NOFOLLOW as a belt-and-braces guard against a symlink swap between
	// SafePath and open (TOCTOU).
	f, err := os.OpenFile(clean, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, size, false, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, size, false, err
	}
	buf := make([]byte, cfg.MaxChunk)
	n, err := f.Read(buf)
	if n > 0 {
		buf = buf[:n]
	}
	if err == io.EOF || err == nil {
		return buf, size, offset+int64(n) >= size, nil
	}
	return buf, size, false, err
}

// UploadBegin creates the upload temp file (same directory as the target, so
// the commit rename is atomic on the same filesystem). It enforces the
// transfer size cap up front. Returns the absolute temp path.

// resolvePathForUpload is ResolvePath with upload semantics: missing
// INTERMEDIATE directories are created (mkdir -p, 0755, confined to the
// file root, no symlink components) rather than rejected — the file
// surface has no separate mkdir op, so a nested upload would otherwise be
// impossible (field feedback F19). The final component may not exist.
func resolvePathForUpload(root, path string) (string, error) {
	if root == "" {
		return "", ErrRootUnavailable
	}
	rel := strings.TrimPrefix(path, "/")
	rel = filepath.Clean(rel)
	switch rel {
	case ".", "":
		return root, nil
	case "..":
		return "", fmt.Errorf("%w: path traversal", ErrBadPath)
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path traversal", ErrBadPath)
	}
	full := filepath.Join(root, rel)
	if r, err := filepath.Rel(root, full); err == nil && (r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator))) {
		return "", fmt.Errorf("%w: path escapes file root", ErrBadPath)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	prefix := root
	for i, p := range parts {
		prefix = filepath.Join(prefix, p)
		isFinal := i == len(parts)-1
		info, err := os.Lstat(prefix)
		if os.IsNotExist(err) {
			if isFinal {
				return full, nil // target may not exist yet (upload)
			}
			// Create the missing intermediate directory (upload semantics).
			if err := os.Mkdir(prefix, 0o755); err != nil {
				return "", fmt.Errorf("fs: mkdir %s: %w", prefix, err)
			}
			continue
		}
		if err != nil {
			return "", fmt.Errorf("fs: %s: %w", prefix, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: symlink not allowed in path: %s", ErrBadPath, p)
		}
		if !isFinal && !info.IsDir() {
			return "", fmt.Errorf("%w: not a directory: %s", ErrBadPath, p)
		}
	}
	return full, nil
}

func UploadBegin(root, target string, totalSize int64, cfg Config) (string, error) {
	cfg = cfg.fill()
	if totalSize < 0 {
		return "", fmt.Errorf("fs: negative size %d", totalSize)
	}
	if totalSize > cfg.MaxTransfer {
		return "", fmt.Errorf("%w: transfer size %d exceeds cap %d", ErrCapExceeded, totalSize, cfg.MaxTransfer)
	}
	clean, err := resolvePathForUpload(root, target)
	if err != nil {
		return "", err
	}
	// If the target exists it must not be a symlink (SafePath covers this) —
	// commit will atomically replace it.
	name := filepath.Base(clean) + tempSuffix + randHex(8)
	tempPath := filepath.Join(filepath.Dir(clean), name)
	f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("fs: create temp: %w", err)
	}
	return tempPath, f.Close()
}

// UploadChunk appends data to the upload temp at exactly offset (strict
// in-order: offset must equal the current temp size). Enforces the transfer
// size cap. Returns the cumulative byte count.
func UploadChunk(tempPath string, offset int64, data []byte, cfg Config) (int64, error) {
	cfg = cfg.fill()
	if offset < 0 || len(data) == 0 {
		return 0, fmt.Errorf("fs: bad chunk (offset %d, len %d)", offset, len(data))
	}
	if err := checkTemp(tempPath); err != nil {
		return 0, err
	}
	info, err := os.Lstat(tempPath)
	if err != nil {
		return 0, err
	}
	if offset != info.Size() {
		return 0, fmt.Errorf("fs: chunk offset %d != current size %d", offset, info.Size())
	}
	if info.Size()+int64(len(data)) > cfg.MaxTransfer {
		return 0, fmt.Errorf("%w: transfer would exceed cap %d", ErrCapExceeded, cfg.MaxTransfer)
	}
	f, err := os.OpenFile(tempPath, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.WriteAt(data, offset); err != nil {
		return 0, err
	}
	return info.Size() + int64(len(data)), nil
}

// UploadCommit verifies the total size, applies the requested mode, and
// atomically renames the temp over the target. Returns the sha256 of the
// committed file.
func UploadCommit(root, tempPath, target, mode string, totalSize int64) (string, error) {
	if err := checkTemp(tempPath); err != nil {
		return "", err
	}
	cleanTarget, err := ResolvePath(root, target)
	if err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	if filepath.Dir(tempPath) != filepath.Dir(cleanTarget) {
		_ = os.Remove(tempPath)
		return "", errors.New("fs: temp and target are in different directories")
	}
	info, err := os.Lstat(tempPath)
	if err != nil {
		return "", err
	}
	if totalSize > 0 && info.Size() != totalSize {
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("fs: committed size %d != expected %d", info.Size(), totalSize)
	}
	if mode != "" {
		m, err := parseMode(mode)
		if err != nil {
			_ = os.Remove(tempPath)
			return "", err
		}
		if err := os.Chmod(tempPath, m); err != nil {
			_ = os.Remove(tempPath)
			return "", fmt.Errorf("fs: chmod: %w", err)
		}
	}
	if err := os.Rename(tempPath, cleanTarget); err != nil {
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("fs: rename: %w", err)
	}
	h, err := hashFile(cleanTarget)
	if err != nil {
		return "", fmt.Errorf("fs: hash: %w", err)
	}
	return hex.EncodeToString(h), nil
}

// UploadAbort removes an upload temp file (only files carrying the agent
// temp suffix are removable — defense against a forged temp path).
func UploadAbort(tempPath string) error {
	if err := checkTemp(tempPath); err != nil {
		return err
	}
	return os.Remove(tempPath)
}

// ErrConflict is returned by EditCAS when the file's current sha256 does not
// match expected.
var ErrConflict = errors.New("fs: checksum mismatch (file changed)")

// ErrBadPath is wrapped when a path violates the transfer path-safety rules
// (not absolute, symlink component, or non-directory intermediate). The
// agent maps it to FileOpResult code 400.
var ErrBadPath = errors.New("fs: bad path")

// ErrCapExceeded is wrapped when a transfer would exceed the configured size
// cap. The agent maps it to FileOpResult code 413.
var ErrCapExceeded = errors.New("fs: size cap exceeded")

// EditCAS atomically rewrites path's content when its current sha256 equals
// expected (an empty expected skips the check — but callers always send the
// observed sha). Content is bounded by cfg.MaxEditSize (small text files).
// Returns the new sha256.
func EditCAS(root, path, expected string, content []byte, cfg Config) (string, error) {
	cfg = cfg.fill()
	if int64(len(content)) > cfg.MaxEditSize {
		return "", fmt.Errorf("%w: edit content %d bytes exceeds cap %d", ErrCapExceeded, len(content), cfg.MaxEditSize)
	}
	clean, err := ResolvePath(root, path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("fs: not a regular file: %s", clean)
	}
	cur, err := hashFile(clean)
	if err != nil {
		return "", fmt.Errorf("fs: hash: %w", err)
	}
	if expected != "" && !strings.EqualFold(expected, hex.EncodeToString(cur)) {
		return "", ErrConflict
	}
	tmp := clean + tempSuffix + randHex(8)
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return "", fmt.Errorf("fs: write: %w", err)
	}
	// Preserve the original mode.
	if err := os.Chmod(tmp, info.Mode().Perm()); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, clean); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("fs: rename: %w", err)
	}
	h, err := hashFile(clean)
	if err != nil {
		return "", fmt.Errorf("fs: hash: %w", err)
	}
	return hex.EncodeToString(h), nil
}

// SetPerm applies a mode change to path (root-relative; the file root gates
// where). Ownership changes are rejected: inside the file root the agent
// user owns everything, so mode is all that is needed (the file surface is
// unprivileged by design — the no-escape invariant, docs/spec-file-root.md).
func SetPerm(root, path, mode, owner, group string) error {
	if owner != "" || group != "" {
		return errors.New("fs: ownership changes are not allowed inside the file root (mode changes only)")
	}
	if mode == "" {
		return errors.New("fs: nothing to change")
	}
	clean, err := ResolvePath(root, path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("fs: symlink not allowed: %s", clean)
	}
	parsed, err := parseMode(mode)
	if err != nil {
		return err
	}
	if err := os.Chmod(clean, parsed); err != nil {
		return fmt.Errorf("fs: chmod: %w", err)
	}
	return nil
}

// ---- internals -------------------------------------------------------------

func checkTemp(tempPath string) error {
	base := filepath.Base(tempPath)
	if !strings.Contains(base, tempSuffix) {
		return fmt.Errorf("fs: not an upload temp file: %s", base)
	}
	return nil
}

func parseMode(s string) (os.FileMode, error) {
	// Accept "0644" or "644".
	t := strings.TrimPrefix(s, "0")
	v, err := strconv.ParseUint(t, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("fs: bad octal mode %q", s)
	}
	return os.FileMode(v), nil
}

func hashFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}
