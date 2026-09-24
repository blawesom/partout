// Package fs implements the agent-side file operations (PRD §5.3, arch §6.1):
// stat, list, chunked download, atomic upload, compare-and-swap edit, and
// permission changes.
//
// Path safety (PRD §7 "Path safety", D4 strict):
//
//   - Every path must be absolute.
//   - No path component (including the final one) may be a symlink; any
//     symlink anywhere in the path is rejected. This prevents symlink
//     traversal across the transfer boundary (a maliciously placed link
//     cannot redirect a transfer outside its apparent location).
//   - Intermediate components must exist and be real directories.
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

// StatPath returns file metadata for path. Symlinks are rejected (consistent
// with SafePath): callers pass already-validated paths, but this is a direct
// entry point so it re-checks.
func StatPath(path string) (*Stat, error) {
	clean, err := SafePath(path)
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
func List(dir string, cfg Config) ([]Entry, bool, error) {
	cfg = cfg.fill()
	clean, err := SafePath(dir)
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
func DownloadAt(path string, offset int64, cfg Config) ([]byte, int64, bool, error) {
	cfg = cfg.fill()
	clean, err := SafePath(path)
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
func UploadBegin(target string, totalSize int64, cfg Config) (string, error) {
	cfg = cfg.fill()
	if totalSize < 0 {
		return "", fmt.Errorf("fs: negative size %d", totalSize)
	}
	if totalSize > cfg.MaxTransfer {
		return "", fmt.Errorf("%w: transfer size %d exceeds cap %d", ErrCapExceeded, totalSize, cfg.MaxTransfer)
	}
	clean, err := SafePath(target)
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
func UploadCommit(tempPath, target, mode string, totalSize int64) (string, error) {
	if err := checkTemp(tempPath); err != nil {
		return "", err
	}
	cleanTarget, err := SafePath(target)
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
func EditCAS(path, expected string, content []byte, cfg Config) (string, error) {
	cfg = cfg.fill()
	if int64(len(content)) > cfg.MaxEditSize {
		return "", fmt.Errorf("%w: edit content %d bytes exceeds cap %d", ErrCapExceeded, len(content), cfg.MaxEditSize)
	}
	clean, err := SafePath(path)
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

// SetPerm applies mode (octal string) and/or owner/group changes to path.
// At least one of the three must be non-empty.
func SetPerm(path, mode, owner, group string) error {
	if mode == "" && owner == "" && group == "" {
		return errors.New("fs: nothing to change")
	}
	clean, err := SafePath(path)
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
	var m *os.FileMode
	if mode != "" {
		parsed, err := parseMode(mode)
		if err != nil {
			return err
		}
		m = &parsed
	}
	var uid, gid uint32
	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return fmt.Errorf("fs: user %q: %w", owner, err)
		}
		uid, err = parseUint(u.Uid)
		if err != nil {
			return fmt.Errorf("fs: user %q: %w", owner, err)
		}
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("fs: group %q: %w", group, err)
		}
		gid, err = parseUint(g.Gid)
		if err != nil {
			return fmt.Errorf("fs: group %q: %w", group, err)
		}
	}
	if m != nil {
		if err := os.Chmod(clean, *m); err != nil {
			return fmt.Errorf("fs: chmod: %w", err)
		}
	}
	if owner != "" || group != "" {
		// chown(2) semantics: Go's os.Chown only changes both, so pass the
		// current values for the unchanged side.
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("fs: chown unsupported on this platform")
		}
		if owner == "" {
			uid = st.Uid
		}
		if group == "" {
			gid = st.Gid
		}
		if err := os.Chown(clean, int(uid), int(gid)); err != nil {
			return fmt.Errorf("fs: chown: %w", err)
		}
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

func parseUint(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
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
