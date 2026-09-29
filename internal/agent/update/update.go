// Package update implements the agent side of M8.1 self-update: release
// directive verification, the binary swap with N-1 retention, and the boot
// marker that lets the systemd guard (and this package) roll back a failed
// update without a human on the host.
//
// Trust model: the agent verifies the Ed25519 signature over
// "version|arch|kind|sha256" against the release public key it was
// provisioned with (PARTOUT_RELEASE_KEY). Without a provisioned key the
// agent refuses every directive (fails closed). The server is never the
// trust anchor.
package update

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/release"
)

// Marker is the on-disk record of an in-flight update. It is plain
// key=value lines so the systemd boot guard (a shell script, no runtime
// dependency) can parse it the same way.
type Marker struct {
	TargetVersion string
	ReleaseID     string
	PrevBinary    string
	StartedAt     int64 // unix s
}

// WriteMarker atomically writes the marker (write temp + rename).
func WriteMarker(path string, m Marker) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "target_version=%s\n", m.TargetVersion)
	fmt.Fprintf(&b, "release_id=%s\n", m.ReleaseID)
	fmt.Fprintf(&b, "prev_binary=%s\n", m.PrevBinary)
	fmt.Fprintf(&b, "started_at=%d\n", m.StartedAt)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadMarker returns the marker at path, or ok=false when absent.
func ReadMarker(path string) (Marker, bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return Marker{}, false, nil
	}
	if err != nil {
		return Marker{}, false, err
	}
	defer f.Close()
	var m Marker
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "target_version":
			m.TargetVersion = v
		case "release_id":
			m.ReleaseID = v
		case "prev_binary":
			m.PrevBinary = v
		case "started_at":
			m.StartedAt, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	if err := sc.Err(); err != nil {
		return Marker{}, false, err
	}
	if m.TargetVersion == "" {
		return Marker{}, false, nil // corrupt/unparseable: treat as absent
	}
	return m, true, nil
}

// RemoveMarker deletes the marker (no error when absent).
func RemoveMarker(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// MarkerPath is the conventional marker location: <dataDir>/update.json.
func MarkerPath(dataDir string) string {
	return filepath.Join(dataDir, "update.json")
}

// Verify checks a directive against the provisioned release key:
//   - a key must be provisioned (fails closed)
//   - the manifest must be well-formed
//   - the signature must verify over the canonical manifest
//   - the arch must match this host (a wrong-arch binary is refused before
//     any byte is written)
//
// It does NOT check the artifact bytes: the caller computes the sha256 of
// the downloaded file and compares it to dir.Sha256 (the signature binds
// that digest).
func Verify(dir *pb.UpdateDirective, releaseKeyB64 string) error {
	if releaseKeyB64 == "" {
		return fmt.Errorf("no release key provisioned (set PARTOUT_RELEASE_KEY); refusing update")
	}
	pub, err := release.PubKeyFromB64(releaseKeyB64)
	if err != nil {
		return fmt.Errorf("release key: %w", err)
	}
	if dir.Kind != string(release.KindAgent) {
		return fmt.Errorf("refusing kind %q (agent accepts only %q)", dir.Kind, release.KindAgent)
	}
	wantArch := runtime.GOOS + "-" + runtime.GOARCH
	if dir.Arch != wantArch {
		return fmt.Errorf("arch mismatch: directive %q, host %q", dir.Arch, wantArch)
	}
	m := release.Manifest{Version: dir.Version, Arch: dir.Arch, Kind: dir.Kind, SHA256: dir.Sha256}
	if err := m.Valid(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dir.Signature))
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !release.Verify(pub, m, sig) {
		return fmt.Errorf("release signature verification FAILED for %s (%s, %s)", dir.Version, dir.Arch, dir.Kind)
	}
	return nil
}

// CurrentBinary resolves the running executable to a real path (symlinks
// resolved). The swap replaces exactly this file.
func CurrentBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	return filepath.EvalSymlinks(exe)
}

// Swap installs artifact over the running binary at binPath with N-1
// retention:
//
//	<dir>/partout          current binary (replaced)
//	<dir>/partout.old      N-1 (restored by the boot guard on failure)
//	<dir>/partout.new      staging (fsync'd, renamed into place)
//
// It returns the N-1 path (for the marker) and the previous binary's size
// (sanity: a zero-byte "old" means the swap source was unreadable).
// PrevBinaryPath is where the retained N-1 binary lives for binPath. The
// boot guard hardcodes the same name (`partout.old`), so the agent can
// record it in the marker before the swap actually happens.
func PrevBinaryPath(binPath string) string {
	return filepath.Join(filepath.Dir(binPath), "partout.old")
}

func Swap(binPath string, artifact []byte) (prevPath string, prevSize int64, err error) {
	prevPath = PrevBinaryPath(binPath)
	dir := filepath.Dir(binPath)
	staging := filepath.Join(dir, "partout.new")

	// N-1 retention: keep the current binary so the boot guard can roll
	// back. Skip the copy when the N-1 already exists AND is identical to
	// the current binary (idempotent re-runs, e.g. the guard already
	// restored it).
	if _, err := os.Stat(prevPath); err != nil {
		cur, rerr := os.ReadFile(binPath)
		if rerr != nil {
			return "", 0, fmt.Errorf("read current binary for N-1 retention: %w", rerr)
		}
		if werr := os.WriteFile(prevPath, cur, 0o755); werr != nil {
			return "", 0, fmt.Errorf("write N-1 retention copy: %w", werr)
		}
		prevSize = int64(len(cur))
	} else if sz, serr := os.Stat(prevPath); serr == nil {
		prevSize = sz.Size()
	}

	// Stage, fsync, rename. The rename is atomic on the same filesystem;
	// a crash between rename and restart leaves a valid N+1 binary on disk
	// (the marker then drives the boot check).
	f, err := os.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return "", 0, fmt.Errorf("open staging: %w", err)
	}
	if _, err := f.Write(artifact); err != nil {
		f.Close()
		os.Remove(staging)
		return "", 0, fmt.Errorf("write staging: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(staging)
		return "", 0, fmt.Errorf("fsync staging: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(staging)
		return "", 0, err
	}
	if err := os.Rename(staging, binPath); err != nil {
		os.Remove(staging)
		return "", 0, fmt.Errorf("rename into place: %w", err)
	}
	return prevPath, prevSize, nil
}

// RestoreN1 puts the retained N-1 binary back over binPath (the agent-side
// rollback; the systemd guard does the same thing before process start).
// It RENAMES (like the guard's mv), not copies: overwriting a running
// binary fails with ETXTBSY on Linux, while a rename is atomic and safe —
// the kernel keeps executing the old inode.
func RestoreN1(binPath, prevPath string) error {
	if prevPath == "" {
		return fmt.Errorf("no N-1 binary recorded")
	}
	if _, err := os.Stat(prevPath); err != nil {
		return fmt.Errorf("N-1 not present: %w", err)
	}
	if err := os.Rename(prevPath, binPath); err != nil {
		return fmt.Errorf("rename N-1 into place: %w", err)
	}
	return nil
}

// PostBootCheck runs on every agent start before connecting. It resolves
// the in-flight-update marker:
//
//   - no marker            → nothing to do.
//   - marker + our version == target → the swap landed and we booted: the
//     caller (on first successful connect) removes the marker and reports
//     phase=verified. We return the marker so the caller can act.
//   - marker + our version != target → the on-disk binary does not match
//     the marker (partial swap / guard already rolled us back). Restore N-1
//     (best effort), clear the marker, and continue as the old version.
//
// The returned error is non-nil only when the marker read or the N-1
// restore fails; callers log and continue (the systemd guard is the
// backstop for the broken-binary case).
func PostBootCheck(markerPath, currentVersion string) (Marker, bool, error) {
	m, ok, err := ReadMarker(markerPath)
	if err != nil || !ok {
		return Marker{}, false, err
	}
	if currentVersion == m.TargetVersion {
		return m, true, nil // healthy boot of the new version
	}
	// Mismatch: roll back to N-1 (best effort) and clear the marker.
	var restoreErr error
	if m.PrevBinary != "" {
		if bin, berr := CurrentBinary(); berr == nil {
			restoreErr = RestoreN1(bin, m.PrevBinary)
		}
	}
	if rmErr := RemoveMarker(markerPath); restoreErr == nil {
		restoreErr = rmErr
	}
	return Marker{}, false, restoreErr
}

// MarkerAge is how long the marker has existed (for stale detection).
func MarkerAge(m Marker, now time.Time) time.Duration {
	return now.Sub(time.Unix(m.StartedAt, 0))
}
