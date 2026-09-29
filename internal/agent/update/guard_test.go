package update

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findGuardScript locates the systemd boot guard relative to this package.
func findGuardScript(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "deploy", "systemd", "partout-update-guard.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("guard script not found at %s: %v", p, err)
	}
	return p
}

// writeFakeBinary installs a stand-in partout binary that reports version
// for --version and appends "RAN <version>" to $GUARD_TEST_RAN when started.
func writeFakeBinary(t *testing.T, path, version string) {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--version" ]; then echo "partout %s"; exit 0; fi
echo "RAN %s" >> "$GUARD_TEST_RAN"
exit 0
`, version, version)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// runGuard invokes the boot guard with the given env overrides and returns
// its combined output.
func runGuard(t *testing.T, script, bin, dataDir, ranFile string) string {
	t.Helper()
	cmd := exec.Command("sh", script, "--mode=agent", "--data-dir", dataDir)
	cmd.Env = append(os.Environ(),
		"PARTOUT_GUARD_BIN="+bin,
		"PARTOUT_AGENT_DATA_DIR="+dataDir,
		"PARTOUT_UPDATE_HEALTH_S=60",
		"GUARD_TEST_RAN="+ranFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("guard: %v\n%s", err, out)
	}
	return string(out)
}

func writeMarkerFile(t *testing.T, path, target string, startedAgoS int, prev string) {
	t.Helper()
	content := fmt.Sprintf("target_version=%s\nrelease_id=rel_g\nprev_binary=%s\nstarted_at=%d\n",
		target, prev, time.Now().Unix()-int64(startedAgoS))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateGuardScript(t *testing.T) {
	script := findGuardScript(t)

	t.Run("no marker runs binary directly", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "partout")
		data := filepath.Join(dir, "data")
		ran := filepath.Join(dir, "ran")
		if err := os.MkdirAll(data, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFakeBinary(t, bin, "v9")
		runGuard(t, script, bin, data, ran)
		b, _ := os.ReadFile(ran)
		if !strings.Contains(string(b), "RAN v9") {
			t.Fatalf("binary did not run: %q", b)
		}
	})

	t.Run("fresh marker with matching version runs new binary", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "partout")
		data := filepath.Join(dir, "data")
		ran := filepath.Join(dir, "ran")
		os.MkdirAll(data, 0o755)
		writeFakeBinary(t, bin, "v9") // the NEW version is on disk
		marker := filepath.Join(data, "update.json")
		writeMarkerFile(t, marker, "v9", 10, filepath.Join(dir, "partout.old"))
		runGuard(t, script, bin, data, ran)
		b, _ := os.ReadFile(ran)
		if !strings.Contains(string(b), "RAN v9") {
			t.Fatalf("new binary did not run: %q", b)
		}
		// Marker must remain: the agent clears it on first connect.
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("marker should remain for the healthy new version: %v", err)
		}
	})

	t.Run("stale marker rolls back to N-1", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "partout")
		prev := filepath.Join(dir, "partout.old")
		data := filepath.Join(dir, "data")
		ran := filepath.Join(dir, "ran")
		os.MkdirAll(data, 0o755)
		writeFakeBinary(t, bin, "v9")  // broken new version on disk
		writeFakeBinary(t, prev, "v8") // retained N-1
		marker := filepath.Join(data, "update.json")
		writeMarkerFile(t, marker, "v9", 3600, prev) // stale (60s window + 120 grace long passed)
		out := runGuard(t, script, bin, data, ran)
		b, _ := os.ReadFile(ran)
		if !strings.Contains(string(b), "RAN v8") {
			t.Fatalf("N-1 did not run after rollback: %q (guard: %s)", b, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Error("marker should be cleared after rollback")
		}
		// The rolled-back binary on disk is now the N-1.
		if out2, _ := exec.Command(bin, "--version").CombinedOutput(); !strings.Contains(string(out2), "v8") {
			t.Errorf("on-disk binary after rollback = %q, want v8", out2)
		}
	})

	t.Run("version mismatch rolls back even when fresh", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "partout")
		prev := filepath.Join(dir, "partout.old")
		data := filepath.Join(dir, "data")
		ran := filepath.Join(dir, "ran")
		os.MkdirAll(data, 0o755)
		writeFakeBinary(t, bin, "v8")   // old binary running (partial swap)
		writeFakeBinary(t, prev, "v8b") // retained N-1
		marker := filepath.Join(data, "update.json")
		writeMarkerFile(t, marker, "v10", 5, prev) // fresh, but on-disk != target
		runGuard(t, script, bin, data, ran)
		b, _ := os.ReadFile(ran)
		if !strings.Contains(string(b), "RAN v8b") {
			t.Fatalf("N-1 did not run after mismatch rollback: %q", b)
		}
	})
}
