package embedded

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestUpdateGuardMatchesRepo pins the embedded guard to the repo's
// deploy/systemd source of truth — the two must never drift (the manual
// install path ships the repo copy; provisioning ships the embedded one).
func TestUpdateGuardMatchesRepo(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))), "deploy", "systemd", "partout-update-guard.sh")
	repoCopy, err := os.ReadFile(repo)
	if err != nil {
		t.Fatalf("read repo guard: %v", err)
	}
	if string(repoCopy) != UpdateGuard {
		t.Fatal("embedded partout-update-guard.sh differs from deploy/systemd/partout-update-guard.sh — copy the repo file into embedded/ (both paths install it)")
	}
}
