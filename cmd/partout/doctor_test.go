package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/config"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Mode:   "server",
		Addr:   "127.0.0.1",
		Port:   1,
		DBPath: "/tmp/partout-doctor-test/partout.db",
	}
}

// claimPort binds a port and returns its number, so tests can assert the
// "port in use" path against a known-occupied port.
func claimPort(t *testing.T) int {
	t.Helper()
	la, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	t.Cleanup(func() { la.Close() })
	return la.Addr().(*net.TCPAddr).Port
}

func TestDoctorPortFree(t *testing.T) {
	// A port nothing else holds must pass.
	cfg := newTestConfig()
	cfg.Port = claimPort(t) // we hold it, so the doctor's own probe will fail
	cfg2 := newTestConfig()
	// Pick a free port by listening then closing.
	la, _ := net.Listen("tcp", "127.0.0.1:0")
	freePort := la.Addr().(*net.TCPAddr).Port
	la.Close()
	cfg2.Port = freePort

	r := &doctorResult{}
	checkPortFree(cfg2, r)
	if r.fails != 0 {
		t.Fatalf("free port should pass, got %d fail(s): %+v", r.fails, r.checks)
	}

	// A port we are holding must fail with the bind error.
	r2 := &doctorResult{}
	checkPortFree(cfg, r2)
	if r2.fails != 1 {
		t.Fatalf("occupied port should fail once, got %d", r2.fails)
	}
	found := false
	for _, c := range r2.checks {
		if c.level == dfail && strings.Contains(c.detail, "bind") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a bind failure, got %+v", r2.checks)
	}
}

func TestDoctorDBWritable(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestConfig()
	cfg.DBPath = filepath.Join(dir, "p.db")

	r := &doctorResult{}
	checkDBWritable(cfg, r)
	if r.fails != 0 {
		t.Fatalf("writable dir should pass, got %+v", r.checks)
	}

	// A non-existent parent dir must fail.
	cfg2 := newTestConfig()
	cfg2.DBPath = filepath.Join(t.TempDir(), "no-such-dir", "p.db")
	r2 := &doctorResult{}
	checkDBWritable(cfg2, r2)
	if r2.fails != 1 {
		t.Fatalf("missing dir should fail, got %+v", r2.checks)
	}
}

func TestDoctorSSHKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PARTOUT_SSH_DIR", dir)
	t.Setenv("SSH_AUTH_SOCK", "") // no agent: the no-file-key case must warn

	// No key yet -> warning.
	cfg := newTestConfig()
	r := &doctorResult{}
	checkSSHKey(cfg, r)
	if r.warns != 1 {
		t.Fatalf("no key should warn, got %+v", r.checks)
	}

	// Drop a conventional key -> passes and names it.
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2 := &doctorResult{}
	checkSSHKey(cfg, r2)
	if r2.fails != 0 || r2.warns != 0 {
		t.Fatalf("key present should pass cleanly, got %+v", r2.checks)
	}
	if len(r2.checks) != 1 || r2.checks[0].level != dok || !strings.Contains(r2.checks[0].detail, "id_ed25519") {
		t.Fatalf("should name the key, got %+v", r2.checks)
	}
}

func TestDoctorReleaseKey(t *testing.T) {
	cfg := newTestConfig()

	r := &doctorResult{}
	checkReleaseKey(cfg, r) // no key -> info, no fail
	if r.fails != 0 || r.warns != 0 {
		t.Fatalf("no release key is informational, got %+v", r.checks)
	}

	cfg.ReleaseKey = "c2ln"
	r2 := &doctorResult{}
	checkReleaseKey(cfg, r2)
	if r2.checks[0].level != dok {
		t.Fatalf("release key set should be ok, got %+v", r2.checks)
	}
}

func TestDoctorResultCounting(t *testing.T) {
	r := &doctorResult{}
	r.add(dok, "a", "")
	r.add(dwarn, "b", "")
	r.add(dfail, "c", "")
	if r.fails != 1 || r.warns != 1 {
		t.Fatalf("counts = fail %d warn %d, want 1/1", r.fails, r.warns)
	}
}
