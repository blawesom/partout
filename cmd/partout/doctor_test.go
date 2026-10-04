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

func TestDoctorTLSPlainBind(t *testing.T) {
	// Loopback + TLS off: still informational (local dev posture).
	cfg := newTestConfig() // Addr 127.0.0.1
	r := &doctorResult{}
	checkTLS(cfg, r)
	if r.fails != 0 || r.warns != 0 {
		t.Fatalf("loopback + tls off should stay info, got %+v", r.checks)
	}
	if len(r.checks) != 1 || r.checks[0].level != dinfo {
		t.Fatalf("want one info check, got %+v", r.checks)
	}

	// All interfaces (the default, empty addr) + TLS off: warn — the admin
	// password and session tokens would cross the network in cleartext.
	for _, exposed := range []string{"", "0.0.0.0", "::", "203.0.113.7", "example.com"} {
		cfg2 := newTestConfig()
		cfg2.Addr = exposed
		r2 := &doctorResult{}
		checkTLS(cfg2, r2)
		if r2.warns != 1 || r2.fails != 0 {
			t.Fatalf("addr %q + tls off should warn exactly once, got %+v", exposed, r2.checks)
		}
		detail := r2.checks[0].detail
		// The warning must name both remedies so it is actionable.
		if !strings.Contains(detail, "PARTOUT_TLS") || !strings.Contains(detail, "PARTOUT_ADDR") {
			t.Fatalf("addr %q: warning should name PARTOUT_TLS and PARTOUT_ADDR remedies, got %q", exposed, detail)
		}
	}

	// Loopback spellings that must keep the quiet info level.
	for _, lo := range []string{"127.0.0.1", "::1", "localhost"} {
		cfg3 := newTestConfig()
		cfg3.Addr = lo
		r3 := &doctorResult{}
		checkTLS(cfg3, r3)
		if r3.warns != 0 {
			t.Fatalf("addr %q + tls off should not warn (loopback), got %+v", lo, r3.checks)
		}
	}

	// TLS on: unchanged path (SAN-name warnings), independent of the bind.
	cfgOn := newTestConfig()
	cfgOn.TLS = true
	cfgOn.Addr = ""
	rOn := &doctorResult{}
	checkTLS(cfgOn, rOn)
	if rOn.fails != 0 {
		t.Fatalf("tls on should never fail here, got %+v", rOn.checks)
	}
}

func TestLoopbackOnly(t *testing.T) {
	cases := map[string]bool{
		"":            false, // default = all interfaces
		"0.0.0.0":     false,
		"::":          false,
		"203.0.113.7": false,
		"example.com": false,
		"127.0.0.1":   true,
		"::1":         true,
		"localhost":   true, // RFC 6761 reserves it as loopback
		"Localhost":   true,
	}
	for addr, want := range cases {
		if got := loopbackOnly(addr); got != want {
			t.Errorf("loopbackOnly(%q) = %v, want %v", addr, got, want)
		}
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

// TestCheckProvisioningBind covers the loopback-bind diagnostic: a
// loopback-only bind can never be reached by a provisioned remote host, so
// doctor must warn (a routable or default bind must not).
func TestCheckProvisioningBind(t *testing.T) {
	cfg := newTestConfig() // Addr 127.0.0.1 from the helper
	cfg.ServerHost = "192.0.2.10"
	r := &doctorResult{}
	checkProvisioning(cfg, r)
	if r.warns == 0 {
		t.Fatalf("loopback bind should warn, got %+v", r.checks)
	}
	found := false
	for _, c := range r.checks {
		if c.name == "provision bind" && c.level == dwarn && strings.Contains(c.detail, "loopback") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a provision bind warning, got %+v", r.checks)
	}

	// A routable bind must not produce the provision-bind warning.
	cfg.Addr = "192.0.2.10"
	r2 := &doctorResult{}
	checkProvisioning(cfg, r2)
	for _, c := range r2.checks {
		if c.name == "provision bind" {
			t.Errorf("routable bind must not warn, got %+v", r2.checks)
		}
	}
}

// TestCheckProvisioningServerHost covers the resolution diagnostics for the
// address written into provisioned agents' PARTOUT_SERVER: it must resolve
// to something other targets can actually use.
func TestCheckProvisioningServerHost(t *testing.T) {
	cfg := newTestConfig()
	cfg.Addr = "192.0.2.10"

	// An explicitly-set IP needs no DNS and is OK.
	cfg.ServerHost = "192.0.2.10"
	r := &doctorResult{}
	checkProvisioning(cfg, r)
	ok := false
	for _, c := range r.checks {
		if c.name == "provision server host" && c.level == dok {
			ok = true
		}
	}
	if !ok {
		t.Errorf("explicit IP server host should be ok, got %+v", r.checks)
	}

	// A set-but-unresolvable host must warn.
	cfg.ServerHost = "no-such-host.invalid"
	r2 := &doctorResult{}
	checkProvisioning(cfg, r2)
	found := false
	for _, c := range r2.checks {
		if c.name == "provision server host" && c.level == dwarn && strings.Contains(c.detail, "resolve") {
			found = true
		}
	}
	if !found {
		t.Errorf("unresolvable server host should warn, got %+v", r2.checks)
	}
}

// TestCheckProvisioningTLSSAN covers the TLS x provisioning interaction:
// with TLS on, the host agents dial must be covered by the leaf SANs or
// provisioned agents fail certificate verification.
func TestCheckProvisioningTLSSAN(t *testing.T) {
	cfg := newTestConfig()
	cfg.Addr = "192.0.2.10"
	cfg.TLS = true
	cfg.ServerHost = "192.0.2.10"
	cfg.TLSNames = "partout.example.com"

	r := &doctorResult{}
	checkProvisioning(cfg, r)
	found := false
	for _, c := range r.checks {
		if c.name == "provision tls" && c.level == dwarn && strings.Contains(c.detail, "SAN") {
			found = true
		}
	}
	if !found {
		t.Errorf("uncovered server host should warn about SANs, got %+v", r.checks)
	}

	// Covered by an explicit SAN: no warning.
	cfg.ServerHost = "partout.example.com"
	r2 := &doctorResult{}
	checkProvisioning(cfg, r2)
	for _, c := range r2.checks {
		if c.name == "provision tls" {
			t.Errorf("covered server host must not warn, got %+v", r2.checks)
		}
	}
}

// TestDoctorFileRoot covers the agent file-root check (docs/spec-file-root.md):
// a usable root passes with its canonical path, a missing root warns with the
// create-it remedy (the agent creates it at startup only when the parent is
// writable — typical gap on hosts provisioned pre-0.9.5), and a symlink or
// non-writable root fails (the file surface would be disabled, fail closed).
func TestDoctorFileRoot(t *testing.T) {
	// Usable root: ok, canonical path in the detail.
	root := t.TempDir()
	cfg := newTestConfig()
	cfg.FileRoot = root
	r := &doctorResult{}
	checkFileRoot(cfg, r)
	if r.fails != 0 || r.warns != 0 {
		t.Fatalf("usable root should pass, got %+v", r.checks)
	}
	if len(r.checks) != 1 || !strings.Contains(r.checks[0].detail, root) {
		t.Fatalf("expected the canonical path in the detail, got %+v", r.checks)
	}

	// Missing root: warn with the mkdir/chown remedy, never a hard fail
	// (the agent may still create it itself).
	cfg2 := newTestConfig()
	cfg2.FileRoot = filepath.Join(t.TempDir(), "gone")
	r2 := &doctorResult{}
	checkFileRoot(cfg2, r2)
	if r2.fails != 0 || r2.warns != 1 {
		t.Fatalf("missing root should warn once, got %+v", r2.checks)
	}
	if !strings.Contains(r2.checks[0].detail, "mkdir -p") {
		t.Fatalf("missing-root warning must carry the remedy, got %+v", r2.checks)
	}

	// Symlink root: fail (the root must be a real directory).
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg3 := newTestConfig()
	cfg3.FileRoot = link
	r3 := &doctorResult{}
	checkFileRoot(cfg3, r3)
	if r3.fails != 1 || !strings.Contains(r3.checks[0].detail, "symlink") {
		t.Fatalf("symlink root must fail, got %+v", r3.checks)
	}

	// Read-only root: fail (fail closed at runtime).
	ro := t.TempDir()
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Skipf("cannot chmod (running as root?): %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	cfg4 := newTestConfig()
	cfg4.FileRoot = ro
	r4 := &doctorResult{}
	checkFileRoot(cfg4, r4)
	if r4.fails != 1 {
		t.Fatalf("read-only root must fail (as non-root), got %+v", r4.checks)
	}
}
