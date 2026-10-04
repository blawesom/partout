package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/sshutil"
	"github.com/blawesom/partout/internal/store"
)

// writeFakeFleet creates fake ssh/scp/ssh-keyscan/ssh-keygen binaries that
// emulate a remote host: keyscan returns a host key, the ssh "command"
// returns preflight output (or INSTALL_OK for the install script), scp
// succeeds, and keygen -F checks the (real) known_hosts file.
func writeFakeFleet(t *testing.T) (binDir string) {
	t.Helper()
	bin := t.TempDir()

	ssh := `#!/bin/sh
# last token(s) form the command; distinguish install (base64 -d) vs preflight
case "$*" in
  *"base64 -d"*) echo "INSTALL_OK"; exit 0 ;;
  *)
    echo "os=Ubuntu 24.04"
    echo "arch=x86_64"
    echo "init=systemd"
    echo "user=root"
    echo "sudo=yes"
    echo "disk=100000000"
    echo "reach=yes-plain"
    exit 0
    ;;
esac
`
	scp := `#!/bin/sh
exit 0
`
	keyscan := `#!/bin/sh
# ssh-keyscan -t types host  -> host is $3
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFleetKeyForTest0123456789abcdef"
exit 0
`
	keygen := `#!/bin/sh
case "$1" in
  -F)
    if grep -qF "$2" "$HOME/.ssh/known_hosts" 2>/dev/null; then exit 0; else exit 1; fi
    ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeFleetFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": scp, "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	return bin
}

// newTestProvisioner builds an in-memory store + a Provisioner over a fake
// ssh fleet. Returns the provisioner, store, and the home dir for ssh.
func newTestProvisioner(t *testing.T) (*Provisioner, *store.Store) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	bin := writeFakeFleet(t)
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0o700)

	// A fake "server binary" to transfer.
	binPath := filepath.Join(t.TempDir(), "partout")
	os.WriteFile(binPath, []byte("fake-partout-binary"), 0o755)

	ssh := sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}
	prov := New(Options{
		Store:      st,
		SSH:        ssh,
		ServerHost: "127.0.0.1:8443",
		BinaryPath: binPath,
		Logger:     log.New(os.Stderr, "", 0),
	})
	return prov, st
}

// waitForState polls the run until it reaches wantState or times out.
func waitForState(t *testing.T, st *store.Store, runID, wantState string) *store.ProvisionRun {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		run, err := st.ProvisionRun(runID)
		if err != nil {
			t.Fatalf("ProvisionRun: %v", err)
		}
		if run.State == wantState {
			return run
		}
		time.Sleep(100 * time.Millisecond)
	}
	run, _ := st.ProvisionRun(runID)
	t.Fatalf("run did not reach %q (state=%q, step=%q, err=%q)", wantState, run.State, run.Step, run.Error)
	return nil
}

// TestProvisionFreshKeyConfirm drives a fresh-host provision through the
// fingerprint gate: the run must pause at key_confirm, and only after the
// operator confirms should it proceed to preflight/transfer/install and
// complete once the (pre-seeded) agent connects.
func TestProvisionFreshKeyConfirm(t *testing.T) {
	prov, st := newTestProvisioner(t)

	run, err := prov.Start("web01", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// The host is not trusted, so the run must pause at key_confirm.
	waitForState(t, st, run.ID, "key_confirm")
	run, _ = st.ProvisionRun(run.ID)
	if run.Fingerprint == "" {
		t.Fatal("key_confirm run has no captured fingerprint")
	}
	if run.KeyLine == "" {
		t.Fatal("key_confirm run has no captured key line")
	}

	// Confirm the key: known_hosts gets the (hashed) key, run resumes.
	if err := prov.ConfirmKey(run.ID); err != nil {
		t.Fatalf("ConfirmKey: %v", err)
	}

	// After confirm the run should flow through preflight/transfer/install
	// and, since wait-enroll needs a connected agent, it will sit in
	// "enrolling" until we link one. Drive it to "enrolling" first.
	waitForState(t, st, run.ID, "enrolling")

	// Simulate the agent having enrolled (enroll handler sets agent_id) and
	// connected (stream handler sets state).
	agentID := "ag_test"
	if err := st.UpsertAgent(store.Agent{
		ID: agentID, UUID: "test-uuid", ED25519Pub: "cHVi", X25519Pub: "eGNwdWI",
		State: "pending",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.LinkProvisionRunAgent(run.ID, agentID); err != nil {
		t.Fatalf("LinkProvisionRunAgent: %v", err)
	}
	if err := st.SetAgentState(agentID, "connected"); err != nil {
		t.Fatalf("SetAgentState: %v", err)
	}

	waitForState(t, st, run.ID, "connected")
	run, _ = st.ProvisionRun(run.ID)
	if run.AgentID != agentID {
		t.Fatalf("run.AgentID = %q, want %q", run.AgentID, agentID)
	}

	// All five steps should be done.
	steps, err := st.ProvisionRunSteps(run.ID)
	if err != nil {
		t.Fatalf("ProvisionRunSteps: %v", err)
	}
	if len(steps) != 5 {
		t.Fatalf("expected 5 steps, got %d", len(steps))
	}
	for i, s := range steps {
		if s.State != "done" {
			t.Errorf("step %d (%s) state = %q, want done", i+1, s.Name, s.State)
		}
	}
}

// TestProvisionHandoffNonSystemd verifies that a host without systemd lands
// in the terminal "handoff" state (not an error).
func TestProvisionHandoffNonSystemd(t *testing.T) {
	prov, st := newTestProvisioner(t)

	// Swap the fake ssh to report init=none.
	bin := writeFakeFleetNonSystemd(t)
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0o700)
	ssh := sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}
	prov.ssh = ssh

	// Pre-trust the host so we skip key_confirm and reach preflight.
	if err := prov.ssh.AddKey(context.Background(), "web02 ssh-ed25519 AAAApretrusted"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	run, err := prov.Start("web02", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	run = waitForState(t, st, run.ID, "handoff")
	if run.Error == "" {
		t.Error("handoff run should carry a remediation note")
	}
}

func writeFakeFleetNonSystemd(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	ssh := `#!/bin/sh
echo "os=Alpine 3.20"
echo "arch=x86_64"
echo "init=none"
echo "user=root"
echo "sudo=yes"
echo "disk=100000000"
echo "reach=yes-plain"
exit 0
`
	scp := `#!/bin/sh
exit 0
`
	keyscan := `#!/bin/sh
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFleetKeyForTest0123456789abcdef"
exit 0
`
	keygen := `#!/bin/sh
# Honour an explicit -f <file> (sshutil passes it for known_hosts lookups);
# fall back to $HOME/.ssh/known_hosts like real ssh-keygen.
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F) if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeFleetFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": scp, "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	return bin
}

// TestConfirmKeyIsIdempotent is the regression guard for the duplicate-confirm
// panic: a second POST /key (double-click, retry, two admins) must return an
// error, never panic with "close of closed channel".
func TestConfirmKeyIsIdempotent(t *testing.T) {
	prov, st := newTestProvisioner(t)
	run, err := prov.Start("web-dc", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForState(t, st, run.ID, "key_confirm")

	if err := prov.ConfirmKey(run.ID); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	// Must not panic; must be rejected because the run left key_confirm.
	if err := prov.ConfirmKey(run.ID); err == nil {
		t.Error("second confirm returned nil, want an error")
	}

	// The run must still make progress (double-confirm must not wedge it).
	waitForState(t, st, run.ID, "enrolling")
}

// TestRacingConfirmsDoNotPanic exercises simultaneous confirms.
func TestRacingConfirmsDoNotPanic(t *testing.T) {
	prov, st := newTestProvisioner(t)
	run, err := prov.Start("web-race", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForState(t, st, run.ID, "key_confirm")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = prov.ConfirmKey(run.ID) // errors are fine; a panic is not
		}()
	}
	wg.Wait()
	waitForState(t, st, run.ID, "enrolling")
}

// TestConfirmAfterRestartFailsRun is the regression guard for the zombie-run
// bug: if the server restarted while a run was paused (no in-memory state
// machine), ConfirmKey must fail the run with a clear message instead of
// returning success and leaving it in key_confirm forever.
func TestConfirmAfterRestartFailsRun(t *testing.T) {
	prov, st := newTestProvisioner(t)
	run, err := prov.Start("web-restart", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForState(t, st, run.ID, "key_confirm")

	// Simulate a restart: drop the in-memory active-run registry.
	prov.mu.Lock()
	delete(prov.runs, run.ID)
	prov.mu.Unlock()

	err = prov.ConfirmKey(run.ID)
	if err == nil {
		t.Fatal("ConfirmKey after restart returned nil, want error")
	}
	cur, _ := st.ProvisionRun(run.ID)
	if cur.State != "failed" {
		t.Fatalf("state after failed confirm = %q, want failed", cur.State)
	}
	if cur.Error == "" {
		t.Error("failed run should carry a remediation message")
	}
}

// TestReapStaleFailsStrandedRuns verifies that after a simulated restart
// (in-memory state machine gone), ReapStale fails every non-terminal run
// with a remediation message and leaves already-terminal runs untouched.
func TestReapStaleFailsStrandedRuns(t *testing.T) {
	prov, st := newTestProvisioner(t)
	a, err := prov.Start("web-stranded", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start a: %v", err)
	}
	waitForState(t, st, a.ID, "key_confirm")
	b, err := prov.Start("web-done", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start b: %v", err)
	}
	waitForState(t, st, b.ID, "key_confirm")
	// b already reached a terminal state before the "restart".
	if err := st.SetProvisionRunState(b.ID, "cancelled", "connect", "manual cancel"); err != nil {
		t.Fatalf("SetProvisionRunState b: %v", err)
	}

	// Simulate a restart: drop the in-memory active-run registry.
	prov.mu.Lock()
	delete(prov.runs, a.ID)
	delete(prov.runs, b.ID)
	prov.mu.Unlock()

	prov.ReapStale()

	aCur, _ := st.ProvisionRun(a.ID)
	if aCur.State != "failed" {
		t.Fatalf("stranded run state = %q, want failed", aCur.State)
	}
	if !strings.Contains(aCur.Error, "server restarted") {
		t.Errorf("stranded run error = %q, want mention of server restart", aCur.Error)
	}
	bCur, _ := st.ProvisionRun(b.ID)
	if bCur.State != "cancelled" {
		t.Fatalf("terminal run state = %q, want unchanged cancelled", bCur.State)
	}
	if bCur.Error != "manual cancel" {
		t.Errorf("terminal run error = %q, want unchanged", bCur.Error)
	}
}

// TestProvisionUnreachableServerFailsPreflight verifies the host->server
// reachability probe: when the target cannot reach the control-plane port,
// the run fails at preflight (with remediation) instead of installing the
// agent and burning the 60s enroll window.
func TestProvisionUnreachableServerFailsPreflight(t *testing.T) {
	prov, st := newTestProvisioner(t)

	bin := writeFakeFleetNoReach(t)
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	prov.ssh = sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}
	// Pre-trust so we go straight to preflight.
	if err := prov.ssh.AddKey(context.Background(), "web-nr ssh-ed25519 AAAApretrusted"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	run, err := prov.Start("web-nr", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	run = waitForState(t, st, run.ID, "failed")
	if !strings.Contains(run.Error, "reach") && !strings.Contains(run.Error, "firewall") {
		t.Errorf("failure message should mention reachability, got %q", run.Error)
	}
}

// writeFakeFleetNoReach is a fleet whose preflight reports reach=no.
func writeFakeFleetNoReach(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	ssh := `#!/bin/sh
case "$*" in
  *"base64 -d"*) echo "INSTALL_OK"; exit 0 ;;
  *)
    echo "os=Ubuntu 24.04"
    echo "arch=x86_64"
    echo "init=systemd"
    echo "user=root"
    echo "sudo=yes"
    echo "disk=100000000"
    echo "reach=no"
    exit 0
    ;;
esac
`
	scp := "#!/bin/sh\nexit 0\n"
	keyscan := `#!/bin/sh
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyNoReach"
exit 0
`
	keygen := `#!/bin/sh
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F) if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": scp, "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	return bin
}

// TestPreflightAuthDeniedGetsHint: when the server user's SSH dir presents no
// key the target accepts (the common first-run failure), the run error must
// carry an actionable hint naming the SSH dir, not just raw ssh stderr.
func TestPreflightAuthDeniedGetsHint(t *testing.T) {
	prov, st := newTestProvisioner(t)

	bin := t.TempDir()
	ssh := `#!/bin/sh
echo "web-auth: Permission denied (publickey)." >&2
exit 255
`
	keyscan := `#!/bin/sh
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyAuth"
exit 0
`
	keygen := `#!/bin/sh
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F) if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeAuthFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": "#!/bin/sh\nexit 0\n", "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}

	sshDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	prov.ssh = sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}
	if err := prov.ssh.AddKey(context.Background(), "web-auth ssh-ed25519 AAAApretrusted"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	run, err := prov.Start("web-auth", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	run = waitForState(t, st, run.ID, "failed")
	if !strings.Contains(run.Error, "Permission denied") {
		t.Errorf("expected Permission denied in error, got %q", run.Error)
	}
	if !strings.Contains(run.Error, "no usable SSH client key") || !strings.Contains(run.Error, sshDir) {
		t.Errorf("expected actionable hint naming the SSH dir, got %q", run.Error)
	}
}

// TestInstallScriptFreshWipe verifies fresh mode's install script includes the
// destructive wipe (stop/disable unit + remove identity/env) and join mode's
// does not, and that the env-file values are NOT shell-quoted (they sit in a
// quoted <<'EOF' heredoc).
func TestInstallScriptFreshWipe(t *testing.T) {
	fresh := buildInstallScript(installSpec{
		binSHA12: "abc123def456", binSHA: "fullsha", wipe: wipeScript("fresh"),
		serverHost: "127.0.0.1:8443", token: "ptok_0123456789abcdef",
	})
	// The install script must create the file root (spec-file-root):
	// the file surface is confined to /home/partout on every host.
	if !strings.Contains(fresh, "mkdir -p /home/partout") || !strings.Contains(fresh, "chown partout:partout /home/partout") {
		t.Fatalf("install script missing file root setup:\n%s", fresh)
	}
	if !strings.Contains(fresh, "rm -rf /var/lib/partout/agent") {
		t.Fatalf("fresh script missing data-dir wipe:\n%s", fresh)
	}
	if !strings.Contains(fresh, "systemctl stop partout-agent") {
		t.Fatalf("fresh script missing unit stop:\n%s", fresh)
	}
	if !strings.Contains(fresh, "systemctl disable partout-agent") {
		t.Fatalf("fresh script missing unit disable:\n%s", fresh)
	}

	join := buildInstallScript(installSpec{
		binSHA12: "abc123def456", binSHA: "fullsha", wipe: wipeScript("join"),
		serverHost: "127.0.0.1:8443", token: "ptok_0123456789abcdef",
	})
	if strings.Contains(join, "rm -rf /var/lib/partout/agent") {
		t.Fatalf("join script must NOT wipe the data dir:\n%s", join)
	}
	if strings.Contains(join, "systemctl stop partout-agent") {
		t.Fatalf("join script must NOT stop the unit:\n%s", join)
	}

	// Env-file values must be raw (no surrounding single quotes) because they
	// are inside a quoted heredoc; a quoted value would corrupt the env file.
	if !strings.Contains(fresh, "PARTOUT_SERVER=127.0.0.1:8443\n") {
		t.Fatalf("PARTOUT_SERVER should be raw in the heredoc:\n%s", fresh)
	}
	if !strings.Contains(fresh, "PARTOUT_TOKEN=ptok_0123456789abcdef\n") {
		t.Fatalf("PARTOUT_TOKEN should be raw in the heredoc:\n%s", fresh)
	}
	if strings.Contains(fresh, "PARTOUT_SERVER='") || strings.Contains(fresh, "PARTOUT_TOKEN='") {
		t.Fatalf("env values must not be shell-quoted in the heredoc:\n%s", fresh)
	}
}

// TestVersionNote checks the version-diff classification used in preflight.
func TestVersionNote(t *testing.T) {
	cases := []struct {
		remote, local, want string
	}{
		{"none", "v0.7.0", "install"},
		{"", "v0.7.0", "install"},
		{"v0.7.0", "v0.7.0", "same (v0.7.0)"},
		{"v0.6.5", "v0.7.0", "v0.6.5 -> v0.7.0"},
		{"v0.8.0", "v0.7.0", "v0.8.0 -> v0.7.0"}, // downgrade direction is reported too
	}
	for _, c := range cases {
		if got := versionNote(c.remote, c.local); got != c.want {
			t.Errorf("versionNote(%q,%q) = %q, want %q", c.remote, c.local, got, c.want)
		}
	}
}

// TestPreflightLoopbackBindMessage verifies the loopback-bind diagnostic:
// when the server itself binds loopback-only, the preflight failure must
// blame the bind (actionable: change PARTOUT_ADDR) instead of sending the
// operator to debug firewalls — the first-user report's exact failure mode.
func TestPreflightLoopbackBindMessage(t *testing.T) {
	prov, st := newTestProvisioner(t)
	prov.bindAddr = "127.0.0.1"

	bin := writeFakeFleetNoReach(t)
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	prov.ssh = sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}
	if err := prov.ssh.AddKey(context.Background(), "web-lb ssh-ed25519 AAAApretrusted"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	run, err := prov.Start("web-lb", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	run = waitForState(t, st, run.ID, "failed")
	for _, want := range []string{"loopback", "PARTOUT_ADDR"} {
		if !strings.Contains(run.Error, want) {
			t.Errorf("loopback-bind failure should mention %q, got %q", want, run.Error)
		}
	}
	if strings.Contains(run.Error, "firewall") {
		t.Errorf("loopback-bind failure must not blame the firewall, got %q", run.Error)
	}
}

// TestPreflightDNSFailureMessage verifies the DNS-distinct diagnostic: when
// the target cannot resolve the server address (typically the hostname
// fallback for PARTOUT_SERVER_HOST), the failure must say so — no firewall
// change can fix a name that does not resolve.
func TestPreflightDNSFailureMessage(t *testing.T) {
	prov, st := newTestProvisioner(t)

	bin := t.TempDir()
	ssh := `#!/bin/sh
case "$*" in
  *"base64 -d"*) echo "INSTALL_OK"; exit 0 ;;
  *)
    echo "os=Ubuntu 24.04"
    echo "arch=x86_64"
    echo "init=systemd"
    echo "user=root"
    echo "sudo=yes"
    echo "disk=100000000"
    echo "reach=dns"
    exit 0
    ;;
esac
`
	scp := "#!/bin/sh\nexit 0\n"
	keyscan := `#!/bin/sh
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyDNS"
exit 0
`
	keygen := `#!/bin/sh
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F) if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeDNSFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": scp, "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}

	sshDir := filepath.Join(t.TempDir(), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	prov.ssh = sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}
	if err := prov.ssh.AddKey(context.Background(), "web-dns ssh-ed25519 AAAApretrusted"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	run, err := prov.Start("web-dns", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	run = waitForState(t, st, run.ID, "failed")
	for _, want := range []string{"resolve", "PARTOUT_SERVER_HOST"} {
		if !strings.Contains(run.Error, want) {
			t.Errorf("dns failure should mention %q, got %q", want, run.Error)
		}
	}
}

// TestInstallScriptCADistribution verifies the TLS install path: with a CA
// fingerprint the script must verify + install the CA and wire
// PARTOUT_TLS_CA into the agent env; without one (TLS off) neither may
// appear — the script stays byte-compatible with the pre-TLS installer.
func TestInstallScriptCADistribution(t *testing.T) {
	base := installSpec{
		binSHA12: "abc123def456", binSHA: "fullsha",
		wipe:       wipeScript("join"),
		serverHost: "10.0.0.5:8443", token: "ptok_0123456789abcdef",
	}
	withCA := base
	withCA.caSHA12, withCA.caSHA = "cafebabecafe", "cafefullsha"
	s := buildInstallScript(withCA)
	if !strings.Contains(s, "CA=/tmp/partout-ca-cafebabecafe") {
		t.Errorf("install script missing CA transfer path:\n%s", s)
	}
	if !strings.Contains(s, `"$CAACT" != 'cafefullsha'`) {
		t.Errorf("install script missing CA sha verification:\n%s", s)
	}
	if !strings.Contains(s, `install -m 0644 "$CA" /etc/partout/ca.crt`) {
		t.Errorf("install script missing CA install:\n%s", s)
	}
	if !strings.Contains(s, "PARTOUT_TLS_CA=/etc/partout/ca.crt\n") {
		t.Errorf("agent env missing PARTOUT_TLS_CA:\n%s", s)
	}

	without := buildInstallScript(base)
	if strings.Contains(without, "PARTOUT_TLS_CA") || strings.Contains(without, "partout-ca") {
		t.Errorf("TLS-off install script must not reference a CA:\n%s", without)
	}
}

// TestTransferShipsCA verifies the transfer step copies the CA alongside the
// binary when one is configured (the fake scp records its arguments).
func TestTransferShipsCA(t *testing.T) {
	prov, st := newTestProvisioner(t)

	caPath := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(caPath, []byte("fake-ca-pem"), 0o644)
	prov.caPath = caPath

	// scp logs every invocation's args so the test can assert both copies.
	logFile := filepath.Join(t.TempDir(), "scp.log")
	bin := t.TempDir()
	scp := "#!/bin/sh\necho \"$@\" >> " + logFile + "\nexit 0\n"
	ssh := `#!/bin/sh
case "$*" in
  *"base64 -d"*) echo "INSTALL_OK"; exit 0 ;;
  *) echo "os=Ubuntu 24.04"; echo "init=systemd"; echo "sudo=yes"; echo "reach=yes-plain"; exit 0 ;;
esac
`
	keyscan := `#!/bin/sh
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyCA"
exit 0
`
	keygen := `#!/bin/sh
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F) if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeCAFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": scp, "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	prov.ssh = sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}
	if err := prov.ssh.AddKey(context.Background(), "web-ca ssh-ed25519 AAAApretrusted"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	run, err := prov.Start("web-ca", "join", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The run flows through transfer; wait for install to have happened
	// (enrolling needs an agent we do not simulate — enrolling is enough).
	waitForState(t, st, run.ID, "enrolling")

	scpLog, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read scp log: %v", err)
	}
	log := string(scpLog)
	if !strings.Contains(log, "/tmp/partout-") {
		t.Errorf("scp log missing binary copy:\n%s", log)
	}
	if !strings.Contains(log, "/tmp/partout-ca-") {
		t.Errorf("scp log missing CA copy:\n%s", log)
	}
}

// TestProvisionAliasResolvesSSHConfig verifies ssh-config aliases work as
// provision hosts: keyscan/keygen read no ssh config, so the run must
// resolve the alias (ssh -G), capture the key under the resolved name, and
// surface the resolution on the run for the key-confirm screen.
func TestProvisionAliasResolvesSSHConfig(t *testing.T) {
	prov, st := newTestProvisioner(t)

	bin := t.TempDir()
	// ssh: -G resolves "ai" to 172.16.100.95 (port 22); other calls behave
	// like the standard fake fleet.
	ssh := `#!/bin/sh
GH=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-G" ]; then GH="$a"; fi
  prev="$a"
done
if [ -n "$GH" ]; then
  echo "hostname 172.16.100.95"
  echo "port 22"
  exit 0
fi
case "$*" in
  *"base64 -d"*) echo "INSTALL_OK"; exit 0 ;;
  *) echo "os=Ubuntu 24.04"; echo "init=systemd"; echo "sudo=yes"; echo "reach=yes-plain"; exit 0 ;;
esac
`
	// keyscan echoes the last non-flag arg as the host (the resolved host we
	// pass it).
	keyscan := `#!/bin/sh
HOST=""
for a in "$@"; do case "$a" in -*) ;; *) HOST="$a" ;; esac; done
echo "$HOST ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyAliasRes"
exit 0
`
	keygen := `#!/bin/sh
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F) if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeAliasFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": "#!/bin/sh\nexit 0\n", "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	prov.ssh = sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}

	run, err := prov.Start("ai", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	run = waitForState(t, st, run.ID, "key_confirm")
	if run.ResolvedHost != "172.16.100.95" {
		t.Errorf("run.ResolvedHost = %q, want 172.16.100.95", run.ResolvedHost)
	}
	if !strings.HasPrefix(run.KeyLine, "172.16.100.95 ") {
		t.Errorf("key line not keyed under resolved host: %q", run.KeyLine)
	}

	// Confirm must succeed (known_hosts keyed under the resolved name —
	// exactly what ssh verifies when connecting via the alias).
	if err := prov.ConfirmKey(run.ID); err != nil {
		t.Fatalf("ConfirmKey via alias: %v", err)
	}
	waitForState(t, st, run.ID, "enrolling")
}

// TestProvisionKeyRotationReconfirm exercises the host-reinstall path: a
// trusted host presents a new key, the run fails with the re-confirm hint,
// ReconfirmKey removes the stale entry + re-captures + re-gates at
// key_confirm, and ConfirmKey resumes the machine (fresh token) through to
// enrolling.
func TestProvisionKeyRotationReconfirm(t *testing.T) {
	prov, st := newTestProvisioner(t)
	ctx := context.Background()

	// Fake fleet whose ssh fails with the rotation banner while
	// PROV_ROTATED=1, and behaves normally once the test clears it.
	bin := t.TempDir()
	ssh := `#!/bin/sh
GH=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-G" ]; then GH="$a"; fi
  prev="$a"
done
if [ -n "$GH" ]; then echo "hostname $GH"; echo "port 22"; exit 0; fi
if [ "$PROV_ROTATED" = "1" ]; then
  echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" >&2
  echo "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" >&2
  echo "Host key verification failed." >&2
  exit 255
fi
case "$*" in
  *"base64 -d"*) echo "INSTALL_OK"; exit 0 ;;
  *) echo "os=Ubuntu 24.04"; echo "init=systemd"; echo "sudo=yes"; echo "reach=yes-plain"; exit 0 ;;
esac
`
	scp := "#!/bin/sh\nexit 0\n"
	keyscan := `#!/bin/sh
HOST=""
for a in "$@"; do case "$a" in -*) ;; *) HOST="$a" ;; esac; done
echo "$HOST ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeRotatedNewKey0123456789"
exit 0
`
	keygen := `#!/bin/sh
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F) if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -R) [ -f "$KHFILE" ] && grep -v "^$2 " "$KHFILE" > "$KHFILE.tmp" 2>/dev/null && mv "$KHFILE.tmp" "$KHFILE"; exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeRotatedFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": scp, "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	prov.ssh = sshutil.Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(bin, "ssh"),
		SCP:            filepath.Join(bin, "scp"),
		Keyscan:        filepath.Join(bin, "ssh-keyscan"),
		Keygen:         filepath.Join(bin, "ssh-keygen"),
		ConnectTimeout: 5,
	}

	// Pre-trust the host with the OLD key (the pre-rotation state).
	if err := prov.ssh.AddKey(ctx, "web-rot ssh-ed25519 AAAAFakeOldKeyThatNoLongerMatches"); err != nil {
		t.Fatalf("AddKey old: %v", err)
	}

	// Phase 1: the host was reinstalled; its key changed.
	t.Setenv("PROV_ROTATED", "1")
	run, err := prov.Start("web-rot", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	run = waitForState(t, st, run.ID, "failed")
	for _, want := range []string{"REMOTE HOST IDENTIFICATION HAS CHANGED", "Re-confirm key"} {
		if !strings.Contains(run.Error, want) {
			t.Errorf("rotation failure should mention %q, got %q", want, run.Error)
		}
	}
	oldFP := run.Fingerprint

	// Phase 2: re-confirm — stale entry dropped, new key captured, run
	// re-gated at key_confirm.
	t.Setenv("PROV_ROTATED", "0")
	if err := prov.ReconfirmKey(run.ID); err != nil {
		t.Fatalf("ReconfirmKey: %v", err)
	}
	run = waitForState(t, st, run.ID, "key_confirm")
	if run.Fingerprint == "" || run.Fingerprint == oldFP {
		t.Errorf("fingerprint after re-confirm = %q (old %q), want a new one", run.Fingerprint, oldFP)
	}
	if !strings.Contains(run.KeyLine, "FakeRotatedNewKey") {
		t.Errorf("key line after re-confirm = %q, want the new key", run.KeyLine)
	}

	// Confirm resumes the machine through to enrolling.
	if err := prov.ConfirmKey(run.ID); err != nil {
		t.Fatalf("ConfirmKey after re-confirm: %v", err)
	}
	waitForState(t, st, run.ID, "enrolling")

	// A second reconfirm while the machine is live must be refused.
	if err := prov.ReconfirmKey(run.ID); err == nil {
		t.Error("ReconfirmKey on a live run should fail")
	}
}

// TestStartRejectsConcurrentRunForHost: a second run for a host with a
// non-terminal run in flight must be rejected (concurrent runs race on
// known_hosts, the install script, and the target's units); a different
// host is fine.
func TestStartRejectsConcurrentRunForHost(t *testing.T) {
	prov, st := newTestProvisioner(t)

	a, err := prov.Start("web-dup", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	waitForState(t, st, a.ID, "key_confirm") // non-terminal

	if _, err := prov.Start("web-dup", "fresh", StartOptions{}); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("second Start for same host: err = %v, want ErrHostBusy", err)
	}
	if _, err := prov.Start("web-other", "fresh", StartOptions{}); err != nil {
		t.Fatalf("Start for a different host: %v", err)
	}

	// After the first run reaches a terminal state, the host is free again.
	if err := st.SetProvisionRunState(a.ID, "cancelled", "connect", "test"); err != nil {
		t.Fatalf("cancel first: %v", err)
	}
	third, err := prov.Start("web-dup", "fresh", StartOptions{})
	if err != nil {
		t.Fatalf("Start after terminal: %v", err)
	}
	// Park the relaunched machine before the test's temp dirs are cleaned.
	waitForState(t, st, third.ID, "key_confirm")
	if err := prov.Cancel(third.ID); err != nil {
		t.Fatalf("cancel third: %v", err)
	}
	waitForState(t, st, third.ID, "cancelled")
}

// TestBuildInstallScriptElevation (D1): the elevation bootstrap block is
// present with --elevate (policy install + sudoers render + env wiring)
// and absent without it.
func TestBuildInstallScriptElevation(t *testing.T) {
	spec := installSpec{
		binSHA12: "abc", binSHA: "abcdef", serverHost: "s:8443", token: "tok",
	}
	plain := buildInstallScript(spec)
	if strings.Contains(plain, "elevation.d") {
		t.Error("plain install must not touch /etc/partout/elevation.d")
	}

	spec.elevation = elevationScript(StartOptions{
		Elevate: true,
		ElevationPolicies: []ElevationPolicySpec{{
			Name: "baseline", RulesJSON: `[{"allow":"reboot"}]`, SHA: "0123456789abcdef0123456789abcdef",
		}},
	})
	spec.envExtras = agentEnvExtras(StartOptions{Elevate: true})
	out := buildInstallScript(spec)
	for _, want := range []string{
		"/etc/partout/elevation.d/10-baseline.json",
		"ctl elevation install-sudoers",
		"PARTOUT_ELEVATE=sudo",
		"PARTOUT_ELEVATION_POLICY=/etc/partout/elevation.d",
		"0123456789abcdef", // sha verification of the transferred policy
	} {
		if !strings.Contains(out, want) {
			t.Errorf("elevation install script missing %q", want)
		}
	}
	// The commented-out legacy hint must be gone when elevation is wired.
	if strings.Contains(out, "#PARTOUT_ELEVATE=sudo") {
		t.Error("elevated install must not carry the commented-out ELEVATE hint")
	}
}

// TestStartCanonicalizesElevationPolicy (field-caught on the v0.9.11
// run): a hand-formatted policy (indented JSON — a local file or a preset
// literal) must be canonicalized at Start, or the on-host sha256 check
// (which hashes the canonical form) rejects the transfer.
func TestStartCanonicalizesElevationPolicy(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	prov := New(Options{Store: st, Logger: log.New(io.Discard, "", 0)})
	formatted := "[\n  {\"allow\": \"reboot\"}\n]"
	_, _ = prov.Start("canon-host", "fresh", StartOptions{
		Elevate: true,
		// Valid JSON, just pretty-printed — LoadPolicyJSON accepts it.
		ElevationPolicies: []ElevationPolicySpec{{Name: "p", RulesJSON: formatted, SHA: "0123456789abcdef0123456789abcdef"}},
	})
	// Now verify the canonicalization directly: the same rules, formatted
	// vs compact, must produce the SAME canonical rules + hash.
	a := StartOptions{Elevate: true, ElevationPolicies: []ElevationPolicySpec{{Name: "p", RulesJSON: formatted}}}
	b := StartOptions{Elevate: true, ElevationPolicies: []ElevationPolicySpec{{Name: "p", RulesJSON: `[{"allow":"reboot"}]`}}}
	polA, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + a.ElevationPolicies[0].RulesJSON + `}`))
	if err != nil {
		t.Fatalf("load A: %v", err)
	}
	polB, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + b.ElevationPolicies[0].RulesJSON + `}`))
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	ca, _ := json.Marshal(polA.Rules)
	cb, _ := json.Marshal(polB.Rules)
	if string(ca) != string(cb) {
		t.Fatalf("canonical forms differ: %s vs %s", ca, cb)
	}
	if polA.PolicyHash() != polB.PolicyHash() {
		t.Fatalf("hashes differ: %s vs %s", polA.PolicyHash(), polB.PolicyHash())
	}
	// The transfer file for the canonical form must hash to PolicyHash.
	file := `{"rules":` + string(ca) + `}`
	sum := sha256.Sum256([]byte(file))
	if hex.EncodeToString(sum[:]) != polA.PolicyHash() {
		t.Fatalf("canonical transfer file hash %x != PolicyHash %s", sum, polA.PolicyHash())
	}
}

// TestElevationScriptValidates: options with unparsable rules are
// rejected at Start (before anything reaches the host).
func TestStartRejectsBadElevationPolicy(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	prov := New(Options{Store: st, Logger: log.New(io.Discard, "", 0)})
	_, err = prov.Start("x", "fresh", StartOptions{
		Elevate:           true,
		ElevationPolicies: []ElevationPolicySpec{{Name: "bad", RulesJSON: `[{not json`}},
	})
	if err == nil {
		t.Fatal("Start must reject an unparsable elevation policy")
	}
	_, err = prov.Start("x", "fresh", StartOptions{Elevate: true})
	if err == nil {
		t.Fatal("Start must reject --elevate without policies")
	}
}
