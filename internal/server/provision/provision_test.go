package provision

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	prov := New(st, ssh, "127.0.0.1:8443", binPath, nil, log.New(os.Stderr, "", 0))
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

	run, err := prov.Start("web01", "fresh")
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

	run, err := prov.Start("web02", "fresh")
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
	run, err := prov.Start("web-dc", "fresh")
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
	run, err := prov.Start("web-race", "fresh")
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
	run, err := prov.Start("web-restart", "fresh")
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

	run, err := prov.Start("web-nr", "fresh")
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
