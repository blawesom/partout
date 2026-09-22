package sshutil

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeBinaries creates a temp dir with fake ssh/scp/ssh-keyscan/ssh-keygen
// shell scripts and returns the bin dir path.
func writeFakeBinaries(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	logPath := filepath.Join(bin, "calls.log")
	os.WriteFile(logPath, nil, 0o600)

	ssh := `#!/bin/sh
echo "ssh $*" >> "$FAKE_LOG"
echo "ok"
exit 0
`
	scp := `#!/bin/sh
echo "scp $*" >> "$FAKE_LOG"
exit 0
`
	keyscan := `#!/bin/sh
echo "keyscan $*" >> "$FAKE_LOG"
# invocation: ssh-keyscan -t <types> <host>  ->  host is $3
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTest0123456789abcdefghijklmnopq"
exit 0
`
	keygen := `#!/bin/sh
echo "keygen $*" >> "$FAKE_LOG"
# Parse an optional explicit -f <file> (sshutil passes it for known_hosts
# lookups and hashing). Real ssh-keygen defaults to ~/.ssh/known_hosts when
# -f is absent; the fake mirrors that so an accidental omission is caught.
KHFILE=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then KHFILE="$a"; fi
  prev="$a"
done
[ -z "$KHFILE" ] && KHFILE="$HOME/.ssh/known_hosts"
case "$1" in
  -F)
    if grep -qF "$2" "$KHFILE" 2>/dev/null; then exit 0; else exit 1; fi
    ;;
  -H)
    exit 0
    ;;
  -l)
    cat >/dev/null
    echo "256 SHA256:FakeFingerprint comment (ED25519)"
    exit 0
    ;;
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
	t.Setenv("FAKE_LOG", logPath)
	return bin
}

// newTestCfg builds a Config wired to the fake binaries in binDir, with an
// isolated SSHDir under a temp HOME.
func newTestCfg(t *testing.T, binDir string) Config {
	t.Helper()
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0o700)
	return Config{
		SSHDir:         sshDir,
		SSH:            filepath.Join(binDir, "ssh"),
		SCP:            filepath.Join(binDir, "scp"),
		Keyscan:        filepath.Join(binDir, "ssh-keyscan"),
		Keygen:         filepath.Join(binDir, "ssh-keygen"),
		ConnectTimeout: 10,
	}
}

func TestHostKey(t *testing.T) {
	cfg := newTestCfg(t, writeFakeBinaries(t))
	ft, fp, line, err := cfg.HostKey(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if fp != "SHA256:FakeFingerprint" {
		t.Errorf("fingerprint = %q, want SHA256:FakeFingerprint", fp)
	}
	if !strings.Contains(line, "ssh-ed25519") {
		t.Errorf("keyLine missing ed25519: %q", line)
	}
	if ft != "ED25519" {
		t.Errorf("keyType = %q, want ED25519", ft)
	}
}

func TestHasHostAndAddKey(t *testing.T) {
	cfg := newTestCfg(t, writeFakeBinaries(t))
	ctx := context.Background()

	has, err := cfg.HasHost(ctx, "web01")
	if err != nil {
		t.Fatalf("HasHost: %v", err)
	}
	if has {
		t.Fatal("HasHost true before AddKey")
	}

	_, _, line, err := cfg.HostKey(ctx, "web01")
	if err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	// known_hosts must contain the key and be 0600.
	kh := filepath.Join(cfg.SSHDir, "known_hosts")
	st, err := os.Stat(kh)
	if err != nil {
		t.Fatalf("known_hosts missing after AddKey: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("known_hosts perm = %v, want 0600", perm)
	}

	has, err = cfg.HasHost(ctx, "web01")
	if err != nil {
		t.Fatalf("HasHost after AddKey: %v", err)
	}
	if !has {
		t.Error("HasHost false after AddKey")
	}
}

func TestRunUsesHardenedFlags(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	out, _, exit, err := cfg.Run(context.Background(), "web01", "echo hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exit != 0 {
		t.Fatalf("Run exit = %d, want 0", exit)
	}
	if !strings.Contains(out, "ok") {
		t.Errorf("Run stdout = %q, want to contain ok", out)
	}

	// Assert the hardened options were passed.
	calls, _ := os.ReadFile(filepath.Join(bin, "calls.log"))
	logs := string(calls)
	for _, want := range []string{
		"ssh -o BatchMode=yes",
		"ConnectTimeout=10",
		"ServerAliveInterval=15",
		"StrictHostKeyChecking=yes",
		"web01",
		"echo hi",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("ssh call missing %q; log: %s", want, logs)
		}
	}
}

func TestCopy(t *testing.T) {
	cfg := newTestCfg(t, writeFakeBinaries(t))
	if _, err := cfg.Copy(context.Background(), "/tmp/a", "web01", "/tmp/b"); err != nil {
		t.Fatalf("Copy: %v", err)
	}
}

// TestArgsPinSSHDir is the regression guard for the PARTOUT_SSH_DIR bug: with a
// non-default SSHDir, OpenSSH resolves ~/.ssh from the passwd database rather
// than $HOME, so ssh/scp MUST be given -F and UserKnownHostsFile explicitly,
// and ssh-keygen -F must be given -f. Without these, a confirmed host key is
// written to a file ssh never reads and every strict connect fails.
func TestArgsPinSSHDir(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	ctx := context.Background()

	if _, _, _, err := cfg.Run(ctx, "web01", "echo hi"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := cfg.Copy(ctx, "/tmp/a", "web01", "/tmp/b"); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if _, err := cfg.HasHost(ctx, "web01"); err != nil {
		t.Fatalf("HasHost: %v", err)
	}

	cfgPath := filepath.Join(cfg.SSHDir, "config")
	khPath := filepath.Join(cfg.SSHDir, "known_hosts")

	calls, err := os.ReadFile(filepath.Join(bin, "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	logs := string(calls)

	// ssh and scp must both pin the config + known_hosts.
	for _, want := range []string{
		"-F " + cfgPath,
		"UserKnownHostsFile=" + khPath,
	} {
		if n := strings.Count(logs, want); n < 2 { // once for ssh, once for scp
			t.Errorf("expected %q at least twice (ssh+scp), got %d; log:\n%s", want, n, logs)
		}
	}
	// ssh-keygen -F must consult the explicit known_hosts file.
	if !strings.Contains(logs, "keygen -F web01 -f "+khPath) {
		t.Errorf("HasHost did not pass -f %s; log:\n%s", khPath, logs)
	}
}

// TestDirArgsCreatesConfig guards the -F contract: ssh exits 255 when -F
// points at a missing file, so dirArgs must materialise an empty config.
func TestDirArgsCreatesConfig(t *testing.T) {
	sshDir := filepath.Join(t.TempDir(), "isolated", ".ssh")
	cfg := Default(sshDir)
	args := cfg.dirArgs()
	cfgPath := filepath.Join(sshDir, "config")
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("dirArgs did not create %s: %v", cfgPath, err)
	}
	found := false
	for i, a := range args {
		if a == "-F" && i+1 < len(args) && args[i+1] == cfgPath {
			found = true
		}
	}
	if !found {
		t.Errorf("dirArgs missing -F %s: %v", cfgPath, args)
	}
}

// TestDirArgsEmptySSHDirPassthrough documents that an empty SSHDir applies no
// redirection (the operator's default ~/.ssh is used).
func TestDirArgsEmptySSHDirPassthrough(t *testing.T) {
	if args := (Config{}).dirArgs(); args != nil {
		t.Errorf("dirArgs(empty SSHDir) = %v, want nil", args)
	}
}
