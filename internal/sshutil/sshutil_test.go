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
case "$1" in
  -F)
    if grep -qF "$2" "$HOME/.ssh/known_hosts" 2>/dev/null; then exit 0; else exit 1; fi
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
