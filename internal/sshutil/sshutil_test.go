package sshutil

import (
	"context"
	"os"
	"os/exec"
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
# ssh -G <host> probe (ResolveHost): honor FAKE_RESOLVED_HOST/PORT so tests
# can emulate an ssh-config alias. The host is the argument after -G.
# FAKE_IDENTITYFILE (existing) and FAKE_IDENTITYFILE_MISSING (absent)
# emulate config-declared IdentityFile entries. FAKE_PROXYJUMP and
# FAKE_HOSTKEYALIAS emulate ProxyJump/HostKeyAlias configs.
GH=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-G" ]; then GH="$a"; fi
  prev="$a"
done
if [ -n "$GH" ]; then
  echo "hostname ${FAKE_RESOLVED_HOST:-$GH}"
  echo "port ${FAKE_RESOLVED_PORT:-22}"
  [ -n "$FAKE_IDENTITYFILE" ] && echo "identityfile $FAKE_IDENTITYFILE"
  [ -n "$FAKE_IDENTITYFILE_MISSING" ] && echo "identityfile $FAKE_IDENTITYFILE_MISSING"
  [ -n "$FAKE_PROXYJUMP" ] && echo "proxyjump bastion.example"
  [ -n "$FAKE_HOSTKEYALIAS" ] && echo "hostkeyalias $FAKE_HOSTKEYALIAS"
  exit 0
fi
# hostKeyViaSSH capture: StrictHostKeyChecking=accept-new into a throwaway
# known_hosts — emulate ssh writing the key at kex (before auth).
case " $* " in
  *"StrictHostKeyChecking=accept-new"*)
    KH=""
    for a in "$@"; do
      case "$a" in UserKnownHostsFile=*) KH="${a#UserKnownHostsFile=}" ;; esac
    done
    [ "${FAKE_CAPTURE_FAIL:-0}" = "1" ] && exit 255
    echo "${FAKE_CAPTURE_HOST:-captured.example} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeJumpCaptureKey0123456789ab" >> "$KH" 2>/dev/null
    exit ${FAKE_CAPTURE_EXIT:-0}
    ;;
esac
echo "ok"
exit 0
`
	scp := `#!/bin/sh
echo "scp $*" >> "$FAKE_LOG"
exit 0
`
	keyscan := `#!/bin/sh
echo "keyscan $*" >> "$FAKE_LOG"
# Mirror real ssh-keyscan: host is the last non-flag argument; with
# -p <port> the emitted line is keyed "[host]:port" (the known_hosts form).
HOST=""
PORT=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-p" ]; then PORT="$a"; else case "$a" in -*) ;; *) HOST="$a" ;; esac; fi
  prev="$a"
done
if [ -n "$PORT" ] && [ "$PORT" != "22" ]; then HOST="[$HOST]:$PORT"; fi
echo "$HOST ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTest0123456789abcdefghijklmnopq"
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

// TestHostKeyStripsUserPrefix: provision targets are entered as user@host, but
// ssh-keyscan/ssh-keygen -F take a bare hostname. Passing "root@127.0.0.1"
// made keyscan fail with a name-resolution error, so every provision run died
// at the key_confirm gate instead of pausing there. Run/Copy still need the
// full target, so only the host-key paths strip it.
func TestHostKeyStripsUserPrefix(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	ctx := context.Background()

	if _, _, _, err := cfg.HostKey(ctx, "root@127.0.0.1"); err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if _, err := cfg.HasHost(ctx, "root@127.0.0.1"); err != nil {
		t.Fatalf("HasHost: %v", err)
	}
	log, _ := os.ReadFile(filepath.Join(bin, "calls.log"))
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		if strings.HasPrefix(line, "keyscan ") || strings.HasPrefix(line, "keygen -F") {
			if strings.Contains(line, "root@") {
				t.Errorf("host-key tooling received the user prefix: %q", line)
			}
			if !strings.Contains(line, "127.0.0.1") {
				t.Errorf("host-key tooling lost the hostname: %q", line)
			}
		}
	}
}

// TestIdentityStatus: the readiness report lists the conventional file keys
// present in OpenSSH's own order (not the order they were created), and
// reports "not found" on an empty dir. The ssh-agent is forced off so the
// file keys are the only variable.
func TestIdentityStatus(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	// Fakes (not the system ssh): IdentityStatusFor probes `ssh -G`, and the
	// real binary's default-identity candidates (~/.ssh/id_* from the passwd
	// home) would make the result machine-dependent.
	cfg := newTestCfg(t, writeFakeBinaries(t))
	empty := t.TempDir()
	cfg.SSHDir = empty
	st := cfg.IdentityStatusFor(context.Background(), "")
	if st.Found() {
		t.Fatalf("empty dir should not report a key, got %+v", st)
	}
	if st.SSHDir != empty {
		t.Errorf("SSHDir = %q, want %q", st.SSHDir, empty)
	}

	withKeys := t.TempDir()
	// Deliberately written out of OpenSSH order.
	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa"} {
		os.WriteFile(filepath.Join(withKeys, name), []byte("fake"), 0o600)
	}
	cfg = newTestCfg(t, writeFakeBinaries(t))
	cfg.SSHDir = withKeys
	st = cfg.IdentityStatusFor(context.Background(), "")
	want := []string{"id_ed25519", "id_ecdsa", "id_rsa"}
	if !st.Found() {
		t.Fatalf("expected a key, got %+v", st)
	}
	if len(st.FileKeys) != len(want) || !equalStrings(st.FileKeys, want) {
		t.Fatalf("FileKeys = %v, want %v", st.FileKeys, want)
	}
}

// TestIdentityStatusAgent: the ssh-agent fallback is detected via a fake
// ssh-add on PATH, even when no conventional file key is present.
func TestIdentityStatusAgent(t *testing.T) {
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "ssh-add"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_AUTH_SOCK", "/fake/agent.sock")

	// Fakes: the system ssh -G probe would be machine-dependent (see
	// TestIdentityStatus).
	st := newTestCfg(t, writeFakeBinaries(t)).IdentityStatusFor(context.Background(), "")
	if !st.Agent || !st.Found() {
		t.Fatalf("expected the ssh-agent to satisfy Found(), got %+v", st)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestResolveHostAlias: ssh-config aliases must work at the key-confirm
// gate. ssh-keyscan and ssh-keygen -F read no ssh config, so HostKey/HasHost
// resolve the target through `ssh -G` first — keyscan then scans the real
// host (with -p for non-default ports) and the returned key line is keyed
// the way ssh looks it up in known_hosts.
func TestResolveHostAlias(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	ctx := context.Background()

	// Emulate: Host ai / HostName 172.16.100.95 / Port 2222.
	t.Setenv("FAKE_RESOLVED_HOST", "172.16.100.95")
	t.Setenv("FAKE_RESOLVED_PORT", "2222")

	res, err := cfg.ResolveHost(ctx, "ai")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if res.Host != "172.16.100.95" || res.Port != 2222 {
		t.Fatalf("resolved = %+v, want 172.16.100.95:2222", res)
	}
	if got, want := res.Name(), "[172.16.100.95]:2222"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}

	// HostKey must keyscan the resolved host with the port, and the line
	// must be keyed under [host]:port.
	_, _, line, err := cfg.HostKey(ctx, "ai")
	if err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if !strings.HasPrefix(line, "[172.16.100.95]:2222 ") {
		t.Errorf("key line not keyed under resolved name: %q", line)
	}

	// After AddKey, HasHost via the alias must find it (resolved lookup).
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	has, err := cfg.HasHost(ctx, "ai")
	if err != nil {
		t.Fatalf("HasHost: %v", err)
	}
	if !has {
		t.Error("HasHost(alias) false after AddKey(resolved)")
	}
	logs, _ := os.ReadFile(filepath.Join(bin, "calls.log"))
	for _, want := range []string{"keyscan -t ed25519,ecdsa,rsa -p 2222 172.16.100.95", "keygen -F [172.16.100.95]:2222"} {
		if !strings.Contains(string(logs), want) {
			t.Errorf("missing %q in log:\n%s", want, logs)
		}
	}
}

// TestResolveHostLiteral: a target with no config entry resolves to itself
// on the default port — behaviour identical to pre-alias support.
func TestResolveHostLiteral(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	res, err := cfg.ResolveHost(context.Background(), "203.0.113.7")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if res.Host != "203.0.113.7" || res.Port != 22 || res.Name() != "203.0.113.7" {
		t.Fatalf("resolved = %+v, want literal default-port", res)
	}
}

// TestResolveHostUserPrefix: a user@target provision target resolves on the
// bare host (keyscan/keygen take hostnames, not ssh targets).
func TestResolveHostUserPrefix(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	res, err := cfg.ResolveHost(context.Background(), "root@203.0.113.7")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if res.Host != "203.0.113.7" {
		t.Fatalf("resolved host = %q, want 203.0.113.7", res.Host)
	}
}

// TestResolveHostRealSSH runs the actual system `ssh -G` against a real
// config file — the authoritative check that alias resolution matches what
// OpenSSH itself would do (skipped when the system ssh lacks -G).
func TestResolveHostRealSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no system ssh")
	}
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0o700)
	os.WriteFile(filepath.Join(sshDir, "config"), []byte(
		"Host testalias\n    HostName 203.0.113.9\n    Port 2222\n    User someone\n"), 0o600)
	cfg := Default(sshDir)
	res, err := cfg.ResolveHost(context.Background(), "testalias")
	if err != nil {
		if strings.Contains(err.Error(), "exit") {
			t.Skipf("system ssh -G failed (pre-6.8?): %v", err)
		}
		t.Fatalf("ResolveHost: %v", err)
	}
	if res.Host != "203.0.113.9" || res.Port != 2222 {
		t.Fatalf("resolved = %+v, want 203.0.113.9:2222", res)
	}
	// A literal host with no config entry stays itself.
	res2, err := cfg.ResolveHost(context.Background(), "198.51.100.4")
	if err != nil {
		t.Fatalf("ResolveHost literal: %v", err)
	}
	if res2.Host != "198.51.100.4" || res2.Port != 22 {
		t.Fatalf("resolved literal = %+v", res2)
	}
}

// TestIdentityStatusForHostConfigKey: host-specific ssh-config IdentityFile
// blocks are real offered keys that a conventional-name scan never finds —
// the exact setup from the field report ("Host 172.16.100.95 / IdentityFile
// marvin_ops"). IdentityStatusFor must surface them (when the file exists),
// without double-reporting conventional keys.
func TestIdentityStatusForHostConfigKey(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)

	// A config-declared key that exists on disk.
	keyPath := filepath.Join(t.TempDir(), "marvin_ops")
	os.WriteFile(keyPath, []byte("fake key"), 0o600)
	t.Setenv("FAKE_IDENTITYFILE", keyPath)
	// And one that does not (a stale entry): must be skipped.
	t.Setenv("FAKE_IDENTITYFILE_MISSING", filepath.Join(t.TempDir(), "gone"))

	st := cfg.IdentityStatusFor(context.Background(), "ai")
	if len(st.ConfigKeys) != 1 || st.ConfigKeys[0] != keyPath {
		t.Fatalf("ConfigKeys = %v, want [%s]", st.ConfigKeys, keyPath)
	}
	if !st.Found() {
		t.Error("Found() must be true with a config-declared key")
	}
}

// TestIdentityStatusForDedupesConventional: keys dirArgs already passes
// explicitly (conventional names in SSHDir) must not be re-reported as
// config keys.
func TestIdentityStatusForDedupesConventional(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)

	conventional := filepath.Join(cfg.SSHDir, "id_ed25519")
	os.WriteFile(conventional, []byte("fake"), 0o600)
	t.Setenv("FAKE_IDENTITYFILE", conventional)

	st := cfg.IdentityStatusFor(context.Background(), "web01")
	if len(st.FileKeys) != 1 || st.FileKeys[0] != "id_ed25519" {
		t.Fatalf("FileKeys = %v, want [id_ed25519]", st.FileKeys)
	}
	if len(st.ConfigKeys) != 0 {
		t.Fatalf("ConfigKeys = %v, want empty (already reported as FileKeys)", st.ConfigKeys)
	}
	if !st.Found() {
		t.Error("Found() must be true")
	}
}

// TestHostKeyViaProxyJump: a ProxyJump target can't be keyscanned (raw TCP
// never traverses the bastion), so the key must be captured by ssh itself
// into a throwaway known_hosts — with accept-new applying only to the
// throwaway file, never the operator's known_hosts. An auth failure at
// capture time is fine: kex precedes auth.
func TestHostKeyViaProxyJump(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	ctx := context.Background()

	t.Setenv("FAKE_PROXYJUMP", "1")
	t.Setenv("FAKE_RESOLVED_HOST", "10.9.8.7")
	t.Setenv("FAKE_CAPTURE_HOST", "10.9.8.7")

	ft, fp, line, err := cfg.HostKey(ctx, "behind-bastion")
	if err != nil {
		t.Fatalf("HostKey via proxy: %v", err)
	}
	if !strings.Contains(line, "ssh-ed25519") || !strings.HasPrefix(line, "10.9.8.7 ") {
		t.Errorf("captured line = %q, want keyed under captured host", line)
	}
	if ft != "ED25519" || fp == "" {
		t.Errorf("fingerprint = %q %q", ft, fp)
	}

	// The capture must NOT touch the operator's known_hosts, and must not
	// have used keyscan at all.
	logs, _ := os.ReadFile(filepath.Join(bin, "calls.log"))
	if strings.Contains(string(logs), "keyscan") {
		t.Errorf("proxy target must not be keyscanned:\n%s", logs)
	}
	kh := filepath.Join(cfg.SSHDir, "known_hosts")
	if b, err := os.ReadFile(kh); err == nil && len(b) > 0 {
		t.Errorf("operator known_hosts was written during capture:\n%s", b)
	}
	// The throwaway file must be cleaned up.
	if matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "partout-hostkey-*")); len(matches) > 0 {
		t.Errorf("throwaway known_hosts left behind: %v", matches)
	}

	// The full gate still works: AddKey + HasHost via the proxy host.
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	has, err := cfg.HasHost(ctx, "behind-bastion")
	if err != nil || !has {
		t.Fatalf("HasHost via proxy alias: %v (has=%v)", err, has)
	}
}

// TestHostKeyCaptureAuthFailure: BatchMode auth failing is fine — kex writes
// the host key before authentication, so the capture still succeeds.
func TestHostKeyCaptureAuthFailure(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	t.Setenv("FAKE_PROXYJUMP", "1")
	t.Setenv("FAKE_RESOLVED_HOST", "10.9.8.7")
	t.Setenv("FAKE_CAPTURE_HOST", "10.9.8.7")
	t.Setenv("FAKE_CAPTURE_EXIT", "255") // Permission denied (publickey)

	_, _, line, err := cfg.HostKey(context.Background(), "behind-bastion")
	if err != nil {
		t.Fatalf("HostKey with auth failure: %v", err)
	}
	if !strings.HasPrefix(line, "10.9.8.7 ") {
		t.Errorf("captured line = %q", line)
	}
}

// TestHostKeyCaptureNothingCaptured: when nothing lands in the throwaway
// file (bastion unreachable), the error must say so instead of returning
// garbage.
func TestHostKeyCaptureNothingCaptured(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	t.Setenv("FAKE_PROXYJUMP", "1")
	t.Setenv("FAKE_CAPTURE_FAIL", "1")

	_, _, _, err := cfg.HostKey(context.Background(), "behind-bastion")
	if err == nil || !strings.Contains(err.Error(), "no host key captured") {
		t.Fatalf("want no-host-key-captured error, got %v", err)
	}
}

// TestHostKeyHostKeyAlias: with a HostKeyAlias configured, ssh keys
// known_hosts under the alias — the keyscan line (keyed under the hostname)
// would never match, so the capture path must be used and HasHost must
// look the alias up.
func TestHostKeyHostKeyAlias(t *testing.T) {
	bin := writeFakeBinaries(t)
	cfg := newTestCfg(t, bin)
	ctx := context.Background()

	t.Setenv("FAKE_HOSTKEYALIAS", "realname")
	t.Setenv("FAKE_CAPTURE_HOST", "realname")

	res, err := cfg.ResolveHost(ctx, "aliasedkey")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if res.KeyAlias != "realname" || res.Name() != "realname" {
		t.Fatalf("resolved = %+v, Name() = %q", res, res.Name())
	}

	_, _, line, err := cfg.HostKey(ctx, "aliasedkey")
	if err != nil {
		t.Fatalf("HostKey with HostKeyAlias: %v", err)
	}
	if !strings.HasPrefix(line, "realname ") {
		t.Errorf("captured line = %q, want keyed under the HostKeyAlias", line)
	}
	logs, _ := os.ReadFile(filepath.Join(bin, "calls.log"))
	if strings.Contains(string(logs), "keyscan") {
		t.Errorf("HostKeyAlias target must not be keyscanned:\n%s", logs)
	}

	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	has, err := cfg.HasHost(ctx, "aliasedkey")
	if err != nil || !has {
		t.Fatalf("HasHost under alias: %v (has=%v)", err, has)
	}
}

// TestAddKeyIdempotent: confirming the same key twice (double-click, retry)
// must not append duplicate known_hosts entries.
func TestAddKeyIdempotent(t *testing.T) {
	cfg := newTestCfg(t, writeFakeBinaries(t))
	ctx := context.Background()
	line := "web01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTest0123456789abcdefghijklmnopq"
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey 1: %v", err)
	}
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey 2: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(cfg.SSHDir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "IFakeKeyForTest"); n != 1 {
		t.Errorf("key appears %d times in known_hosts, want 1:\n%s", n, b)
	}
}
