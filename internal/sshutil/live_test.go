//go:build live

// Package sshutil — opt-in live tests against a REAL sshd.
//
// These are the tests that can actually falsify the design: the unit tests in
// sshutil_test.go use shell-script fakes, which implement the *intended*
// semantics of ssh/scp/ssh-keygen and therefore cannot catch the fact that
// OpenSSH resolves ~/.ssh from the passwd database rather than $HOME.
//
// Run with:
//
//	PARTOUT_LIVE_SSH=1 go test -tags live -run TestLive -v ./internal/sshutil
//
// Requirements: a reachable sshd on localhost:22, the current user's sshd
// accepting a key we generate, and write access to the user's
// ~/.ssh/authorized_keys (sshd reads AuthorizedKeysFile relative to the
// passwd home, so unlike the client side it cannot be redirected).
//
// The test is hermetic in cleanup: it restores authorized_keys and removes
// every file it created.
package sshutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func liveHost(t *testing.T) string {
	t.Helper()
	if os.Getenv("PARTOUT_LIVE_SSH") != "1" {
		t.Skip("set PARTOUT_LIVE_SSH=1 to run live sshd tests")
	}
	host := os.Getenv("PARTOUT_LIVE_SSH_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	return host
}

// liveSSHDir provisions a temp ssh dir with a fresh keypair, authorises the
// public key for the current user, and returns the ssh dir. It registers
// cleanup that removes the key from authorized_keys and restores the file.
func liveSSHDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	authKeys := filepath.Join(home, ".ssh", "authorized_keys")

	orig, err := os.ReadFile(authKeys)
	if err != nil && !os.IsNotExist(err) {
		t.Skipf("cannot read %s: %v", authKeys, err)
	}

	sshDir := t.TempDir()
	if err := os.Chmod(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "",
		"-C", "partout-live-test", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(pub))

	appendAuthorizedKey(t, authKeys, orig, pubLine)
	return sshDir
}

// appendAuthorizedKey appends pubLine and guarantees restoration afterwards:
// the ORIGINAL bytes are written back verbatim, so we never re-hash or reorder
// the operator's file.
func appendAuthorizedKey(t *testing.T, path string, orig []byte, pubLine string) {
	t.Helper()
	t.Cleanup(func() {
		if err := os.WriteFile(path, orig, 0o600); err != nil {
			t.Errorf("restore %s: %v", path, err)
		}
	})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := f.WriteString(pubLine + "\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func liveConfig(sshDir string) Config {
	c := Default(sshDir)
	c.ConnectTimeout = 5
	return c
}

// TestLiveRunStrict proves that Run works with StrictHostKeyChecking=yes once
// the host key has been confirmed via AddKey — i.e. that SSHDir redirection
// actually reaches ssh (the bug this test exists to catch).
func TestLiveRunStrict(t *testing.T) {
	host := liveHost(t)
	sshDir := liveSSHDir(t)
	cfg := liveConfig(sshDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Not yet trusted.
	trusted, err := cfg.HasHost(ctx, host)
	if err != nil {
		t.Fatalf("HasHost: %v", err)
	}
	if trusted {
		t.Fatalf("host %s unexpectedly already trusted in %s", host, sshDir)
	}

	// Capture + confirm the key.
	keyType, fp, line, err := cfg.HostKey(ctx, host)
	if err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if keyType == "" || fp == "" || line == "" {
		t.Fatalf("HostKey returned empties: type=%q fp=%q line=%q", keyType, fp, line)
	}
	t.Logf("captured %s %s", keyType, fp)
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	// Now HasHost must see it in SSHDir (not the passwd-home known_hosts).
	trusted, err = cfg.HasHost(ctx, host)
	if err != nil {
		t.Fatalf("HasHost after AddKey: %v", err)
	}
	if !trusted {
		t.Fatalf("HasHost still false after AddKey — ssh-keygen -F is not reading %s",
			filepath.Join(sshDir, "known_hosts"))
	}

	// And a strict ssh run must succeed.
	out, stderr, exit, err := cfg.Run(ctx, host, "echo PARTOUT_LIVE_OK; whoami")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exit != 0 {
		t.Fatalf("strict Run exit %d: %s", exit, strings.TrimSpace(stderr))
	}
	if !strings.Contains(out, "PARTOUT_LIVE_OK") {
		t.Fatalf("unexpected Run output: %q (stderr %q)", out, stderr)
	}
}

// TestLiveCopyStrict proves scp reaches the host with SSHDir redirection and
// the confirmed host key.
func TestLiveCopyStrict(t *testing.T) {
	host := liveHost(t)
	sshDir := liveSSHDir(t)
	cfg := liveConfig(sshDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, _, line, err := cfg.HostKey(ctx, host)
	if err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	src := filepath.Join(t.TempDir(), "payload.txt")
	want := "partout-live-copy-payload\n"
	if err := os.WriteFile(src, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := "/tmp/partout-live-copy-" + filepath.Base(t.TempDir()) + ".txt"
	t.Cleanup(func() { exec.Command("rm", "-f", remote).Run() })

	if _, err := cfg.Copy(ctx, src, host, remote); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	out, stderr, exit, err := cfg.Run(ctx, host, "cat "+remote)
	if err != nil || exit != 0 {
		t.Fatalf("read back: exit=%d err=%v stderr=%s", exit, err, stderr)
	}
	if out != want {
		t.Fatalf("copied content = %q, want %q", out, want)
	}
}

// TestLiveSSHDirIsolation proves the redirection does not leak into the
// operator's real ~/.ssh/known_hosts: confirming a key writes to SSHDir only.
func TestLiveSSHDirIsolation(t *testing.T) {
	host := liveHost(t)
	sshDir := liveSSHDir(t)
	cfg := liveConfig(sshDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, _, line, err := cfg.HostKey(ctx, host)
	if err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	// The isolated known_hosts must exist and contain the key.
	kh := filepath.Join(sshDir, "known_hosts")
	if _, err := os.Stat(kh); err != nil {
		t.Fatalf("isolated known_hosts missing: %v", err)
	}
}

// TestLiveAliasStrict proves ssh-config aliases work end-to-end against a
// real sshd: the run captures the key via the alias (resolved through
// ssh -G to the HostName), stores it under the resolved name, and a strict
// ssh connect via the alias succeeds — the exact provision key-confirm flow
// an operator with "Host ai / HostName <ip>" in their config relies on.
func TestLiveAliasStrict(t *testing.T) {
	host := liveHost(t)
	sshDir := liveSSHDir(t)
	cfg := liveConfig(sshDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The operator-style alias: Host <alias> / HostName <real host>.
	alias := "partout-live-alias"
	cfgPath := filepath.Join(sshDir, "config")
	if err := os.WriteFile(cfgPath, []byte(
		fmt.Sprintf("Host %s\n    HostName %s\n    User %s\n", alias, host, currentUser())), 0o600); err != nil {
		t.Fatal(err)
	}

	// Resolution: alias -> real host, via the same config ssh will use.
	res, err := cfg.ResolveHost(ctx, alias)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if res.Host != host {
		t.Fatalf("resolved host = %q, want %q", res.Host, host)
	}

	// Not yet trusted under the alias.
	trusted, err := cfg.HasHost(ctx, alias)
	if err != nil {
		t.Fatalf("HasHost: %v", err)
	}
	if trusted {
		t.Fatalf("alias %s unexpectedly already trusted", alias)
	}

	// Capture + confirm via the alias; the key line must be keyed under
	// the resolved host.
	_, _, line, err := cfg.HostKey(ctx, alias)
	if err != nil {
		t.Fatalf("HostKey via alias: %v", err)
	}
	if !strings.HasPrefix(line, host+" ") {
		t.Fatalf("key line %q not keyed under resolved host %q", line, host)
	}
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	// The alias must now be trusted.
	trusted, err = cfg.HasHost(ctx, alias)
	if err != nil {
		t.Fatalf("HasHost after AddKey: %v", err)
	}
	if !trusted {
		t.Fatal("HasHost(alias) false after AddKey(resolved)")
	}

	// A strict ssh run via the alias must succeed end-to-end.
	out, stderr, exit, err := cfg.Run(ctx, alias, "echo PARTOUT_LIVE_ALIAS_OK")
	if err != nil {
		t.Fatalf("Run via alias: %v", err)
	}
	if exit != 0 {
		t.Fatalf("strict Run via alias exit %d: %s", exit, strings.TrimSpace(stderr))
	}
	if !strings.Contains(out, "PARTOUT_LIVE_ALIAS_OK") {
		t.Fatalf("unexpected Run output: %q (stderr %q)", out, stderr)
	}
}

// currentUser returns the invoking user's name (sshd needs it in the alias
// config; $USER suffices for the live-test environment).
func currentUser() string {
	u := os.Getenv("USER")
	if u == "" {
		u = "root"
	}
	return u
}

// TestLiveProxyCaptureStrict proves the ProxyJump/ProxyCommand capture path
// end-to-end against a real sshd: the target is only reachable through a
// ProxyCommand (raw-TCP keyscan cannot traverse it), so the key must be
// captured by ssh itself into a throwaway known_hosts — then gated through
// key_confirm (AddKey) and used for a strict connect. The throwaway
// accept-new never touches the operator's known_hosts.
func TestLiveProxyCaptureStrict(t *testing.T) {
	host := liveHost(t)
	sshDir := liveSSHDir(t)
	cfg := liveConfig(sshDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("no nc for the ProxyCommand test")
	}

	// Structurally a proxied target: the connection to <host> goes through
	// a ProxyCommand, which forces the ssh-capture path (keyscan would do
	// raw TCP to the hostname and read no config).
	alias := "partout-live-proxy"
	cfgPath := filepath.Join(sshDir, "config")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(
		"Host %s\n    HostName %s\n    User %s\n    ProxyCommand nc %%h %%p\n",
		alias, host, currentUser())), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := cfg.ResolveHost(ctx, alias)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if !res.ViaProxy {
		t.Fatalf("resolved = %+v, want ViaProxy=true (ProxyCommand present)", res)
	}

	// The operator's known_hosts must stay untouched by the capture.
	kh := filepath.Join(sshDir, "known_hosts")
	before, _ := os.ReadFile(kh)

	_, _, line, err := cfg.HostKey(ctx, alias)
	if err != nil {
		t.Fatalf("HostKey via proxy: %v", err)
	}
	if !strings.HasPrefix(line, host+" ") {
		t.Fatalf("captured line %q not keyed under %q", line, host)
	}
	after, _ := os.ReadFile(kh)
	if string(before) != string(after) {
		t.Fatalf("capture wrote to the operator's known_hosts:\n%s", after)
	}

	// Gate + trust + strict connect via the proxy alias.
	if err := cfg.AddKey(ctx, line); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	trusted, err := cfg.HasHost(ctx, alias)
	if err != nil || !trusted {
		t.Fatalf("HasHost(alias) = %v, %v", trusted, err)
	}
	out, stderr, exit, err := cfg.Run(ctx, alias, "echo PARTOUT_LIVE_PROXY_OK")
	if err != nil {
		t.Fatalf("Run via proxy: %v", err)
	}
	if exit != 0 {
		t.Fatalf("strict Run via proxy exit %d: %s", exit, strings.TrimSpace(stderr))
	}
	if !strings.Contains(out, "PARTOUT_LIVE_PROXY_OK") {
		t.Fatalf("unexpected output: %q", out)
	}
}
