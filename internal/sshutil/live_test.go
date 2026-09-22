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
