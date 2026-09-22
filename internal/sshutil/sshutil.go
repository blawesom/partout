// Package sshutil is a thin wrapper around the operator's *system*
// ssh/scp/ssh-keyscan/ssh-keygen binaries (architecture §3.5, A16).
//
// Deliberately not a Go SSH client library: the operator's ~/.ssh/config,
// known_hosts, ssh-agent, and ProxyJump all keep working as-is. Partout
// never creates, copies, or persists operator credentials — it only drives
// the system binaries the operator has already configured.
//
// The child's HOME is set to the parent of Config.SSHDir so that ssh
// resolves config, known_hosts, and identity files from Config.SSHDir
// (conventionally $HOME/.ssh).
package sshutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config controls the ssh child processes.
type Config struct {
	// SSHDir is the directory holding config, known_hosts, and identity
	// files (conventionally $HOME/.ssh). The child's HOME is set to its
	// parent so the system binaries resolve from here.
	SSHDir string

	// Binary paths; empty defaults to the name on PATH. Injectable for tests.
	SSH, SCP, Keyscan, Keygen string

	// ConnectTimeout is the per-connection timeout in seconds (A16: 10).
	ConnectTimeout int
}

// Default returns a Config with A16 defaults.
func Default(sshDir string) Config {
	return Config{SSHDir: sshDir, ConnectTimeout: 10}
}

func (c Config) sshBin() string {
	if c.SSH == "" {
		return "ssh"
	}
	return c.SSH
}
func (c Config) scpBin() string {
	if c.SCP == "" {
		return "scp"
	}
	return c.SCP
}
func (c Config) keyscanBin() string {
	if c.Keyscan == "" {
		return "ssh-keyscan"
	}
	return c.Keyscan
}
func (c Config) keygenBin() string {
	if c.Keygen == "" {
		return "ssh-keygen"
	}
	return c.Keygen
}

// home returns the HOME value for the child: the parent of SSHDir.
func (c Config) home() string { return filepath.Dir(c.SSHDir) }

// childEnv returns the environment for a child process with HOME set (and
// any pre-existing HOME replaced) to the parent of SSHDir, so ssh resolves
// config, known_hosts, and identity files from SSHDir.
func (c Config) childEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "HOME=") {
			continue
		}
		env = append(env, e)
	}
	return append(env, "HOME="+c.home())
}

// hardened returns the A16 hardened options: non-interactive, bounded
// connect, liveness keepalive, and known_hosts enforced (no silent TOFU).
func (c Config) hardened() []string {
	t := c.ConnectTimeout
	if t <= 0 {
		t = 10
	}
	return []string{
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", t),
		"-o", "ServerAliveInterval=15",
		"-o", "StrictHostKeyChecking=yes",
	}
}

// run is the shared exec helper: sets HOME to SSHDir's parent, captures
// stdout/stderr, and reports the exit code. A non-zero exit is reported via
// exit, not err (err is for launch failures only).
func (c Config) run(ctx context.Context, bin string, args ...string) (stdout, stderr string, exit int, err error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = c.childEnv()
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if runErr := cmd.Run(); runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			return out.String(), errb.String(), ee.ExitCode(), nil
		}
		return out.String(), errb.String(), -1, fmt.Errorf("sshutil: run %s: %w", bin, runErr)
	}
	return out.String(), errb.String(), 0, nil
}

// Run executes a command on the remote host over the operator's ssh.
func (c Config) Run(ctx context.Context, host, command string) (stdout, stderr string, exit int, err error) {
	return c.run(ctx, c.sshBin(), append(c.hardened(), host, command)...)
}

// Copy transfers a local file to host:remote over scp.
func (c Config) Copy(ctx context.Context, local, host, remote string) (string, error) {
	_, stderr, exit, err := c.run(ctx, c.scpBin(), append(c.hardened(), local, host+":"+remote)...)
	if err != nil {
		return stderr, err
	}
	if exit != 0 {
		return stderr, fmt.Errorf("sshutil: scp exit %d: %s", exit, strings.TrimSpace(stderr))
	}
	return "", nil
}

// HostKey captures the remote host key via ssh-keyscan and computes its
// fingerprint. Returns the key type (e.g. "ED25519"), the fingerprint
// (e.g. "SHA256:…"), and the raw keyscan line (for adding to known_hosts).
func (c Config) HostKey(ctx context.Context, host string) (keyType, fingerprint, keyLine string, err error) {
	// ssh-keyscan writes the key line to stdout.
	stdout, stderr, exit, err := c.run(ctx, c.keyscanBin(), "-t", "ed25519,ecdsa,rsa", host)
	if err != nil {
		return "", "", "", err
	}
	if exit != 0 {
		return "", "", "", fmt.Errorf("sshutil: keyscan %s exit %d: %s", host, exit, strings.TrimSpace(stderr))
	}
	line := firstNonComment(stdout)
	if line == "" {
		return "", "", "", fmt.Errorf("sshutil: no host key from %s", host)
	}
	ft, fp, ferr := fingerprintLine(c, ctx, line)
	if ferr != nil {
		return "", "", "", ferr
	}
	return ft, fp, line, nil
}

// HasHost reports whether host is already trusted in known_hosts
// (fingerprint gate, architecture §3.5).
func (c Config) HasHost(ctx context.Context, host string) (bool, error) {
	_, _, exit, err := c.run(ctx, c.keygenBin(), "-F", host)
	if err != nil {
		return false, err
	}
	return exit == 0, nil
}

// AddKey appends keyLine to known_hosts and hashes the file in place
// (ssh-keygen -H) so hostnames/keys are not plaintext at rest.
func (c Config) AddKey(ctx context.Context, keyLine string) error {
	if c.SSHDir == "" {
		return fmt.Errorf("sshutil: SSHDir required to add known host")
	}
	if err := os.MkdirAll(c.SSHDir, 0o700); err != nil {
		return fmt.Errorf("sshutil: mkdir ssh dir: %w", err)
	}
	kh := filepath.Join(c.SSHDir, "known_hosts")
	f, err := os.OpenFile(kh, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("sshutil: open known_hosts: %w", err)
	}
	if _, err := f.WriteString(keyLine + "\n"); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if _, _, exit, err := c.run(ctx, c.keygenBin(), "-H", "-f", kh); err != nil {
		return err
	} else if exit != 0 {
		return fmt.Errorf("sshutil: ssh-keygen -H exit %d", exit)
	}
	return nil
}

// fingerprintLine computes "TYPE FINGERPRINT" for a keyscan line via
// ssh-keygen -l -f - (reads stdin).
func fingerprintLine(c Config, ctx context.Context, line string) (string, string, error) {
	cmd := exec.CommandContext(ctx, c.keygenBin(), "-l", "-f", "-")
	cmd.Env = c.childEnv()
	cmd.Stdin = strings.NewReader(line + "\n")
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("sshutil: fingerprint: %w", err)
	}
	// Output: "<bits> <fingerprint> <comment> (<type>)"
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", "", fmt.Errorf("sshutil: bad fingerprint output %q", out)
	}
	ftype := ""
	if last := fields[len(fields)-1]; strings.Contains(last, "(") {
		ftype = strings.Trim(last, "() ")
	}
	return ftype, fields[1], nil
}

// firstNonComment returns the first non-blank, non-# line of s.
func firstNonComment(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}
