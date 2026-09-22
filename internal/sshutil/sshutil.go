// Package sshutil is a thin wrapper around the operator's *system*
// ssh/scp/ssh-keyscan/ssh-keygen binaries (architecture §3.5, A16).
//
// Deliberately not a Go SSH client library: the operator's ~/.ssh/config,
// known_hosts, ssh-agent, and ProxyJump all keep working as-is. Partout
// never creates, copies, or persists operator credentials — it only drives
// the system binaries the operator has already configured.
//
// # SSH dir redirection
//
// Config.SSHDir is authoritative. It is *not* applied via $HOME: OpenSSH
// resolves ~/.ssh from the passwd database (getpwuid), so overriding HOME is
// silently ignored for config/known_hosts/identity lookups. The wrapper
// therefore passes the paths explicitly to every command:
//
//	-F <SSHDir>/config                        (replaces the per-user config)
//	-o UserKnownHostsFile=<SSHDir>/known_hosts
//	-o IdentityFile=<SSHDir>/id_{ed25519,ecdsa,rsa}   (when present)
//
// Consequence: with a non-default SSHDir the operator's own ~/.ssh/config is
// NOT read (ssh's -F replaces it) — the isolated dir's config is the
// contract. With the default SSHDir ($HOME/.ssh) the two are the same file
// and behaviour is unchanged. ssh-agent keys are still offered unless the
// caller disables agent auth in config.
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

// home returns the HOME value for the child: the parent of SSHDir. This is
// only a best-effort hint (see dirArgs): OpenSSH resolves ~/.ssh from the
// passwd database, not from $HOME, so HOME alone is NOT sufficient to point
// ssh at SSHDir.
func (c Config) home() string { return filepath.Dir(c.SSHDir) }

// childEnv returns the environment for a child process with HOME set (and
// any pre-existing HOME replaced) to the parent of SSHDir.
//
// NOTE: $HOME alone does not redirect OpenSSH's ~/.ssh lookups — ssh uses
// getpwuid() for the user's home. It stays here only because some helpers
// (and non-OpenSSH binaries) honour it, and because ProxyCommand scripts may
// rely on it. The authoritative redirection is dirArgs(), which passes the
// paths explicitly.
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

// knownHostsPath returns the path to the known_hosts file inside SSHDir.
func (c Config) knownHostsPath() string { return filepath.Join(c.SSHDir, "known_hosts") }

// configPath returns the path to the ssh config file inside SSHDir.
func (c Config) configPath() string { return filepath.Join(c.SSHDir, "config") }

// dirArgs returns the OpenSSH options that pin ssh/scp to SSHDir explicitly:
// the config file, the user known_hosts file, and the identity files.
//
// OpenSSH resolves ~/.ssh from the passwd database rather than $HOME, so
// passing these explicitly is the only reliable way to honour PARTOUT_SSH_DIR.
//
// ssh refuses to start when -F points at a missing file, so an empty config
// is created on demand. If SSHDir is empty, no redirection is applied (the
// current user's default ~/.ssh is used).
func (c Config) dirArgs() []string {
	if c.SSHDir == "" {
		return nil
	}
	// Ensure the config file exists (ssh exits 255 on a missing -F target).
	cfg := c.configPath()
	if _, err := os.Stat(cfg); err != nil {
		if err := os.MkdirAll(c.SSHDir, 0o700); err != nil {
			return nil // fall back to defaults rather than break the command
		}
		_ = os.WriteFile(cfg, nil, 0o600)
	}
	args := []string{
		"-F", cfg,
		"-o", "UserKnownHostsFile=" + c.knownHostsPath(),
	}
	// Conventional key names, in the order OpenSSH itself tries them.
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		p := filepath.Join(c.SSHDir, name)
		if _, err := os.Stat(p); err == nil {
			args = append(args, "-o", "IdentityFile="+p)
		}
	}
	return args
}

// hardened returns the A16 hardened options: non-interactive, bounded
// connect, liveness keepalive, known_hosts enforced (no silent TOFU), plus
// the explicit SSHDir redirection (dirArgs).
func (c Config) hardened() []string {
	t := c.ConnectTimeout
	if t <= 0 {
		t = 10
	}
	args := []string{
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", t),
		"-o", "ServerAliveInterval=15",
		"-o", "StrictHostKeyChecking=yes",
	}
	return append(args, c.dirArgs()...)
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
// (fingerprint gate, architecture §3.5). It checks SSHDir's known_hosts
// explicitly: `ssh-keygen -F` otherwise consults the passwd-db home, which
// would silently ignore PARTOUT_SSH_DIR.
func (c Config) HasHost(ctx context.Context, host string) (bool, error) {
	args := []string{"-F", host}
	if c.SSHDir != "" {
		args = append(args, "-f", c.knownHostsPath())
	}
	_, _, exit, err := c.run(ctx, c.keygenBin(), args...)
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
	kh := c.knownHostsPath()
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
