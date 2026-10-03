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
	"strconv"
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

// conventionalIdentityNames are the identity files OpenSSH itself tries, in
// order. This is the single source of truth for both the actual SSH args
// (dirArgs) and the readiness report (IdentityStatus), so the two can never
// drift.
var conventionalIdentityNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// IdentityStatus reports which identity keys a Config would offer for host
// provisioning: the conventional file keys present in SSHDir (in OpenSSH
// order), config-declared IdentityFile entries that exist (resolved for the
// probed host), and whether the ssh-agent holds a key. It returns paths
// only — never key material. Shared by `partout doctor` and the provisioning
// ssh-status endpoint so both report exactly what the provisioner will use.
type IdentityStatus struct {
	SSHDir     string   `json:"ssh_dir"`
	FileKeys   []string `json:"file_keys"`
	ConfigKeys []string `json:"config_keys"` // ssh-config IdentityFile entries that exist (host-specific when host is given)
	Agent      bool     `json:"agent"`
}

// Found reports whether an identity key is available (a conventional file
// key, a config-declared key, or an agent key).
func (s IdentityStatus) Found() bool { return len(s.FileKeys) > 0 || len(s.ConfigKeys) > 0 || s.Agent }

// identityProbeHost is the destination used to expand a host-agnostic ssh
// config for key discovery: a reserved-TLD name that no sane config matches
// except "Host *" blocks, so defaults and global sections are honored while
// host-specific ones are not (callers with a real host pass it instead).
const identityProbeHost = "partout-probe.invalid"

// IdentityStatus inspects SSHDir and the ssh-agent to report which identity
// keys this Config would offer, probing the config host-agnostically. See
// IdentityStatusFor for the host-specific (alias-aware) variant.
func (c Config) IdentityStatus() IdentityStatus {
	return c.IdentityStatusFor(context.Background(), "")
}

// IdentityStatusFor reports which identity keys this Config would offer when
// connecting to host: the conventional files in SSHDir, the ssh-agent, and —
// via `ssh -G <host>` (no connection, no DNS) — every IdentityFile the ssh
// config declares for that host, kept when the file exists. This is what
// makes host-specific "Host <name> / IdentityFile <key>" blocks visible:
// they are real offered keys that a conventional-name scan never finds. An
// empty host probes host-agnostically (defaults + "Host *" sections only).
func (c Config) IdentityStatusFor(ctx context.Context, host string) IdentityStatus {
	s := IdentityStatus{SSHDir: c.SSHDir, FileKeys: []string{}, ConfigKeys: []string{}}
	if c.SSHDir != "" {
		for _, name := range conventionalIdentityNames {
			p := filepath.Join(c.SSHDir, name)
			if _, err := os.Stat(p); err == nil {
				s.FileKeys = append(s.FileKeys, name)
			}
		}
	}
	s.Agent = agentHasKeys()

	if host == "" {
		host = identityProbeHost
	}
	args := append(c.dirArgs(), "-G", bareHost(host))
	stdout, _, exit, err := c.run(ctx, c.sshBin(), args...)
	if err != nil || exit != 0 {
		return s // no readable config: conventional + agent is the truth
	}
	home, _ := os.UserHomeDir()
	seen := map[string]bool{}
	for _, name := range s.FileKeys { // conventional paths are already reported
		seen[filepath.Join(c.SSHDir, name)] = true
	}
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if !ok || k != "identityfile" {
			continue
		}
		p := strings.TrimSpace(v)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "~/") && home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
		if seen[p] {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			continue
		}
		seen[p] = true
		s.ConfigKeys = append(s.ConfigKeys, p)
	}
	return s
}

// agentHasKeys reports whether the ssh-agent holds at least one key. It is
// read-only and bounded: with no SSH_AUTH_SOCK it returns false immediately,
// as does a missing ssh-add or an agent with no keys.
func agentHasKeys() bool {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return false
	}
	return exec.Command("ssh-add", "-l").Run() == nil
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

// configArgs returns just the -F pin for SSHDir, materializing an empty
// config on demand (ssh exits 255 when -F points at a missing file).
func (c Config) configArgs() []string {
	if c.SSHDir == "" {
		return nil
	}
	cfg := c.configPath()
	if _, err := os.Stat(cfg); err != nil {
		if err := os.MkdirAll(c.SSHDir, 0o700); err != nil {
			return nil // fall back to defaults rather than break the command
		}
		_ = os.WriteFile(cfg, nil, 0o600)
	}
	return []string{"-F", cfg}
}

// dirArgs returns the OpenSSH options that pin ssh/scp to SSHDir explicitly:
// the config file, the user known_hosts file, and the identity files.
//
// OpenSSH resolves ~/.ssh from the passwd database rather than $HOME, so
// passing these explicitly is the only reliable way to honour PARTOUT_SSH_DIR.
//
// If SSHDir is empty, no redirection is applied (the current user's default
// ~/.ssh is used).
func (c Config) dirArgs() []string {
	args := c.configArgs()
	if args == nil {
		return nil
	}
	args = append(args, "-o", "UserKnownHostsFile="+c.knownHostsPath())
	// Conventional key names, in the order OpenSSH itself tries them.
	for _, name := range conventionalIdentityNames {
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

// bareHost strips the optional user@ prefix from a target so it can be passed
// to host-key tooling. ssh-keyscan and ssh-keygen -F take a hostname, not an
// ssh target: "root@127.0.0.1" makes keyscan fail with a name resolution
// error, which used to fail every provision run at the key-confirm gate.
func bareHost(host string) string {
	if i := strings.LastIndex(host, "@"); i >= 0 {
		return host[i+1:]
	}
	return host
}

// ResolvedTarget is the effective connection target for a provision host,
// expanded from the operator's ssh config.
type ResolvedTarget struct {
	// Host is the post-config hostname: what OpenSSH actually connects to
	// and what known_hosts entries are keyed under.
	Host string
	// Port is the post-config port (22 when unset).
	Port int
	// KeyAlias is the ssh config's HostKeyAlias: when set, ssh keys
	// known_hosts under this name instead of the hostname.
	KeyAlias string
	// ViaProxy is true when the connection goes through a ProxyJump or
	// ProxyCommand — raw-TCP keyscan cannot reach such hosts.
	ViaProxy bool
}

// Name returns the known_hosts key for this target: "[host]:port" for
// non-default ports, the bare host otherwise — the same form ssh-keyscan
// emits and ssh looks up. A HostKeyAlias replaces the hostname entirely.
func (r ResolvedTarget) Name() string {
	name := r.Host
	if r.KeyAlias != "" {
		name = r.KeyAlias
	}
	if r.Port != 0 && r.Port != 22 {
		return fmt.Sprintf("[%s]:%d", name, r.Port)
	}
	return name
}

// ResolveHost expands a provision target through the operator's ssh config
// using `ssh -G` (print-only: no connection is made, no DNS is touched).
// This is what makes ssh-config aliases work at the key-confirm gate:
// ssh-keyscan and ssh-keygen -F do not read ssh config, so they must be
// pointed at the resolved hostname (+port) instead of the alias. A literal
// host/IP with no config entry resolves to itself.
func (c Config) ResolveHost(ctx context.Context, target string) (ResolvedTarget, error) {
	res := ResolvedTarget{Host: bareHost(target), Port: 22}
	args := append(c.dirArgs(), "-G", bareHost(target))
	stdout, stderr, exit, err := c.run(ctx, c.sshBin(), args...)
	if err != nil {
		return res, fmt.Errorf("sshutil: resolve %s: %w", target, err)
	}
	if exit != 0 {
		return res, fmt.Errorf("sshutil: ssh -G %s exit %d: %s", target, exit, strings.TrimSpace(stderr))
	}
	// `ssh -G` prints the fully-expanded effective config, one "key value"
	// per line (values may contain spaces — e.g. ProxyCommand). Only
	// hostname/port/aliases matter here; unknown lines are ignored (an empty
	// parse keeps the literal target — no config entry).
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		v = strings.TrimSpace(v)
		if !ok || v == "" || v == "none" {
			continue
		}
		switch k {
		case "hostname":
			res.Host = v
		case "port":
			if p, perr := strconv.Atoi(v); perr == nil && p > 0 {
				res.Port = p
			}
		case "hostkeyalias":
			res.KeyAlias = v
		case "proxyjump", "proxycommand":
			res.ViaProxy = true
		}
	}
	return res, nil
}

// resolveForHostTools resolves a target for host-key tooling (keyscan,
// ssh-keygen -F), falling back to the legacy literal target when ssh -G
// fails (pre-6.8 OpenSSH without -G, or an unreadable config): the keyscan
// then fails exactly as it would have before alias support, rather than
// breaking literal-IP flows that never needed resolution.
func (c Config) resolveForHostTools(ctx context.Context, target string) ResolvedTarget {
	res, err := c.ResolveHost(ctx, target)
	if err != nil {
		return ResolvedTarget{Host: bareHost(target), Port: 22}
	}
	return res
}

// HostKey captures the remote host key and computes its fingerprint.
// Returns the key type (e.g. "ED25519"), the fingerprint (e.g.
// "SHA256:…"), and the raw key line (for adding to known_hosts). The
// target is resolved through the ssh config first (ssh -G). Direct
// keyscan is used when the target is raw-TCP reachable and known_hosts
// is keyed under the hostname; through a ProxyJump/ProxyCommand — or with
// a HostKeyAlias — the key is captured via ssh itself (see hostKeyViaSSH),
// because ssh-keyscan reads no config and keys its output under the
// hostname.
func (c Config) HostKey(ctx context.Context, host string) (keyType, fingerprint, keyLine string, err error) {
	res := c.resolveForHostTools(ctx, host)
	if res.ViaProxy || res.KeyAlias != "" {
		return c.hostKeyViaSSH(ctx, host)
	}
	args := []string{"-t", "ed25519,ecdsa,rsa"}
	if res.Port != 22 {
		args = append(args, "-p", strconv.Itoa(res.Port))
	}
	args = append(args, res.Host)
	// ssh-keyscan writes the key line to stdout.
	stdout, stderr, exit, err := c.run(ctx, c.keyscanBin(), args...)
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

// hostKeyViaSSH captures the host key by connecting with ssh itself into a
// throwaway known_hosts — the only transport that honors ProxyJump and
// ProxyCommand (ssh-keyscan does raw TCP and reads no config) and the only
// one that keys the line the way a HostKeyAlias config expects. The key
// exchange happens before authentication, so even a BatchMode auth failure
// still records the key. StrictHostKeyChecking=accept-new applies ONLY to
// the throwaway file: the operator's key_confirm gate stays the sole path
// into the real known_hosts, so this is a capture transport, not silent
// TOFU.
//
// NOTE: OpenSSH keeps the FIRST value for a repeated option, so these
// options must not be appended after dirArgs()/hardened() (both pin
// UserKnownHostsFile and strict checking) — the invocation is built on the
// config pin alone.
func (c Config) hostKeyViaSSH(ctx context.Context, host string) (keyType, fingerprint, keyLine string, err error) {
	tmp, err := os.CreateTemp("", "partout-hostkey-*")
	if err != nil {
		return "", "", "", fmt.Errorf("sshutil: temp known_hosts: %w", err)
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)
	_ = os.Chmod(tmpName, 0o600)

	t := c.ConnectTimeout
	if t <= 0 {
		t = 10
	}
	args := append(c.configArgs(),
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", t),
		"-o", "UserKnownHostsFile="+tmpName,
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "LogLevel=ERROR",
		host, "true")
	if _, _, _, rerr := c.run(ctx, c.sshBin(), args...); rerr != nil {
		return "", "", "", fmt.Errorf("sshutil: capture %s: %w", host, rerr)
	}
	// An auth failure is expected and fine (kex precedes auth); a missing
	// key line means the capture itself failed to reach the target.
	data, rerr := os.ReadFile(tmpName)
	if rerr != nil {
		return "", "", "", fmt.Errorf("sshutil: read captured key: %w", rerr)
	}
	line := firstEd25519(string(data))
	if line == "" {
		return "", "", "", fmt.Errorf("sshutil: no host key captured from %s — is the target reachable through its ProxyJump/ProxyCommand?", host)
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
// would silently ignore PARTOUT_SSH_DIR. The target is resolved through
// the ssh config first (ssh -G) so an alias is looked up under the name
// ssh actually verifies — the resolved hostname, [host]:port for non-default
// ports.
func (c Config) HasHost(ctx context.Context, host string) (bool, error) {
	res := c.resolveForHostTools(ctx, host)
	args := []string{"-F", res.Name()}
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
	// Idempotent: a duplicate confirm (double-click, retry) must not append
	// the same key twice.
	if name := knownHostName(keyLine); name != "" {
		if has, err := c.hasName(ctx, name); err == nil && has {
			return nil
		}
	}
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

// RemoveHost removes every known_hosts entry for name (plain and hashed —
// ssh-keygen -R handles both). Used by the key-rotation re-confirm flow: a
// reinstalled host presents a new key, the operator re-gates it through
// key_confirm instead of hand-editing a hashed file with ssh-keygen -R.
func (c Config) RemoveHost(ctx context.Context, name string) error {
	if c.SSHDir == "" {
		return fmt.Errorf("sshutil: SSHDir required to remove known host")
	}
	args := []string{"-R", name, "-f", c.knownHostsPath()}
	_, _, exit, err := c.run(ctx, c.keygenBin(), args...)
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("sshutil: ssh-keygen -R %s exit %d", name, exit)
	}
	return nil
}

// hasName reports whether known_hosts holds an entry for name (used for
// AddKey idempotency).
func (c Config) hasName(ctx context.Context, name string) (bool, error) {
	args := []string{"-F", name, "-f", c.knownHostsPath()}
	_, _, exit, err := c.run(ctx, c.keygenBin(), args...)
	if err != nil {
		return false, err
	}
	return exit == 0, nil
}

// knownHostName returns the known_hosts key (first field) of a key line —
// the name entries are looked up by.
func knownHostName(keyLine string) string {
	if f := strings.Fields(keyLine); len(f) > 0 {
		return f[0]
	}
	return ""
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

// firstEd25519 returns the first non-blank, non-# line of s, preferring an
// ed25519 key line (ssh writes every key type it accepted at kex; the
// gate's keyscan path prefers ed25519 too, so both paths agree on what the
// operator is confirming).
func firstEd25519(s string) string {
	first := ""
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if first == "" {
			first = l
		}
		if strings.Contains(l, " ssh-ed25519 ") {
			return l
		}
	}
	return first
}
