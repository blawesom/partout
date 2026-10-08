// Package elevate implements the host-level elevation policy (PRD Decision 3,
// first slice): when PARTOUT_ELEVATE=sudo, the agent runs its action-class
// commands (dispatched exec, PTY sessions, package apply, reboot, task steps)
// through `sudo -n` so the unprivileged `partout` service user can perform
// privileged operations — exactly the ones the host's sudoers file allows.
//
// Security model:
//   - fail-closed: nothing elevates unless the host's sudoers grants it; a
//     denied elevation surfaces as a normal command failure (exit != 0) and
//     is audited like any failed command;
//   - non-interactive: `sudo -n` never prompts, so no password is ever
//     needed or cached;
//   - scope lives in the operator-installed sudoers drop-in
//     (deploy/sudoers/partout-agent), never in the binary;
//   - host-level only: per-command elevation profiles (pattern-scoped,
//     policy-constrained) are the later full Decision 3 implementation.
//
// Note: a systemd unit with NoNewPrivileges=true blocks setuid, so sudo does
// not work until that line is removed from the agent unit (documented in
// deploy/systemd/README.md).
package elevate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Mode is the agent's host-level elevation policy.
type Mode string

const (
	// None runs every command as the agent user (the default).
	None Mode = "none"
	// Sudo prefixes action commands with `sudo -n`.
	Sudo Mode = "sudo"
)

// Parse normalizes a PARTOUT_ELEVATE / --elevate value. "sudoers" is accepted
// as an alias for "sudo" (PRD Decision 3 vocabulary): the actual scope is
// always the host's sudoers file.
func Parse(v string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none":
		return None, nil
	case "sudo", "sudoers":
		return Sudo, nil
	default:
		return None, fmt.Errorf("invalid elevation mode %q (want none|sudo)", v)
	}
}

// SudoPrefix returns the argv prefix for elevation, or nil when off.
func (m Mode) SudoPrefix() []string {
	if m == Sudo {
		return []string{"-n"}
	}
	return nil
}

// Run returns the (name, args) to execute under this policy.
func (m Mode) Run(name string, args ...string) (string, []string) {
	if m != Sudo {
		return name, args
	}
	out := make([]string, 0, len(args)+2)
	out = append(out, "-n", "--", name)
	out = append(out, args...)
	return "sudo", out
}

// RunCmd builds a ready-to-start *exec.Cmd under this policy.
func (m Mode) RunCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	n, a := m.Run(name, args...)
	return exec.CommandContext(ctx, n, a...)
}

// ErrDenied is returned when an elevated operation is refused by sudoers.
var ErrDenied = errors.New("elevation denied (no sudoers entry for this command, or NoNewPrivileges blocks setuid)")

// elevatedOutput runs `sudo -n cat path`. Indirect through a variable so
// tests can stub it (a real sudo is not available in the test environment).
var elevatedOutput = func(path string) ([]byte, error) {
	out, err := exec.Command("sudo", "-n", "--", "cat", path).Output()
	if err == nil {
		return out, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return nil, classifyExitError(string(ee.Stderr))
	}
	return nil, err
}

// classifyExitError maps sudo's stderr to a typed error: a sudoers denial
// becomes ErrDenied (the fail-closed signal an operator should act on);
// anything else passes through as a plain error.
func classifyExitError(stderr string) error {
	msg := strings.TrimSpace(stderr)
	if strings.Contains(msg, "not allowed") || strings.Contains(msg, "a password is required") {
		return fmt.Errorf("%w: %s", ErrDenied, msg)
	}
	return fmt.Errorf("elevated read failed: %s", msg)
}

// ReadFile reads path directly; under Sudo mode, if the direct read fails
// with a permission error, it retries via `sudo -n cat`. This is how the
// observe layer reads root-owned config files (e.g. haproxy.cfg) without the
// agent running as root.
//
// When a policy is loaded, the elevated retry is gated on it: the retry only
// happens if a rule covers `cat <path>` (fail closed — the legacy
// drop-in-scoped retry is the no-policy fallback). A nil policy keeps the
// legacy behavior of retrying on every EACCES in Sudo mode.
func ReadFile(m Mode, p *Policy, path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil || m != Sudo || !os.IsPermission(err) {
		return b, err
	}
	if p != nil && p.Check("cat", []string{path}) != Elevated {
		return nil, err
	}
	return elevatedOutput(path)
}

// ---------------------------------------------------------------------------
// Runner: one elevation decision for every action surface
// ---------------------------------------------------------------------------

// Runner decides how one action command is executed: the (name, args) pair
// to run after applying the elevation policy. Every action surface —
// dispatched exec, PTY sessions, task step commands, package operations,
// the reboot step — goes through the same Runner, so the contract holds
// everywhere: in sudo mode WITH a policy, a matching command elevates and a
// non-matching one runs UNPRIVILEGED; without a policy (legacy), everything
// is pushed through `sudo -n` and the host's sudoers drop-in decides
// (field feedback F10: PTY sessions and task steps previously used the raw
// Mode and bypassed the policy).
type Runner interface {
	// Wrap returns the (name, args) to execute for one action command.
	Wrap(name string, args ...string) (string, []string)
	// Elevates reports whether Wrap would run this command elevated.
	Elevates(name string, args ...string) bool
	// RunCmd builds a ready-to-start *exec.Cmd under this runner.
	RunCmd(ctx context.Context, name string, args ...string) *exec.Cmd
}

// Wrap implements Runner for a bare Mode (legacy: everything through sudo;
// the host's sudoers file is the authority).
func (m Mode) Wrap(name string, args ...string) (string, []string) {
	return m.Run(name, args...)
}

// Elevates implements Runner for a bare Mode.
func (m Mode) Elevates(name string, args ...string) bool {
	return m == Sudo
}

// PolicyRunner couples the elevation mode with a loaded policy: the
// agent-side authority on what may run elevated (PRD Decision 3, full).
// The policy is swappable at runtime (SetPolicy) — the server-signed
// policy push (P2) replaces the loaded scope in place so every surface
// holding the runner (exec, sessions, tasks, packages) sees the new scope
// without a restart.
type PolicyRunner struct {
	Mode Mode
	// policy is guarded by mu: a runtime swap (SetPolicy) must not race an
	// in-flight Wrap/Elevates/Explain on another goroutine.
	mu     sync.RWMutex
	policy *Policy
	// OutOfScope, when set, is called with the full command line whenever
	// a command runs unprivileged because no policy rule matches it (the
	// agent logs it as a first-class event).
	OutOfScope func(cmdline string)
}

// NewPolicyRunner builds the policy-aware runner. A nil policy degenerates
// to the legacy Mode behavior.
func NewPolicyRunner(m Mode, p *Policy, outOfScope func(string)) *PolicyRunner {
	return &PolicyRunner{Mode: m, policy: p, OutOfScope: outOfScope}
}

// SetPolicy atomically replaces the loaded policy (nil = legacy mode).
func (r *PolicyRunner) SetPolicy(p *Policy) {
	r.mu.Lock()
	r.policy = p
	r.mu.Unlock()
}

func (r *PolicyRunner) current() *Policy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.policy
}

// Wrap implements Runner: a policy match elevates; a non-match runs
// UNPRIVILEGED (and is reported through OutOfScope) instead of being
// pushed through sudo on faith. A nil policy is LEGACY: everything is
// pushed through sudo (the hand-installed drop-in decides) — Check on a
// nil policy returns Denied, so the nil case must be handled explicitly.
func (r *PolicyRunner) Wrap(name string, args ...string) (string, []string) {
	if p := r.current(); p != nil && r.Mode == Sudo && p.Check(name, args) == Denied {
		if r.OutOfScope != nil {
			r.OutOfScope(strings.Join(append([]string{name}, args...), " "))
		}
		return name, args
	}
	return r.Mode.Run(name, args...)
}

// Elevates implements Runner.
func (r *PolicyRunner) Elevates(name string, args ...string) bool {
	if r.Mode != Sudo {
		return false
	}
	if p := r.current(); p == nil {
		return true // legacy: everything is pushed through sudo
	} else {
		return p.Check(name, args) == Elevated
	}
}

// RunCmd implements Runner.
func (r *PolicyRunner) RunCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	n, a := r.Wrap(name, args...)
	return exec.CommandContext(ctx, n, a...)
}

// Explain reports the elevation decision for (name, args) with a
// human-readable reason: which policy rule matched, that none matched
// (the command runs unprivileged), that elevation is off, or that the
// legacy no-policy path pushed the command through sudo. It is recorded on
// every run row so "why didn't my command elevate?" is a one-glance
// answer instead of an agent-log dive.
func (r *PolicyRunner) Explain(name string, args ...string) (elevated bool, note string) {
	switch {
	case r.Mode != Sudo:
		return false, "elevation off (PARTOUT_ELEVATE=" + string(r.Mode) + ")"
	case r.current() == nil:
		// Legacy: everything is pushed through sudo -n and the
		// hand-installed sudoers drop-in decides.
		return true, "legacy mode: no elevation policy loaded — pushed through sudo, the host sudoers drop-in decides"
	case r.current().Check(name, args) == Elevated:
		return true, "policy rule matched: " + describeRule(r.current().RuleFor(name, args))
	default:
		return false, "no elevation rule matches this command — ran unprivileged (add a rule to the elevation policy to elevate it)"
	}
}

// describeRule renders a compact, human-readable summary of a matched rule
// (nil-safe). It mirrors the rule's own matcher vocabulary so the note can
// be traced straight back to the policy document.
func describeRule(r *Rule) string {
	if r == nil {
		return "<unknown rule>"
	}
	var parts []string
	parts = append(parts, r.Allow)
	switch {
	case len(r.Verbs) > 0 || len(r.Units) > 0:
		if len(r.Verbs) > 0 {
			parts = append(parts, "verbs="+strings.Join(r.Verbs, ","))
		}
		if len(r.Units) > 0 {
			parts = append(parts, "units="+strings.Join(r.Units, ","))
		}
	case len(r.Args) > 0:
		parts = append(parts, "args="+strings.Join(r.Args, " "))
	case len(r.Files) > 0:
		parts = append(parts, "files="+strings.Join(r.Files, ","))
	default:
		parts = append(parts, "(bare command, no arguments)")
	}
	return strings.Join(parts, " ")
}
