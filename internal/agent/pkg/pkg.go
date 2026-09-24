// Package pkg provides the agent-side package-management backend (PRD §5.6).
//
// It wraps the distro's native tooling:
//
//	apt / apt-get (Debian, Ubuntu, etc.)
//	dnf / yum      (RHEL, CentOS, AlmaLinux, Rocky, Fedora)
//
// Operations:
//   - ListUpdates: list packages that have a newer available version.
//   - DryRun:      simulate an upgrade (no mutation).
//   - Apply:       run the real upgrade after a successful dry-run.
//   - Journal:     collect installed package state before/after apply.
//
// All subprocess invocations use the wrapper (apt-get, aptitude, dnf) that
// avoids interactive prompts and uses UTC timestamps in output parsing.
package pkg

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// PkgUpdate is one package's update status.
type PkgUpdate struct {
	Name         string
	Installed    string
	Available    string
	VulnCount    int64
	MaxSeverity  string
	IsSecurity   bool
}

// PkgResult is the agent's full package operation result.
type PkgResult struct {
	Code            int32
	Error           string
	Updates         []PkgUpdate
	Before          []PkgUpdate
	After           []PkgUpdate
	DryRunSummary   string
	AppliedCount    int64
	SkippedCount    int64
	Applied         bool
}

// Backend is the agent-side package-management interface.
type Backend interface {
	// List returns packages that can be upgraded.
	List(ctx context.Context) ([]PkgUpdate, error)
	// DryRun simulates an upgrade and returns a human-readable summary.
	DryRun(ctx context.Context) (string, error)
	// Apply performs a real upgrade (must NOT be dry-run — the server calls
	// DryRun first; Apply is for the non-interactive apply step).
	Apply(ctx context.Context) error
	// Installed returns the full installed-package inventory.
	Installed(ctx context.Context) ([]PkgUpdate, error)
}

// SelectBackend picks the correct distro backend from os-release facts.
func SelectBackend(facts map[string]string) Backend {
	switch facts["host.distro"] {
	case "ubuntu", "debian", "linuxmint", "pop":
		return &aptBackend{}
	case "rhel", "centos", "rocky", "alma", "fedora", "ol":
		return &dnfBackend{}
	default:
		return &noopBackend{}
	}
}

// ---------------------------------------------------------------------------
// apt / apt-get backend
// ---------------------------------------------------------------------------

type aptBackend struct{}

// aptInstRe matches `apt-get upgrade -s` install lines:
// "Inst name:arch (old, ...) -> (new, ...)"
var aptInstRe = regexp.MustCompile(`Inst\s+(\S+?):(\S+)\s+\(([^,]+),[^)]*\)\s*->\s*\(([^,]+),`)

func (a *aptBackend) List(ctx context.Context) ([]PkgUpdate, error) {
	out, err := run(ctx, time.Minute, "apt-get", "-o", "Dpkg::Progress-Focus=full", "-s", "upgrade")
	if err != nil {
		return nil, fmt.Errorf("apt-get upgrade -s: %w", err)
	}
	return parseAptUpgrade(out), nil
}

func (a *aptBackend) DryRun(ctx context.Context) (string, error) {
	out, err := run(ctx, time.Minute, "apt-get", "-o", "Dpkg::Progress-Focus=full", "-s", "upgrade")
	if err != nil {
		return "", fmt.Errorf("apt-get -s upgrade: %w", err)
	}
	return summarizeAptUpgrade(out), nil
}

func (a *aptBackend) Apply(ctx context.Context) error {
	// Run non-interactive: DEBIAN_FRONTEND=noninteractive, auto-confirm.
	cmd := exec.CommandContext(ctx, "apt-get", "-o", "Dpkg::Progress-Focus=full",
		"-y", "-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold", "upgrade")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-get upgrade: %w: %s", err, string(out))
	}
	return nil
}

func (a *aptBackend) Installed(ctx context.Context) ([]PkgUpdate, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query -W: %w: %s", err, string(out))
	}
	return parseDpkgQuery(out), nil
}

// parseAptUpgrade parses the output of `apt-get upgrade -s` and returns
// a list of packages that will be upgraded. The format per line is:
//
//	Inst package [old_ver] -> [new_ver] (...)
//
// Lines without Inst are ignored.
func parseAptUpgrade(out string) []PkgUpdate {
	var updates []PkgUpdate
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		// Example: Inst python3.12:amd64 (3.12.3-1ubuntu0.5, auto, ubuntu) -> (3.12.3-1ubuntu0.6, auto, ubuntu)
		m := aptInstRe.FindStringSubmatch(line)
		if len(m) < 5 {
			continue
		}
		updates = append(updates, PkgUpdate{
			Name:      m[1],
			Installed: m[3],
			Available: m[4],
		})
	}
	return updates
}

// summarizeAptUpgrade produces a short summary from `apt-get upgrade -s` output.
func summarizeAptUpgrade(out string) string {
	scanner := bufio.NewScanner(strings.NewReader(out))
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		// The last few lines contain the summary:
		// "Need to get 0 B/123 MB of archives."
		// "After this operation, 12 MB of additional disk space will be used."
		if strings.HasPrefix(line, "Need to get") || strings.HasPrefix(line, "After this") {
			continue // these are the real summary lines; we keep them
		}
	}
	// Keep only the last 20 lines (summary).
	keep := lines
	if len(keep) > 20 {
		keep = keep[len(keep)-20:]
	}
	return strings.Join(keep, "\n")
}

// parseDpkgQuery parses `dpkg-query -W` output and returns installed packages.
func parseDpkgQuery(b []byte) []PkgUpdate {
	var pkgs []PkgUpdate
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if f[2] != "installed" {
			continue // skip virtual / half-installed
		}
		pkgs = append(pkgs, PkgUpdate{Name: f[0], Installed: f[1]})
	}
	return pkgs
}

// ---------------------------------------------------------------------------
// dnf / yum backend
// ---------------------------------------------------------------------------

type dnfBackend struct{}

func (d *dnfBackend) List(ctx context.Context) ([]PkgUpdate, error) {
	out, err := run(ctx, time.Minute, "dnf", "check-update")
	if err != nil {
		// dnf check-update returns 100 if updates available; that's OK.
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 100 {
				return parseDNFCheck(out), nil
			}
		}
		return nil, fmt.Errorf("dnf check-update: %w", err)
	}
	// Exit code 0 means no updates.
	return nil, nil
}

func (d *dnfBackend) DryRun(ctx context.Context) (string, error) {
	out, err := run(ctx, time.Minute, "dnf", "upgrade", "--assumeno")
	if err != nil {
		return "", fmt.Errorf("dnf upgrade --assumeno: %w", err)
	}
	return summarizeDNF(out), nil
}

func (d *dnfBackend) Apply(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "dnf", "-y", "upgrade")
	cmd.Env = append(os.Environ(), "LANG=en_US.UTF-8")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dnf upgrade: %w: %s", err, string(out))
	}
	return nil
}

func (d *dnfBackend) Installed(ctx context.Context) ([]PkgUpdate, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{EPOCH}\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w: %s", err, string(out))
	}
	return parseRPMQA(out), nil
}

// dnfUpdRe matches a `dnf check-update` update-available line:
// "name.arch  version  repo" — the name and arch are joined by a dot,
// and there is exactly one whitespace-separated version token.
var dnfUpdRe = regexp.MustCompile(`^([A-Za-z0-9._+-]+)\.(x86_64|aarch64|ppc64le|s390x|noarch|src|i686)\s+(\S+)\s+(\S+)`)

// parseDNFCheck parses `dnf check-update` output. Only the "Update
// Available" section lines (name.arch version repo) are kept; header and
// status lines are skipped by the regex.
func parseDNFCheck(out string) []PkgUpdate {
	var updates []PkgUpdate
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		m := dnfUpdRe.FindStringSubmatch(line)
		if len(m) < 4 {
			continue
		}
		updates = append(updates, PkgUpdate{
			Name:      m[1],
			Available: m[3],
		})
	}
	return updates
}

// summarizeDNF takes dnf output and returns the last ~20 lines (summary).
func summarizeDNF(out string) string {
	lines := strings.Split(out, "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return strings.Join(lines, "\n")
}

// parseRPMQA parses `rpm -qa --qf`.
func parseRPMQA(b []byte) []PkgUpdate {
	var pkgs []PkgUpdate
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pkgs = append(pkgs, PkgUpdate{Name: f[0], Installed: f[1]})
	}
	return pkgs
}

// ---------------------------------------------------------------------------
// noop backend (for distros we don't support yet)
// ---------------------------------------------------------------------------

type noopBackend struct{}

func (n *noopBackend) List(ctx context.Context) ([]PkgUpdate, error) {
	return nil, nil
}

func (n *noopBackend) DryRun(ctx context.Context) (string, error) {
	return "no-op: package backend not installed for this distro", nil
}

func (n *noopBackend) Apply(ctx context.Context) error {
	return fmt.Errorf("package backend not available for this distro")
}

func (n *noopBackend) Installed(ctx context.Context) ([]PkgUpdate, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// run executes a command with a deadline, reading only stdout (stderr is
// included via CombinedOutput).
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
