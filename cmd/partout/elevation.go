// Command partout ctl elevation — the operator's tool for the elevation
// policy (PRD Decision 3, full slice). Local: no server round-trip.
//
// The policy (PARTOUT_ELEVATION_POLICY: one .json file or a *.json
// drop-in dir) is the single declarative source of truth. The agent runs a
// command elevated only when a rule matches; this command renders the
// sudoers drop-in from the same policy, so the agent's belief and the
// kernel's wall can be kept — and checked — in sync.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/blawesom/partout/internal/agent/elevate"
)

func elevationLoad(policy string) *elevate.Policy {
	pol, err := elevate.Load(policy)
	if err != nil {
		fatal(fmt.Errorf("load elevation policy: %w", err))
	}
	return pol
}

func elevationRuleDesc(r elevate.Rule) string {
	switch {
	case len(r.Args) > 0:
		return "args: " + strings.Join(r.Args, " ")
	case len(r.Verbs) > 0:
		return "verbs " + strings.Join(r.Verbs, ",") + " × units " + strings.Join(r.Units, ",")
	case len(r.Files) > 0:
		return "files " + strings.Join(r.Files, ",")
	}
	return ""
}

func elevationShow(policy string) {
	pol := elevationLoad(policy)
	if pol == nil {
		fmt.Printf("no elevation policy at %s — legacy behavior: the hand-installed sudoers drop-in decides\n", policy)
		return
	}
	fmt.Printf("policy: %s (%d rules)\n", strings.Join(pol.Source(), ", "), len(pol.Rules))
	if len(pol.Rules) == 0 {
		fmt.Println("  (no rules — with PARTOUT_ELEVATE=sudo nothing elevates; every command runs unprivileged)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "#\tCOMMAND\tSCOPE\tENV")
	for i, r := range pol.Rules {
		env := ""
		if len(r.Env) > 0 {
			env = strings.Join(r.Env, ",")
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", i+1, r.Allow, elevationRuleDesc(r), env)
	}
	w.Flush()
}

// elevationDiff is a minimal line diff (no dependencies): "-" lines are in
// the installed file only, "+" lines in the rendered one.
func elevationDiff(installed, rendered string) string {
	a := strings.Split(strings.TrimRight(installed, "\n"), "\n")
	b := strings.Split(strings.TrimRight(rendered, "\n"), "\n")
	var out []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		// Small lookahead keeps trivial shifts readable.
		foundB := false
		for k := i; k < len(a) && k < i+3; k++ {
			if a[k] == b[j] {
				for ; i < k; i++ {
					out = append(out, "- "+a[i])
				}
				foundB = true
				break
			}
		}
		if foundB {
			j++
			continue
		}
		foundA := false
		for k := j; k < len(b) && k < j+3; k++ {
			if a[i] == b[k] {
				for ; j < k; j++ {
					out = append(out, "+ "+b[j])
				}
				foundA = true
				break
			}
		}
		if foundA {
			i++
			continue
		}
		out = append(out, "- "+a[i], "+ "+b[j])
		i++
		j++
	}
	for ; i < len(a); i++ {
		out = append(out, "- "+a[i])
	}
	for ; j < len(b); j++ {
		out = append(out, "+ "+b[j])
	}
	return strings.Join(out, "\n")
}

func elevationCheck(policy, sudoersPath, user string) {
	pol := elevationLoad(policy)
	if pol == nil {
		fmt.Printf("no elevation policy at %s — nothing to check (legacy drop-in in force, if any)\n", policy)
		os.Exit(2)
	}
	rendered, err := pol.RenderSudoers(user)
	if err != nil {
		fatal(err)
	}
	installed, err := os.ReadFile(sudoersPath)
	if err != nil {
		fmt.Printf("no drop-in installed at %s — run: sudo /usr/local/bin/partout ctl elevation install-sudoers\n", sudoersPath)
		os.Exit(2)
	}
	if strings.TrimSpace(string(installed)) == strings.TrimSpace(rendered) {
		fmt.Printf("in sync: %s matches the policy (sha256 %s…)\n", sudoersPath, pol.PolicyHash()[:12])
		return
	}
	fmt.Printf("DRIFT: %s does not match the policy (sha256 %s…)\n", sudoersPath, pol.PolicyHash()[:12])
	// Full path: sudo's secure_path commonly excludes /usr/local/bin, so
	// the bare `sudo partout …` form fails with "command not found" on
	// RHEL-family (field feedback F16).
	fmt.Println("reinstall with: sudo /usr/local/bin/partout ctl elevation install-sudoers")
	fmt.Println()
	if d := elevationDiff(string(installed), rendered); d != "" {
		fmt.Println(d)
	}
	os.Exit(1)
}

func elevationInstall(policy, sudoersPath, user string, dryRun bool) {
	pol := elevationLoad(policy)
	if pol == nil {
		fatal(fmt.Errorf("no elevation policy at %s — write one first (see docs/operations.md §4.2)", policy))
	}
	rendered, err := pol.RenderSudoers(user)
	if err != nil {
		fatal(err)
	}
	if dryRun {
		fmt.Print(rendered)
		fmt.Printf("\n(dry run — nothing installed; policy sha256 %s…)\n", pol.PolicyHash()[:12])
		return
	}
	if os.Geteuid() != 0 {
		fatal(fmt.Errorf("installing %s needs root: sudo /usr/local/bin/partout ctl elevation install-sudoers", sudoersPath))
	}
	// visudo-check the rendered file BEFORE it touches the live system.
	tmp, err := os.CreateTemp("", "partout-sudoers-*.new")
	if err != nil {
		fatal(err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(rendered); err != nil {
		tmp.Close()
		fatal(err)
	}
	tmp.Close()
	if out, err := exec.Command("visudo", "-cf", tmpName).CombinedOutput(); err != nil {
		fatal(fmt.Errorf("visudo rejected the rendered drop-in — not installed: %v\n%s", err, out))
	}
	if err := os.Chown(tmpName, 0, 0); err != nil {
		fatal(err)
	}
	if err := os.Chmod(tmpName, 0o440); err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(sudoersPath), 0o755); err != nil {
		fatal(err)
	}
	if err := os.Rename(tmpName, sudoersPath); err != nil {
		fatal(err)
	}
	fmt.Printf("installed %s (policy sha256 %s…; user %s)\n", sudoersPath, pol.PolicyHash()[:12], user)
	fmt.Println("verify with:  partout ctl elevation check")
}
