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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/blawesom/partout/internal/agent/elevate"
	policypkg "github.com/blawesom/partout/internal/policy"
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

// elevationExplain answers "would this command line elevate?" against the
// loaded policy — the same matcher the agent uses, so what you see here is
// what the host will do. It is the authoring loop for policy edits: change
// the rule, re-run the explain, see the verdict.
func elevationExplain(policy string, cmdline []string) {
	if len(cmdline) < 1 {
		fatal(fmt.Errorf("usage: partout ctl elevation explain [--policy P] -- <command> [args…]"))
	}
	pol := elevationLoad(policy)
	name, args := cmdline[0], cmdline[1:]
	dec := pol.Check(name, args)
	fmt.Printf("command:  %s\n", strings.Join(cmdline, " "))
	fmt.Printf("policy:   %s (%d rules, %s)\n", policy, len(pol.Rules), pol.Source())
	switch dec {
	case elevate.Elevated:
		rule := pol.RuleFor(name, args)
		fmt.Printf("verdict:  ELEVATED — rule %d matches: allow %s %s\n",
			ruleIndex(pol, rule), rule.Allow, elevationRuleDesc(*rule))
	default:
		fmt.Printf("verdict:  UNPRIVILEGED — no rule matches (the command still runs, without sudo;\n")
		fmt.Printf("          the agent log records it as out-of-scope). Add a rule to elevate it.\n")
	}
	// The runner-level view (what the run row will show): mode is a host
	// fact, but the policy decision is printable from here.
	if pr := elevate.NewPolicyRunner(elevate.Sudo, pol, nil); pr != nil {
		_, note := pr.Explain(name, args...)
		fmt.Printf("run row:  %s\n", note)
	}
}

// ruleIndex finds a rule's position (for the explain verdict).
func ruleIndex(pol *elevate.Policy, r *elevate.Rule) int {
	for i := range pol.Rules {
		if &pol.Rules[i] == r {
			return i + 1
		}
	}
	return 0
}

// elevationBundle is the staged wire format for a server-signed policy
// push (the agent writes it to its data dir; this command runs as root
// via the sudoers self-grant and re-verifies everything).
type elevationBundle struct {
	PushID     string `json:"push_id"`
	PolicyName string `json:"policy_name"`
	RulesJSON  string `json:"rules_json"`
	PolicySHA  string `json:"policy_sha256"`
	Signature  string `json:"signature"`
}

// serverPolicyKeyPath is the root-owned pinned server identity key
// (written at provision/join/bootstrap time). Root-readable only in
// practice: the unprivileged partout user must not be able to swap it.
const serverPolicyKeyPath = "/etc/partout/server-policy.pub"

// elevationApply applies a server-signed elevation policy push (P2). Runs
// as ROOT (the agent invokes it through the sudoers self-grant); every
// input is re-verified here — the signature against the root-owned pinned
// key (the unprivileged caller can stage any bundle it likes; only the
// server key's signature gets through) and the policy's shape + hash.
func elevationApply(bundlePath, policyDir, sudoersPath, user, keyPath string) {
	if os.Geteuid() != 0 {
		fatal(fmt.Errorf("elevation apply needs root (the agent invokes it via the sudoers self-grant)"))
	}
	// "-" reads the bundle from STDIN (the agent's form: the self-grant is
	// an exact-argv match with no path argument).
	var raw []byte
	var err error
	if bundlePath == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(bundlePath)
	}
	if err != nil {
		fatal(fmt.Errorf("read bundle: %w", err))
	}
	bundle, _, err := parseAndVerifyElevationBundle(raw, keyPath)
	if err != nil {
		fatal(err)
	}

	// 3. Install the drop-in policy document (0644 root:root — the agent
	//    re-reads it unprivileged after the swap).
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		fatal(err)
	}
	dest := filepath.Join(policyDir, "10-"+slugPolicyFileName(bundle.PolicyName)+".json")
	doc := `{"rules":` + bundle.RulesJSON + `}`
	if err := os.WriteFile(dest, []byte(doc), 0o644); err != nil {
		fatal(err)
	}
	if err := os.Chown(dest, 0, 0); err != nil {
		fatal(err)
	}

	// 4. Render + visudo-check + install the sudoers drop-in from the
	//    (now merged) policy dir — the same path install-sudoers uses.
	elevationInstall(policyDir, sudoersPath, user, false)
	fmt.Printf("applied push %s (policy %s, sha %s…) → %s\n", bundle.PushID, bundle.PolicyName, bundle.PolicySHA[:12], dest)
}

// slugPolicyFileName makes a policy name filesystem-safe for its drop-in.
func slugPolicyFileName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "policy"
	}
	return out
}

// parseAndVerifyElevationBundle does everything short of touching the
// system: parse the staged bundle, verify the signature against the pinned
// server key, and validate the policy's shape + hash claim. Split out of
// elevationApply so tests can pin the verification contract without root.
func parseAndVerifyElevationBundle(raw []byte, keyPath string) (elevationBundle, *elevate.Policy, error) {
	var bundle elevationBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return bundle, nil, fmt.Errorf("parse bundle: %w", err)
	}
	if bundle.PushID == "" || bundle.PolicyName == "" || bundle.RulesJSON == "" || bundle.PolicySHA == "" {
		return bundle, nil, fmt.Errorf("bundle is missing fields (push_id, policy_name, rules_json, policy_sha256)")
	}
	// 1. Signature against the root-owned pinned key.
	pubB64, err := os.ReadFile(keyPath)
	if err != nil {
		return bundle, nil, fmt.Errorf("read pinned server key %s (provisioned at install; see operations.md §3.6): %w", keyPath, err)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubB64)))
	if err != nil {
		return bundle, nil, fmt.Errorf("pinned server key is not base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return bundle, nil, fmt.Errorf("bundle signature is not base64: %w", err)
	}
	if !policypkg.VerifyElevationPush(ed25519.PublicKey(pub), bundle.PushID, bundle.PolicyName, bundle.PolicySHA, sig) {
		return bundle, nil, fmt.Errorf("signature verification FAILED — refusing to apply (forged or stale bundle)")
	}
	// 2. The policy must parse and hash to its claim.
	pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + bundle.RulesJSON + `}`))
	if err != nil {
		return bundle, nil, fmt.Errorf("policy does not parse: %w", err)
	}
	if pol.PolicyHash() != bundle.PolicySHA {
		return bundle, nil, fmt.Errorf("policy sha mismatch: %s != %s", pol.PolicyHash(), bundle.PolicySHA)
	}
	return bundle, pol, nil
}

// policyHashOf computes the canonical policy hash for a rules array.
func policyHashOf(rulesJSON string) string {
	pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + rulesJSON + `}`))
	if err != nil {
		return ""
	}
	return pol.PolicyHash()
}
