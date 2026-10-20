// Elevation policy (PRD Decision 3, full slice): the agent-side,
// pattern-scoped statement of which commands may run elevated.
//
// The policy is the single declarative source of truth that both the agent
// (what it runs elevated, and what it tells the UI will happen) and the
// sudoers drop-in (`RenderSudoers` → `partout ctl elevation
// install-sudoers`) derive from. The host's sudoers file remains the
// security wall — the policy is what the agent *believes*, sudoers is what
// the kernel honors, and `partout ctl elevation check` detects drift.
//
// Semantics (fail closed):
//   - mode none:        the policy is not consulted; nothing elevates.
//   - mode sudo, no
//     policy file:      legacy behavior — every action command is prefixed
//     `sudo -n` and the (hand-installed) drop-in decides.
//   - mode sudo +
//     policy:          the policy is the agent-side authority. A command
//     that matches a rule runs elevated; one that does not
//     match runs UNPRIVILEGED (and the agent says so in
//     its log) rather than being refused or being pushed
//     through sudo on faith.
//
// Glob syntax is path.Match: `*` and `?` within a segment, `*` never
// crosses `/` — the same intuition as sudoers argument wildcards.
package elevate

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Decision is the agent-side verdict for one (command, args) pair.
type Decision int

const (
	// Denied: no rule matches — the command must not be elevated.
	Denied Decision = iota
	// Elevated: a rule matches — the command may be elevated.
	Elevated
)

func (d Decision) String() string {
	if d == Elevated {
		return "elevated"
	}
	return "denied"
}

// Rule is one elevation grant. The matcher is optional:
//
//	Args:  the full argument vector, element-wise globs
//	        (e.g. ["-c", "-f", "/etc/haproxy/haproxy.cfg"]).
//	Verbs + Units: argv[0] ∩ verbs AND argv[1] matches a unit glob,
//	        and nothing else (e.g. systemctl restart haproxy*).
//	Files: argv is exactly one path matching a file glob
//	        (e.g. cat /etc/haproxy/*).
//	None set: the bare command — the grant matches ONLY a zero-argument
//	        invocation (e.g. `reboot`, `poweroff`). In sudoers this renders
//	        as `path ""` (the empty-args specifier), not a bare command
//	        (which would match any arguments).
//
// Full: the full-privilege tier grant (P0 elevation tiers). A rule with
// Full=true and no allow/matchers matches EVERY command and renders as
// `NOPASSWD: ALL` — root-equivalent by design, the explicit escape hatch
// above the seeded "broad" default. It must be the loud, visible option:
// the posture fact reports tier=full, and the renderer refuses to mix it
// with other rules (validate enforces one grant per policy document).
type Rule struct {
	Allow string   `json:"allow"` // binary name(s), `|`-separated
	Args  []string `json:"args,omitempty"`
	Verbs []string `json:"verbs,omitempty"`
	Units []string `json:"units,omitempty"`
	Files []string `json:"files,omitempty"`
	Env   []string `json:"env,omitempty"`
	Full  bool     `json:"full,omitempty"`
	// ArgsPrefix (the "broad" tier's shape): matches when argv begins
	// with exactly these elements — any remainder matches. It renders to
	// a sudoers line ending in `*` (which, in sudoers, matches the rest
	// of the argument string including spaces), so multi-argument forms
	// like `apt-get -y install vim fail2ban btop` elevate on both sides
	// of the wall. The fixed-length `args` matcher cannot express that;
	// prefix grants are inherently WIDE — the tier classifier reads them
	// as broad.
	ArgsPrefix []string `json:"args_prefix,omitempty"`
}

// matches reports whether (name, args) is covered by this rule.
func (r Rule) matches(name string, args []string) bool {
	if r.Full {
		return true // the full tier: everything elevates
	}

	for _, alt := range r.allowAlts() {
		if alt != name {
			continue
		}
		switch {
		case len(r.ArgsPrefix) > 0:
			if len(args) < len(r.ArgsPrefix) {
				return false
			}
			for i, want := range r.ArgsPrefix {
				ok, err := path.Match(want, args[i])
				if err != nil || !ok {
					return false
				}
			}
			return true
		case len(r.Args) > 0:
			if len(args) != len(r.Args) {
				return false
			}
			for i, want := range r.Args {
				ok, err := path.Match(want, args[i])
				if err != nil || !ok {
					return false
				}
			}
			return true
		case len(r.Verbs) > 0:
			if len(args) != 2 {
				return false
			}
			if !contains(r.Verbs, args[0]) {
				return false
			}
			for _, g := range r.Units {
				if ok, _ := path.Match(g, args[1]); ok {
					return true
				}
			}
			return false
		case len(r.Files) > 0:
			if len(args) != 1 {
				return false
			}
			for _, g := range r.Files {
				if ok, _ := path.Match(g, args[0]); ok {
					return true
				}
			}
			return false
		default:
			// No matcher set: the bare-command grant — zero arguments only.
			return len(args) == 0
		}
	}
	return false
}

func (r Rule) allowAlts() []string {
	var out []string
	for _, a := range strings.Split(r.Allow, "|") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// validate fails closed on ambiguous or empty rules.
func (r Rule) validate(i int) error {
	if r.Full {
		// The full tier is a standalone grant: it cannot be scoped (a
		// scoped "full" would be a normal rule wearing a louder name),
		// and it cannot carry env (SETENV on NOPASSWD: ALL is not a
		// thing the renderer will emit).
		if len(r.allowAlts()) > 0 || len(r.ArgsPrefix) > 0 || len(r.Args) > 0 || len(r.Verbs) > 0 || len(r.Units) > 0 || len(r.Files) > 0 || len(r.Env) > 0 {
			return fmt.Errorf("rule %d: a full:true grant is standalone — no allow/args/args_prefix/verbs/units/files/env with it", i)
		}
		return nil
	}
	if len(r.allowAlts()) == 0 {
		return fmt.Errorf("rule %d: empty \"allow\"", i)
	}
	matchers := 0
	if len(r.ArgsPrefix) > 0 {
		matchers++
	}
	if len(r.Args) > 0 {
		matchers++
	}
	if len(r.Verbs) > 0 {
		matchers++
	}
	if len(r.Files) > 0 {
		matchers++
	}
	if matchers > 1 {
		return fmt.Errorf("rule %d (%s): set at most one of args_prefix / args / verbs+units / files", i, r.Allow)
	}
	if len(r.Verbs) > 0 && len(r.Units) == 0 {
		return fmt.Errorf("rule %d (%s): verbs require units (the scope)", i, r.Allow)
	}
	for _, a := range append(append([]string{}, r.ArgsPrefix...), r.Args...) {
		if _, err := path.Match(a, "x"); err != nil {
			return fmt.Errorf("rule %d (%s): bad glob %q", i, r.Allow, a)
		}
	}
	for _, g := range append(append([]string{}, r.Units...), r.Files...) {
		if _, err := path.Match(g, "x"); err != nil {
			return fmt.Errorf("rule %d (%s): bad glob %q", i, r.Allow, g)
		}
	}
	return nil
}

// Tier reports the policy's privilege tier: "full" when it contains a
// full:true grant, "broad" when its rules include any wildcard-scoped
// grant (the seeded default-broad shape), else "strict" (exact-argv
// grants only). The posture fact carries this so the fleet's tier is
// visible at a glance — the whole point of tiers is that the blast
// radius is readable without reading rules.
func (p *Policy) Tier() string {
	if p == nil {
		return ""
	}
	for _, r := range p.Rules {
		if r.Full {
			return "full"
		}
	}
	for _, r := range p.Rules {
		if len(r.ArgsPrefix) > 0 {
			return "broad" // a prefix grant is wide by construction
		}
		if len(r.Args) > 0 {
			for _, a := range r.Args {
				if strings.ContainsAny(a, "*?") {
					return "broad"
				}
			}
		}
		if len(r.Units) > 0 || len(r.Files) > 0 {
			return "broad"
		}
	}
	return "strict"
}

// Policy is a loaded elevation policy (merged drop-ins).
type Policy struct {
	Rules   []Rule   `json:"rules"`
	sources []string // loaded file paths, in merge order
}

// Source lists the files this policy was merged from.
func (p *Policy) Source() []string { return p.sources }

// Check returns the agent-side decision for (name, args).
// A nil policy denies (legacy sudo mode is handled by callers, not here).
func (p *Policy) Check(name string, args []string) Decision {
	if p == nil {
		return Denied
	}
	for _, r := range p.Rules {
		if r.matches(name, args) {
			return Elevated
		}
	}
	return Denied
}

// RuleFor returns the first rule matching (name, args), or nil.
func (p *Policy) RuleFor(name string, args []string) *Rule {
	if p == nil {
		return nil
	}
	for i := range p.Rules {
		if p.Rules[i].matches(name, args) {
			return &p.Rules[i]
		}
	}
	return nil
}

// LoadPolicyJSON parses policy JSON ({"rules":[...]}), validating each
// rule. Exported for tests and for tools that build policies in memory.
func LoadPolicyJSON(b []byte) (*Policy, error) {
	var part struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.Unmarshal(b, &part); err != nil {
		return nil, err
	}
	pol := &Policy{}
	full := 0
	for i, r := range part.Rules {
		if err := r.validate(i); err != nil {
			return nil, err
		}
		if r.Full {
			full++
		}
		pol.Rules = append(pol.Rules, r)
	}
	if full > 0 && len(pol.Rules) > 1 {
		return nil, fmt.Errorf("a full:true grant must be the policy's only rule — split the document (mixing full with scoped rules would misrepresent the tier)")
	}
	return pol, nil
}

// Load reads a policy from path: a single .json file, or a directory of
// *.json drop-ins (merged in lexical filename order, earlier files first).
// An empty or nonexistent path yields (nil, nil) — the legacy
// no-policy behavior, not an error.
func Load(p string) (*Policy, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil, nil
	}
	var files []string
	if st, err := os.Stat(p); err == nil {
		if st.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				return nil, fmt.Errorf("elevation policy: read dir: %w", err)
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				files = append(files, filepath.Join(p, e.Name()))
			}
			sort.Strings(files)
		} else {
			files = []string{p}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("elevation policy: %w", err)
	}
	if len(files) == 0 {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return nil, nil // empty drop-in dir = no policy
		}
		return nil, fmt.Errorf("elevation policy: no .json policy at %s", p)
	}
	pol := &Policy{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("elevation policy: %w", err)
		}
		part, err := LoadPolicyJSON(b)
		if err != nil {
			return nil, fmt.Errorf("elevation policy %s: %w", f, err)
		}
		pol.Rules = append(pol.Rules, part.Rules...)
		pol.sources = append(pol.sources, f)
	}
	return pol, nil
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
