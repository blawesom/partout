// Sudoers rendering: the half of the policy that the kernel honors.
//
// RenderSudoers turns the policy into a /etc/sudoers.d drop-in. It is the
// only sanctioned producer of that file: `partout ctl elevation
// install-sudoers` writes it (0440 root:root, visudo-checked), and
// `partout ctl elevation check` re-renders and diffs to catch drift.
//
// Design notes (sudoers syntax is verified with `visudo -cf` before any
// install):
//   - command names are resolved to absolute paths at render time (sudoers
//     requires them). Names not on PATH on this host are skipped with a
//     visible comment (e.g. `dnf` on an Ubuntu box) rather than failing the
//     whole render.
//   - argument patterns containing wildcards or punctuation are
//     double-quoted — unquoted `*` is a syntax error in sudoers, and quoted
//     strings still match as patterns.
//   - env_reset stays ON (the sudoers default). The legacy hand-written
//     drop-in used `!env_reset` so dispatched `--env K=V` survived
//     elevation; that blanket grant is retired here — a rule that needs
//     environment is rendered with the SETENV: spec on the user line
//     (SETENV is not permitted inside a Cmnd_Alias definition).
//   - one Cmnd_Alias per distinct binary; long lists continue with
//     ", \" (a bare trailing comma is a syntax error).
package elevate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// PolicyHash is the sha256 over the canonical (rules-only) JSON of the
// policy, embedded in the rendered drop-in so `elevation check` can spot a
// stale file even when an operator "fixed" the body by hand.
func (p *Policy) PolicyHash() string {
	b, _ := json.Marshal(Policy{Rules: p.Rules})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// sudoersArg quotes a single argument pattern if it contains any character
// sudoers would reject or reinterpret unquoted (wildcards, spaces,
// punctuation). Quoted strings still match as patterns.
func sudoersArg(a string) string {
	for _, r := range a {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '/' || r == '@' || r == '-':
		default:
			return `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
	}
	return a
}

// sudoersLine renders one command grant: absolute path + quoted argument
// patterns.
func sudoersLine(abi string, args ...string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, abi)
	for _, a := range args {
		parts = append(parts, sudoersArg(a))
	}
	return strings.Join(parts, " ")
}

// RenderSudoers renders the policy as a complete drop-in for the given
// service user.
func (p *Policy) RenderSudoers(user string) (string, error) {
	if p == nil || len(p.Rules) == 0 {
		return "", fmt.Errorf("empty policy — nothing to render")
	}
	if user == "" {
		return "", fmt.Errorf("no sudoers user given")
	}

	type grant struct {
		abi  string
		args []string
		env  []string
	}
	var grants []grant
	var skipped []string

	for i, r := range p.Rules {
		for _, alt := range r.allowAlts() {
			abi, err := exec.LookPath(alt)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("# skipped: %s (rule %d, not found on PATH)", alt, i))
				continue
			}
			switch {
			case len(r.Args) > 0:
				grants = append(grants, grant{abi: abi, args: r.Args, env: r.Env})
			case len(r.Verbs) > 0:
				for _, v := range r.Verbs {
					for _, u := range r.Units {
						grants = append(grants, grant{abi: abi, args: []string{v, u}, env: r.Env})
					}
				}
			case len(r.Files) > 0:
				for _, f := range r.Files {
					grants = append(grants, grant{abi: abi, args: []string{f}, env: r.Env})
				}
			}
		}
	}
	if len(grants) == 0 {
		return "", fmt.Errorf("no renderable grants (every command name was missing from PATH?)")
	}

	// De-duplicate identical command lines; remember the env union per line.
	type keyed struct {
		line string
		env  map[string]bool
	}
	seen := map[string]*keyed{}
	var order []string
	for _, g := range grants {
		line := sudoersLine(g.abi, g.args...)
		k, ok := seen[line]
		if !ok {
			k = &keyed{line: line}
			seen[line] = k
			order = append(order, line)
		}
		for _, e := range g.env {
			if k.env == nil {
				k.env = map[string]bool{}
			}
			k.env[e] = true
		}
	}

	// Group by binary, in first-use order. Grants without env go into a
	// Cmnd_Alias; grants with env go on the user spec as SETENV: lines
	// (SETENV is not permitted inside a Cmnd_Alias definition).
	aliasOf := map[string]string{}
	var aliasOrder []string
	aliasLines := map[string][]string{}
	var setenvLines []string
	for _, line := range order {
		abi := strings.Fields(line)[0]
		if _, ok := aliasOf[abi]; !ok {
			aliasOf[abi] = "PARTOUT_" + strings.ToUpper(sanitizeAliasName(filepath.Base(abi)))
			aliasOrder = append(aliasOrder, abi)
		}
		if env := seen[line].env; len(env) > 0 {
			setenvLines = append(setenvLines, "SETENV: "+line)
		} else {
			aliasLines[abi] = append(aliasLines[abi], line)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# /etc/sudoers.d/partout-agent — GENERATED by `partout ctl elevation install-sudoers`\n")
	fmt.Fprintf(&b, "# Do not edit by hand: edit the elevation policy (PARTOUT_ELEVATION_POLICY)\n")
	fmt.Fprintf(&b, "# and re-run the install. policy-sha256: %s\n", p.PolicyHash())
	for _, s := range skipped {
		b.WriteString(s + "\n")
	}
	b.WriteString("\n")

	for _, abi := range aliasOrder {
		lines := aliasLines[abi]
		if len(lines) == 0 {
			continue // env-only binary: its grant is on the user spec line
		}
		// ", \" continuation: a bare trailing comma is a syntax error.
		fmt.Fprintf(&b, "Cmnd_Alias %s = %s\n", aliasOf[abi], strings.Join(lines, ", \\\n        "))
	}
	b.WriteString("\n")
	specParts := make([]string, 0, len(aliasOrder)+len(setenvLines))
	for _, abi := range aliasOrder {
		if len(aliasLines[abi]) > 0 {
			specParts = append(specParts, aliasOf[abi])
		}
	}
	specParts = append(specParts, setenvLines...)
	b.WriteString(fmt.Sprintf("%s ALL=(root) NOPASSWD: %s\n", user, strings.Join(specParts, ", ")))
	return b.String(), nil
}

// sanitizeAliasName turns a basename into a sudoers-identifier fragment.
func sanitizeAliasName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
