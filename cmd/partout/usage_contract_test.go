package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestCtlUsageContract is the "first-use" guard for the CLI: the `partout ctl`
// usage text, the dispatch switch, each subcommand's handler, and the README
// command-set line must all agree. It is the regression class where an
// operator reads the help and goes astray — a stale command list, a ghost
// command, a documented verb the handler doesn't have, or the README listing
// something that isn't a ctl subcommand (e.g. the top-level `selftest`).
func TestCtlUsageContract(t *testing.T) {
	wd, _ := os.Getwd()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(wd, "ctl.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse ctl.go: %v", err)
	}

	// 1. Real top-level commands: the dispatch switch inside runCtl.
	real, handler := dispatchTable(t, f)

	// 2. Documented commands + verb groups from the usage text.
	usage := usageText(t, f)
	doc, verbGroups, lineVerbs := parseUsage(usage)

	// "help" is trivially self-documenting; ignore it in set comparisons.
	ignore := map[string]bool{"help": true}
	setEq(t, "top-level commands: usage text vs dispatch", doc, real, ignore)

	// 3. Verbs: explicit <a|b|c> groups must match the handler's switch in
	// both directions (no ghosts, no omissions); line-form verbs (e.g.
	// "sessions open") must at least be real. A command with no sub-dispatch
	// switch has no verbs to check.
	var checked int
	for cmd, verbs := range verbGroups {
		if ignore[cmd] {
			continue
		}
		fn, ok := handler[cmd]
		if !ok {
			t.Errorf("command %q has verb group <%s> but no dispatch handler", cmd, strings.Join(verbs, "|"))
			continue
		}
		hv := handlerVerbs(t, f, fn)
		if len(hv) == 0 {
			t.Errorf("%s: documented verb group but %s has no sub-dispatch switch", cmd, fn)
			continue
		}
		for _, v := range verbs {
			if !hv[v] {
				t.Errorf("%s: documented verb %q not found in %s's switch", cmd, v, fn)
			}
		}
		for v := range hv {
			if !strings.Contains(strings.Join(verbs, "|"), v) {
				t.Errorf("%s: handler %s accepts verb %q that the usage text does not document", cmd, fn, v)
			}
		}
		checked++
	}
	for cmd, verbs := range lineVerbs {
		if ignore[cmd] || len(verbGroups[cmd]) > 0 {
			continue
		}
		fn, ok := handler[cmd]
		if !ok {
			continue
		}
		hv := handlerVerbs(t, f, fn)
		if len(hv) == 0 {
			continue // no sub-dispatch; the second token was a description word
		}
		for _, v := range verbs {
			if !hv[v] {
				t.Errorf("%s: line-form verb %q not found in %s's switch (ghost in usage text)", cmd, v, fn)
			}
		}
	}
	if checked == 0 {
		t.Error("no verb groups checked — the usage text format may have changed")
	}

	// 4. The usage header must name the real flags (and not a wrong one).
	flags := flagNames(t, f)
	header := strings.SplitN(usage, "\n", 2)[0]
	for _, fl := range flags {
		if !strings.Contains(header, "--"+fl) {
			t.Errorf("usage header does not document flag --%s", fl)
		}
	}
	for _, ghost := range []string{"--admin-token", "--op-token", "--viewer-token"} {
		if strings.Contains(header, ghost) {
			t.Errorf("usage header mentions server flag %s (ctl takes --token)", ghost)
		}
	}

	// 5. README "full command set" line must match the dispatch.
	readme, err := os.ReadFile(filepath.Join(wd, "..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	rt := readmeTokens(t, string(readme))
	setEq(t, "README full command set vs dispatch", rt, real, ignore)
}

// TestCtlHelpRendersWithoutServer: first-use check — `partout ctl help` must
// work with no server and print the real list (regression: it used to fail
// with "--server is required" before reaching the usage text).
func TestCtlHelpRendersWithoutServer(t *testing.T) {
	t.Setenv("PARTOUT_SERVER", "")
	t.Setenv("PARTOUT_CTL_TOKEN", "")
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	runCtl([]string{"help"})
	w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	s := string(out)
	for _, want := range []string{"usage: partout ctl", "--token", "preset", "db-backup", "update"} {
		if !strings.Contains(s, want) {
			t.Errorf("ctl help output missing %q", want)
		}
	}
	if strings.Contains(s, "required") {
		t.Error("ctl help must not demand a server")
	}
}

// --- helpers ---------------------------------------------------------------

// dispatchTable returns the real top-level commands (set) and command→handler
// function name, from the switch inside runCtl.
func dispatchTable(t *testing.T, f *ast.File) (map[string]bool, map[string]string) {
	t.Helper()
	real := map[string]bool{}
	handler := map[string]string{}
	var found bool
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "runCtl" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			found = true
			for _, st := range sw.Body.List {
				cs, ok := st.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, e := range cs.List {
					lit, ok := e.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					cmd := unquote(t, lit.Value)
					if strings.HasPrefix(cmd, "-") {
						continue // flag aliases like -h / --help
					}
					real[cmd] = true
					for _, stmt := range cs.Body {
						ex, ok := stmt.(*ast.ExprStmt)
						if !ok {
							continue
						}
						call, ok := ex.X.(*ast.CallExpr)
						if !ok || len(call.Args) == 0 {
							continue
						}
						switch fun := call.Fun.(type) {
						case *ast.SelectorExpr:
							handler[cmd] = fun.Sel.Name
						case *ast.Ident:
							handler[cmd] = fun.Name
						}
						break
					}
				}
			}
			return false
		})
	}
	if !found {
		t.Fatal("dispatch switch not found in runCtl")
	}
	return real, handler
}

// usageText returns the raw usage string printed by fs.Usage.
func usageText(t *testing.T, f *ast.File) string {
	t.Helper()
	var out string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if strings.HasPrefix(lit.Value, "`usage: partout ctl --server") {
			out = lit.Value
			return false
		}
		return true
	})
	if out == "" {
		t.Fatal("usage text not found in ctl.go")
	}
	return strings.Trim(out, "`")
}

var (
	cmdLineRe = regexp.MustCompile(`^  ([a-z][a-z0-9-]*)`)
	verbGrpRe = regexp.MustCompile(`<([a-z][a-z-]*(?:\|[a-z-]+)*)>`)
)

// parseUsage extracts the documented top-level commands (first token of each
// 2-space-indented line), their explicit verb groups (<a|b|c>, two or more
// items), and line-form verbs (a bare word as second token, e.g.
// "sessions open").
func parseUsage(usage string) (doc map[string]bool, groups map[string][]string, lineVerbs map[string][]string) {
	doc = map[string]bool{}
	groups = map[string][]string{}
	lineVerbs = map[string][]string{}
	verbWord := regexp.MustCompile(`^[a-z][a-z-]*$`)
	for _, line := range strings.Split(usage, "\n") {
		m := cmdLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cmd := m[1]
		doc[cmd] = true
		for _, g := range verbGrpRe.FindAllStringSubmatch(line, -1) {
			items := strings.Split(g[1], "|")
			if len(items) < 2 {
				continue // <id>, <db> are argument placeholders, not verb groups
			}
			groups[cmd] = append(groups[cmd], items...)
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && verbWord.MatchString(fields[1]) &&
			!strings.Contains(line, "<"+fields[1]+"|") {
			lineVerbs[cmd] = append(lineVerbs[cmd], fields[1])
		}
	}
	return doc, groups, lineVerbs
}

// handlerVerbs collects every string case literal in the named function
// (any nested switch), skipping empty/alias-default cases.
func handlerVerbs(t *testing.T, f *ast.File, name string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	var found bool
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			for _, st := range sw.Body.List {
				cs, ok := st.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, e := range cs.List {
					lit, ok := e.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v := unquote(t, lit.Value)
					if v == "" || strings.HasPrefix(v, "-") || strings.ContainsAny(v, " <>{}") {
						continue
					}
					out[v] = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatalf("handler function %s not found in ctl.go", name)
	}
	return out
}

// flagNames collects the flag names defined on the ctl FlagSet.
func flagNames(t *testing.T, f *ast.File) []string {
	t.Helper()
	var names []string
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "runCtl" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok || len(call.Args) < 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "String" && sel.Sel.Name != "Bool" && sel.Sel.Name != "Int" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				names = append(names, unquote(t, lit.Value))
			}
			return true
		})
	}
	if len(names) == 0 {
		t.Fatal("no flags found in runCtl")
	}
	return names
}

// readmeTokens extracts the backtick-quoted "full command set" list.
func readmeTokens(t *testing.T, readme string) map[string]bool {
	t.Helper()
	idx := strings.Index(readme, "full command set: `")
	if idx < 0 {
		t.Fatal("README: 'full command set' line not found")
	}
	rest := readme[idx+len("full command set: `"):]
	end := strings.Index(rest, "`")
	if end < 0 {
		t.Fatal("README: unterminated command-set backticks")
	}
	out := map[string]bool{}
	for _, tok := range regexp.MustCompile(`\s*·\s*`).Split(rest[:end], -1) {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out[tok] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("README: no command-set tokens parsed")
	}
	return out
}

func setEq(t *testing.T, label string, a, b map[string]bool, ignore map[string]bool) {
	t.Helper()
	sa, sb := sortedKeys(a, ignore), sortedKeys(b, ignore)
	var missing, extra []string
	for _, k := range sa {
		if !b[k] {
			missing = append(missing, k)
		}
	}
	for _, k := range sb {
		if !a[k] {
			extra = append(extra, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%s: documented but not real: %v", label, missing)
	}
	if len(extra) > 0 {
		t.Errorf("%s: real but not documented: %v", label, extra)
	}
}

func sortedKeys(m map[string]bool, ignore map[string]bool) []string {
	var out []string
	for k := range m {
		if !ignore[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func unquote(t *testing.T, s string) string {
	t.Helper()
	v, err := strconv.Unquote(s)
	if err != nil {
		t.Fatalf("unquote %q: %v", s, err)
	}
	return v
}
