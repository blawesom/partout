// Command partout — `uninstall` subcommand.
//
// `partout uninstall` is the one-command LOCAL removal of a Partout
// installation on the machine it runs on (server, agent, or embedded). It is
// a local operation: no server round-trip, no --server/--token.
//
// The default is data-preserving (like `apt remove`): stop + disable the
// systemd units, remove the unit files, /etc/partout env files, the update
// guard, and the binary — but keep the state directory (db, TLS, identity,
// spool) so a reinstall or a later decision can recover the data.
//
// `--purge` (like `apt purge`) also removes the state dir(s), the
// $HOME/.partout agent dir, and the `partout` system user.
// `--dry-run` prints the plan and changes nothing; `--keep-binary` leaves
// the binary in place (useful when the same binary is the operator CLI).
//
// Remote uninstall: on a managed host the operator can dispatch
// `sudo partout uninstall --purge` through the agent. The command tolerates
// the first SIGTERM/SIGINT because stopping its own parent service makes
// systemd send SIGTERM to the whole cgroup, uninstall included.
//
// Intended as:
//
//	sudo partout uninstall --dry-run     # preview
//	sudo partout uninstall               # keep state
//	sudo partout uninstall --purge       # full clean removal
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// uninstallEnv holds the well-known install locations. Overridable in tests.
type uninstallEnv struct {
	unitDir          string // /etc/systemd/system
	etcDir           string // /etc/partout
	varDir           string // /var/lib/partout (default state dir)
	fileRoot         string // /home/partout (file surface root, spec-file-root)
	homeDir          string // $HOME (non-systemd agent data: $HOME/.partout)
	binPath          string // /usr/local/bin/partout
	guardPath        string // /usr/local/sbin/partout-update-guard (agent self-update)
	backupScriptPath string // /usr/local/sbin/partout-backup.sh (server backup timer)
}

func defaultUninstallEnv() uninstallEnv {
	home, _ := os.UserHomeDir()
	return uninstallEnv{
		unitDir:          "/etc/systemd/system",
		etcDir:           "/etc/partout",
		varDir:           "/var/lib/partout",
		fileRoot:         "/home/partout",
		homeDir:          home,
		binPath:          "/usr/local/bin/partout",
		guardPath:        "/usr/local/sbin/partout-update-guard",
		backupScriptPath: "/usr/local/sbin/partout-backup.sh",
	}
}

// uninstallUnitNames in stop order: data-owning services first, backup
// service + timer last (the timer re-touches the state dir).
var uninstallUnitNames = []string{
	"partout-server.service",
	"partout-agent.service",
	"partout-embedded.service",
	"partout-backup.service",
	"partout-backup.timer",
}

// uStep is one planned change. kind is stop | disable | unit-file | file |
// dir | etc-dir | user | reload.
type uStep struct {
	kind   string
	unit   string // for stop/disable
	path   string // for unit-file/file/dir/etc-dir
	user   string // for user
	detail string
}

// uninstallPlan is the ordered removal plan for one host.
type uninstallPlan struct {
	scope     string // none | server | agent | embedded | mixed | files
	steps     []uStep
	kept      []string // state dirs kept (default, non-purge)
	notes     []string
	needsRoot bool
}

func (pl *uninstallPlan) add(s uStep) {
	pl.steps = append(pl.steps, s)
}

// buildUninstallPlan inspects env and returns what would be removed (or
// kept). It never mutates anything.
func buildUninstallPlan(env uninstallEnv, purge, keepBinary bool) (*uninstallPlan, error) {
	pl := &uninstallPlan{scope: "none"}

	var present []string
	hasServer, hasAgent, hasEmbedded := false, false, false
	for _, u := range uninstallUnitNames {
		if _, err := os.Stat(filepath.Join(env.unitDir, u)); err == nil {
			present = append(present, u)
			switch u {
			case "partout-server.service":
				hasServer = true
			case "partout-agent.service":
				hasAgent = true
			case "partout-embedded.service":
				hasEmbedded = true
			}
		}
	}
	switch {
	case hasServer && (hasAgent || hasEmbedded):
		pl.scope = "mixed"
	case hasServer:
		pl.scope = "server"
	case hasAgent:
		pl.scope = "agent"
	case hasEmbedded:
		pl.scope = "embedded"
	}

	if len(present) > 0 {
		for _, u := range present {
			pl.add(uStep{kind: "stop", unit: u, detail: "systemctl stop " + u})
		}
		for _, u := range present {
			pl.add(uStep{kind: "disable", unit: u, detail: "systemctl disable " + u})
		}
		pl.needsRoot = true
	}

	// env files: parse custom data locations before they go away.
	customDB := ""
	for _, f := range []string{"server.env", "embedded.env"} {
		if v := envFileValue(filepath.Join(env.etcDir, f), "PARTOUT_DB_PATH"); v != "" {
			customDB = v
			break
		}
	}
	customAgentData := envFileValue(filepath.Join(env.etcDir, "agent.env"), "PARTOUT_DATA_DIR")

	// ---- state locations (kept by default, purged on request) ----
	var state []string
	if pathExists(env.varDir) {
		state = append(state, env.varDir)
	}
	// The file root holds operator-uploaded files (spec-file-root); it is
	// install footprint, so purge removes it and the non-purge plan flags it.
	if pathExists(env.fileRoot) {
		state = append(state, env.fileRoot)
	}
	if customDB != "" {
		if d := filepath.Dir(customDB); d != env.varDir && pathExists(d) {
			state = append(state, d)
		}
	}
	if customAgentData != "" && customAgentData != env.varDir && pathExists(customAgentData) {
		if !under(customAgentData, env.varDir) {
			state = append(state, customAgentData)
		}
	}
	homePartout := filepath.Join(env.homeDir, ".partout")
	if pathExists(homePartout) && !under(homePartout, env.varDir) {
		state = append(state, homePartout)
	}
	state = dedupeNested(state)

	// ---- unit files + update guard ----
	for _, u := range present {
		pl.add(uStep{kind: "unit-file", path: filepath.Join(env.unitDir, u), detail: "remove unit " + u})
	}
	if len(present) > 0 && pathExists(env.guardPath) {
		pl.add(uStep{kind: "file", path: env.guardPath, detail: "remove update guard"})
	}
	// The backup script is install footprint of the server deploy path
	// (install-server.sh / deploy/systemd) — remove it with the units, like
	// the guard. It only exists where the backup timer was installed.
	if len(present) > 0 && pathExists(env.backupScriptPath) {
		pl.add(uStep{kind: "file", path: env.backupScriptPath, detail: "remove backup script"})
	}
	if len(present) > 0 {
		pl.add(uStep{kind: "reload", detail: "systemctl daemon-reload"})
	}

	// ---- /etc/partout ----
	var etcFiles []string
	for _, f := range []string{"server.env", "agent.env", "embedded.env", "ca.crt"} {
		if pathExists(filepath.Join(env.etcDir, f)) {
			etcFiles = append(etcFiles, f)
		}
	}
	for _, f := range etcFiles {
		pl.add(uStep{kind: "file", path: filepath.Join(env.etcDir, f), detail: "remove " + f})
	}
	// If every entry in /etc/partout is one we are removing, remove the dir.
	if len(etcFiles) > 0 {
		if entries, err := os.ReadDir(env.etcDir); err == nil {
			allOurs := true
			for _, e := range entries {
				found := false
				for _, f := range etcFiles {
					if e.Name() == f {
						found = true
						break
					}
				}
				if !found {
					allOurs = false
					break
				}
			}
			if allOurs {
				pl.add(uStep{kind: "etc-dir", path: env.etcDir, detail: "remove empty " + env.etcDir})
			} else {
				pl.notes = append(pl.notes, env.etcDir+" kept (contains files other than Partout's: "+strings.Join(dirNames(entries), ", ")+")")
			}
		}
	}

	// ---- state dirs ----
	if purge {
		for _, d := range state {
			pl.add(uStep{kind: "dir", path: d, detail: "remove state " + d})
		}
		if len(present) > 0 {
			pl.add(uStep{kind: "user", user: "partout", detail: "remove system user partout"})
		}
	} else {
		for _, d := range state {
			pl.kept = append(pl.kept, d)
		}
	}

	// ---- binary ----
	if pathExists(env.binPath) {
		if !keepBinary {
			pl.add(uStep{kind: "file", path: env.binPath, detail: "remove binary"})
		} else {
			pl.notes = append(pl.notes, "binary kept at "+env.binPath+" (--keep-binary)")
		}
	}

	if pl.scope == "none" && (len(pl.steps) > 0 || len(state) > 0 || len(pl.kept) > 0 || len(pl.notes) > 0) {
		pl.scope = "files" // non-systemd install (dev/docker/manual)
	}
	return pl, nil
}

// needsSystemRoot reports whether applying the plan requires root.
func (pl *uninstallPlan) needsSystemRoot(env uninstallEnv) bool {
	for _, s := range pl.steps {
		switch s.kind {
		case "stop", "disable", "reload", "user":
			return true
		case "unit-file", "file", "dir", "etc-dir":
			if !under(s.path, env.homeDir) {
				return true
			}
		}
	}
	return false
}

// print renders the plan for a human (dry-run and pre-flight).
func (pl *uninstallPlan) print(dryRun, purge bool) {
	fmt.Printf("partout uninstall (scope: %s, %s)\n", pl.scope, modeLabel(dryRun, purge))
	for _, s := range pl.steps {
		fmt.Printf("  [%-7s] %s\n", s.kind, s.detail)
	}
	for _, d := range pl.kept {
		fmt.Printf("  [keep  ] %s (state: db, TLS, identity — add --purge to remove)\n", d)
	}
	for _, n := range pl.notes {
		fmt.Printf("  [note  ] %s\n", n)
	}
}

func modeLabel(dryRun, purge bool) string {
	switch {
	case dryRun:
		return "dry-run"
	case purge:
		return "purge"
	default:
		return "keep state"
	}
}

// cmdRunner runs a system command; overridable in tests.
type cmdRunner func(name string, args ...string) (string, error)

func execRunner(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// execute applies the plan with run, reporting each step. It stops at the
// first hard failure (e.g. a stop that fails must abort: the state dir may
// still be owned by a live process).
func (pl *uninstallPlan) execute(run cmdRunner) error {
	onSystemd := pathExists("/run/systemd/system")
	if !onSystemd {
		for _, s := range pl.steps {
			if s.kind == "stop" || s.kind == "disable" {
				pl.notes = append(pl.notes, "not on systemd — unit stop/disable skipped; stop any running partout process manually")
				break
			}
		}
	}

	for i, s := range pl.steps {
		var err error
		switch s.kind {
		case "stop", "disable":
			if !onSystemd {
				continue
			}
			_, err = run("systemctl", s.kind, s.unit)
		case "reload":
			if onSystemd {
				_, err = run("systemctl", "daemon-reload")
			}
		case "unit-file", "file":
			err = os.Remove(s.path)
		case "dir":
			err = os.RemoveAll(s.path)
		case "etc-dir":
			err = os.Remove(s.path) // Remove fails if non-empty (safety)
		case "user":
			if out, e := run("id", s.user); e != nil {
				fmt.Printf("  [%-7s] %s — not present, skipped\n", s.kind, s.detail)
				continue
			} else if out != "" {
				fmt.Printf("  [%-7s] %s (id: %s)\n", s.kind, s.detail, out)
			}
			_, err = run("userdel", s.user)
		}
		if err != nil {
			if os.IsNotExist(err) {
				// vanished between plan and apply — fine.
				fmt.Printf("  [%-7s] %s — already gone\n", s.kind, s.detail)
				continue
			}
			return fmt.Errorf("step %d/%d (%s) failed: %v", i+1, len(pl.steps), s.detail, err)
		}
		fmt.Printf("  [%-7s] %s — ok\n", s.kind, s.detail)
	}
	return nil
}

// runUninstall is the top-level `partout uninstall` entry point.
func runUninstall(args []string) {
	fs := flag.NewFlagSet("partout uninstall", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "print the removal plan and change nothing")
	purge := fs.Bool("purge", false, "also remove state (db, TLS, identity, spool), $HOME/.partout, and the partout system user")
	keepBinary := fs.Bool("keep-binary", false, "leave the partout binary in place")
	fs.Parse(args)

	env := defaultUninstallEnv()
	pl, err := buildUninstallPlan(env, *purge, *keepBinary)
	if err != nil {
		fmt.Fprintln(os.Stderr, "partout uninstall:", err)
		os.Exit(2)
	}
	if pl.scope == "none" {
		fmt.Println("partout uninstall: nothing to remove on this host (no units, env, state, or binary found)")
		return
	}
	pl.print(*dryRun, *purge)

	if *dryRun {
		fmt.Println("dry-run: nothing was changed")
		return
	}
	if pl.needsSystemRoot(env) && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "partout uninstall: this plan touches system paths — re-run with sudo (preview with --dry-run)")
		os.Exit(3)
	}

	// Tolerate the first SIGTERM/SIGINT: a remotely-dispatched uninstall
	// runs inside the agent's cgroup, and its own `systemctl stop` makes
	// systemd signal the whole cgroup, uninstall included. A second signal
	// aborts.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "partout uninstall: signal received — continuing (a second signal aborts)")
		<-sigCh
		os.Exit(1)
	}()

	if err := pl.execute(execRunner); err != nil {
		fmt.Fprintln(os.Stderr, "partout uninstall:", err)
		os.Exit(1)
	}

	fmt.Println("partout uninstall: done")
	if len(pl.kept) > 0 {
		fmt.Println("state kept at: " + strings.Join(pl.kept, ", "))
		fmt.Println("back it up if you need it, then `rm -rf` to finish (or re-run with --purge)")
	}
}

// ---- helpers ----------------------------------------------------------------

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// under reports whether p is dir or inside it.
func under(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// dedupeNested drops any path that is inside another path in the list.
func dedupeNested(paths []string) []string {
	out := make([]string, 0, len(paths))
	for i, p := range paths {
		nested := false
		for j, q := range paths {
			if i != j && under(p, q) {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, p)
		}
	}
	return out
}

// envFileValue reads KEY=VALUE from a simple env file ("" when absent).
func envFileValue(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, key+"=") {
			return strings.Trim(strings.TrimPrefix(line, key+"="), `"'`)
		}
	}
	return ""
}

func dirNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
