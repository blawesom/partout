package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkFakeInstall builds a fake Partout install under t.TempDir() and returns
// the uninstallEnv pointing at it.
func mkFakeInstall(t *testing.T, units []string, etcFiles map[string]string, withVarDB, withBinary, withGuard, withHomeAgent bool) uninstallEnv {
	t.Helper()
	root := t.TempDir()
	env := uninstallEnv{
		unitDir:   filepath.Join(root, "etc/systemd/system"),
		etcDir:    filepath.Join(root, "etc/partout"),
		varDir:    filepath.Join(root, "var/lib/partout"),
		fileRoot:  filepath.Join(root, "home/partout"),
		homeDir:   filepath.Join(root, "home"),
		binPath:   filepath.Join(root, "usr/local/bin/partout"),
		guardPath: filepath.Join(root, "usr/local/sbin/partout-update-guard"),
	}
	for _, u := range units {
		if err := os.MkdirAll(env.unitDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env.unitDir, u), []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if len(etcFiles) > 0 {
		if err := os.MkdirAll(env.etcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range etcFiles {
			if err := os.WriteFile(filepath.Join(env.etcDir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if withVarDB {
		if err := os.MkdirAll(env.varDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env.varDir, "partout.db"), []byte("db"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if withBinary {
		if err := os.MkdirAll(filepath.Dir(env.binPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.binPath, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if withGuard {
		if err := os.MkdirAll(filepath.Dir(env.guardPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.guardPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if withHomeAgent {
		dir := filepath.Join(env.homeDir, ".partout")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

func stepKinds(pl *uninstallPlan) []string {
	out := make([]string, 0, len(pl.steps))
	for _, s := range pl.steps {
		out = append(out, s.kind+" "+s.unit+s.path+s.user)
	}
	return out
}

func TestUninstallPlanServerDefaultKeepsData(t *testing.T) {
	env := mkFakeInstall(t,
		[]string{"partout-server.service", "partout-backup.timer"},
		map[string]string{"server.env": "PARTOUT_TOKEN_ADMIN=x\n"},
		true, true, false, false)
	pl, err := buildUninstallPlan(env, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if pl.scope != "server" {
		t.Fatalf("scope = %q, want server", pl.scope)
	}
	kinds := stepKinds(pl)
	// stop + disable for both units, unit files, env file, binary, reload.
	for _, want := range []string{
		"stop partout-server.service",
		"stop partout-backup.timer",
		"disable partout-server.service",
		"unit-file " + filepath.Join(env.unitDir, "partout-server.service"),
		"file " + filepath.Join(env.etcDir, "server.env"),
		"file " + env.binPath,
		"reload ",
	} {
		if !containsStr(kinds, want) {
			t.Errorf("plan missing %q; plan: %v", want, kinds)
		}
	}
	// data kept by default
	if len(pl.kept) != 1 || pl.kept[0] != env.varDir {
		t.Errorf("kept = %v, want [%s]", pl.kept, env.varDir)
	}
	for _, s := range pl.steps {
		if s.kind == "dir" || s.kind == "user" {
			t.Errorf("default plan must not remove state or the user: %v", s)
		}
	}
	if !pl.needsSystemRoot(env) {
		t.Error("expected needsSystemRoot = true")
	}
}

func TestUninstallPlanPurgeRemovesStateAndUser(t *testing.T) {
	env := mkFakeInstall(t,
		[]string{"partout-embedded.service"},
		nil, true, true, false, false)
	pl, err := buildUninstallPlan(env, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if pl.scope != "embedded" {
		t.Fatalf("scope = %q, want embedded", pl.scope)
	}
	kinds := stepKinds(pl)
	if !containsStr(kinds, "dir "+env.varDir) {
		t.Errorf("purge plan missing state dir removal; plan: %v", kinds)
	}
	if !containsStr(kinds, "user partout") {
		t.Errorf("purge plan missing user removal; plan: %v", kinds)
	}
	if len(pl.kept) != 0 {
		t.Errorf("purge plan kept %v", pl.kept)
	}
}

// TestUninstallPlanFileRoot: the file root (operator-uploaded files,
// spec-file-root) is kept by default and removed with --purge.
func TestUninstallPlanFileRoot(t *testing.T) {
	env := mkFakeInstall(t, []string{"partout-agent.service"}, nil, true, true, false, false)
	if err := os.MkdirAll(env.fileRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	// Kept by default (non-purge).
	pl, err := buildUninstallPlan(env, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(pl.kept, env.fileRoot) {
		t.Errorf("file root not listed as kept; kept: %v", pl.kept)
	}
	// Purge removes it.
	pl, err = buildUninstallPlan(env, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(stepKinds(pl), "dir "+env.fileRoot) {
		t.Errorf("purge plan missing file root removal; plan: %v", stepKinds(pl))
	}
}

func TestUninstallPlanKeepBinary(t *testing.T) {
	env := mkFakeInstall(t, nil, nil, false, true, false, false)
	pl, _ := buildUninstallPlan(env, false, true)
	if pl.scope != "files" {
		t.Fatalf("scope = %q, want files", pl.scope)
	}
	for _, s := range pl.steps {
		if s.path == env.binPath {
			t.Errorf("keep-binary: plan still removes %s", env.binPath)
		}
	}
}

func TestUninstallPlanNothing(t *testing.T) {
	env := uninstallEnv{
		unitDir:   "/nonexistent-partout-test",
		etcDir:    "/nonexistent-partout-test/etc",
		varDir:    "/nonexistent-partout-test/var",
		homeDir:   "/nonexistent-partout-test/home",
		binPath:   "/nonexistent-partout-test/bin",
		guardPath: "/nonexistent-partout-test/guard",
	}
	pl, err := buildUninstallPlan(env, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if pl.scope != "none" || len(pl.steps) != 0 {
		t.Fatalf("scope = %q steps = %v, want none/empty", pl.scope, pl.steps)
	}
}

func TestUninstallPlanAgentCustomDataDirs(t *testing.T) {
	root := t.TempDir()
	env := mkFakeInstall(t,
		[]string{"partout-agent.service"},
		map[string]string{
			"agent.env": "PARTOUT_DATA_DIR=" + filepath.Join(root, "alt-agent") + "\n",
		},
		false, false, true, true)
	// a custom agent data dir OUTSIDE varDir
	if err := os.MkdirAll(filepath.Join(root, "alt-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	pl, err := buildUninstallPlan(env, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if pl.scope != "agent" {
		t.Fatalf("scope = %q, want agent", pl.scope)
	}
	kinds := stepKinds(pl)
	if !containsStr(kinds, "dir "+filepath.Join(root, "alt-agent")) {
		t.Errorf("purge plan missing custom agent data dir; plan: %v", kinds)
	}
	if !containsStr(kinds, "dir "+filepath.Join(env.homeDir, ".partout")) {
		t.Errorf("purge plan missing $HOME/.partout; plan: %v", kinds)
	}
	if !containsStr(kinds, "file "+env.guardPath) {
		t.Errorf("purge plan missing update guard removal; plan: %v", kinds)
	}
}

func TestUninstallPlanCustomDBPath(t *testing.T) {
	root := t.TempDir()
	customDB := filepath.Join(root, "data/custom/partout.db")
	if err := os.MkdirAll(filepath.Dir(customDB), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customDB, []byte("db"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := mkFakeInstall(t,
		[]string{"partout-server.service"},
		map[string]string{"server.env": "PARTOUT_DB_PATH=" + customDB + "\n"},
		false, false, false, false)
	pl, err := buildUninstallPlan(env, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(stepKinds(pl), "dir "+filepath.Dir(customDB)) {
		t.Errorf("purge plan missing custom db dir; plan: %v", stepKinds(pl))
	}
}

func TestUninstallExecuteOrderAndEffects(t *testing.T) {
	env := mkFakeInstall(t,
		[]string{"partout-server.service"},
		map[string]string{"server.env": "PARTOUT_TOKEN_ADMIN=x\n"},
		true, true, false, false)
	pl, err := buildUninstallPlan(env, true, false)
	if err != nil {
		t.Fatal(err)
	}

	var calls []string
	run := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "id" {
			return "", fmt.Errorf("no such user: partout") // force the skip path
		}
		return "", nil
	}
	if err := pl.execute(run); err != nil {
		t.Fatal(err)
	}

	// ordering: stop before disable, daemon-reload last among lifecycle steps
	idx := func(s string) int {
		for i, c := range calls {
			if c == s {
				return i
			}
		}
		return -1
	}
	stop := idx("systemctl stop partout-server.service")
	dis := idx("systemctl disable partout-server.service")
	rel := idx("systemctl daemon-reload")
	if stop == -1 || dis == -1 || rel == -1 {
		t.Fatalf("missing lifecycle calls: %v", calls)
	}
	if !(stop < dis && dis < rel) {
		t.Fatalf("wrong order: %v", calls)
	}
	if idx("userdel partout") != -1 {
		t.Errorf("userdel called though `id partout` failed: %v", calls)
	}

	// effects: unit file, env file + dir, binary, state dir all gone
	for _, p := range []string{
		filepath.Join(env.unitDir, "partout-server.service"),
		env.etcDir,
		env.binPath,
		env.varDir,
	} {
		if pathExists(p) {
			t.Errorf("%s should have been removed", p)
		}
	}
}

func TestUninstallExecuteAbortsOnStopFailure(t *testing.T) {
	env := mkFakeInstall(t,
		[]string{"partout-server.service"},
		nil, true, true, false, false)
	pl, _ := buildUninstallPlan(env, true, false)
	run := func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "stop" {
			return "unit is active", fmt.Errorf("stop failed")
		}
		return "", nil
	}
	if err := pl.execute(run); err == nil {
		t.Fatal("expected error when stop fails")
	}
	// state must be untouched after an aborted run
	if !pathExists(env.varDir) {
		t.Error("state dir removed despite failed stop")
	}
}

func TestUninstallHelpers(t *testing.T) {
	if !under("/a/b/c", "/a/b") {
		t.Error("under: /a/b/c should be under /a/b")
	}
	if under("/a/b", "/a/b/c") {
		t.Error("under: /a/b is not under /a/b/c")
	}
	if under("/other", "/a/b") {
		t.Error("under: /other is not under /a/b")
	}
	got := dedupeNested([]string{"/var/lib/partout", "/var/lib/partout/agent", "/etc/partout"})
	if len(got) != 2 {
		t.Errorf("dedupeNested = %v, want 2 entries", got)
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
