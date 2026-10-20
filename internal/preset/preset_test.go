package preset

import (
	"testing"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/agent/task"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/tasks"

	"github.com/blawesom/partout/internal/policy"
	"github.com/blawesom/partout/internal/store"
)

// TestApplySeedsAndIdempotent: a fresh store gets every default; applying
// again creates nothing.
func TestApplySeedsAndIdempotent(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	res, err := Apply(st)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res.Policies) != len(Policies) {
		t.Fatalf("first apply created %d policies, want %d", len(res.Policies), len(Policies))
	}
	if len(res.Alerts) != len(Alerts) {
		t.Fatalf("first apply created %d alerts, want %d", len(res.Alerts), len(Alerts))
	}
	if len(res.ElevationPolicies) != len(ElevationPolicies) {
		t.Fatalf("first apply created %d elevation policies, want %d", len(res.ElevationPolicies), len(ElevationPolicies))
	}
	if len(res.Tasks) != len(Tasks) {
		t.Fatalf("first apply created %d tasks, want %d", len(res.Tasks), len(Tasks))
	}
	if len(res.Jobs) != len(Jobs) {
		t.Fatalf("first apply created %d jobs, want %d", len(res.Jobs), len(Jobs))
	}
	// The seeded job must be PAUSED (ready to apply, running nothing).
	for _, jd := range Jobs {
		j, err := st.GetJobByName(jd.Name)
		if err != nil || j == nil {
			t.Fatalf("seeded job %s missing", jd.Name)
		}
		if j.Enabled {
			t.Fatalf("seeded job %s must be paused (enabled=false)", jd.Name)
		}
	}

	res2, err := Apply(st)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if len(res2.Policies) != 0 || len(res2.Alerts) != 0 || len(res2.ElevationPolicies) != 0 || len(res2.Tasks) != 0 || len(res2.Jobs) != 0 {
		t.Fatalf("re-apply created rows, want none: %+v", res2)
	}
}

// TestApplyRestoresMissingOnly: deleted defaults come back; user rows
// (including user-edited defaults) are never touched.
func TestApplyRestoresMissingOnly(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if _, err := Apply(st); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// User edits: rename-ish change — modify a default's effect and add a
	// user rule.
	rules, _ := st.ListPolicies()
	var target *store.PolicyRule
	for i := range rules {
		if rules[i].Name == "default-require-approval-reboot" {
			target = &rules[i]
		}
	}
	if target == nil {
		t.Fatal("preset reboot rule missing")
	}
	// Delete one default policy, one default alert, and the modified rule
	// stays.
	if _, err := st.DeletePolicy(target.ID); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	alerts, _ := st.ListAlertRules()
	if len(alerts) != len(Alerts) {
		t.Fatalf("alert count %d, want %d", len(alerts), len(Alerts))
	}
	if err := st.DeleteAlertRule(alerts[0].ID); err != nil {
		t.Fatalf("DeleteAlertRule: %v", err)
	}

	cp, err := Apply(st)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if len(cp.Policies) != 1 || cp.Policies[0] != "default-require-approval-reboot" {
		t.Fatalf("restored policies = %v, want only the deleted default", cp)
	}
	if len(cp.Alerts) != 1 || cp.Alerts[0] != alerts[0].Name {
		t.Fatalf("restored alerts = %v, want only the deleted default", cp.Alerts)
	}
}

// TestPresetRulesEvaluate: the seeded regexes catch the dangerous commands
// and leave ordinary work alone.
func TestPresetRulesEvaluate(t *testing.T) {
	rules := make([]policy.Rule, 0, len(Policies))
	for _, p := range Policies {
		m := p.Match
		m.Hosts = "" // evaluate host-scope-free
		rules = append(rules, policy.Rule{Name: p.Name, Match: m, Effect: p.Effect})
	}

	cases := []struct {
		cmd  string
		want string
	}{
		{"rm -rf /", policy.EffectDeny},
		{"sudo rm -r -f /", policy.EffectDeny},
		{"rm --no-preserve-root -rf /", policy.EffectDeny},
		{"rm -rf /*", policy.EffectDeny},
		{"rm -rf /tmp/build", policy.EffectAllow},
		{"rm -rf /var/cache/apt/archives", policy.EffectAllow},
		{"dd if=/dev/zero of=/dev/sda", policy.EffectDeny},
		{"dd if=/dev/urandom of=/tmp/rand", policy.EffectAllow},
		{"mkfs.ext4 /dev/sdb1", policy.EffectDeny},
		{"wipefs -a /dev/sdc", policy.EffectDeny},
		{"shred -v /dev/sdd", policy.EffectDeny},
		{"echo hack > /etc/shadow", policy.EffectDeny},
		{"echo x >> /etc/passwd", policy.EffectDeny},
		{"systemctl restart haproxy", policy.EffectAllow},
		{"reboot", policy.EffectRequireApproval},
		{"systemctl reboot", policy.EffectRequireApproval},
		{"shutdown -h now", policy.EffectRequireApproval},
		{"cat /var/log/reboot.log", policy.EffectAllow}, // not a command
		{"cat /reboot", policy.EffectAllow},             // path fragment
		{"cat mkfs.ext4.txt", policy.EffectAllow},       // filename
		{"rebooted", policy.EffectAllow},                // suffix word
	}
	for _, c := range cases {
		d := policy.Evaluate(rules, policy.Action{
			Cmd:         firstWord(c.cmd),
			CommandLine: c.cmd,
			ActionClass: policy.ActionExec,
			ActorRole:   "admin",
		})
		if d.Effect != c.want {
			t.Errorf("Evaluate(%q) = %s, want %s (rules: %v)", c.cmd, d.Effect, c.want, d.MatchedRules)
		}
	}
}

func firstWord(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i]
		}
	}
	return s
}

// TestSeededElevationPoliciesValid: every seeded policy must load as an
// elevation policy AND render valid sudoers (provisioning ships it as a
// drop-in document; a bad preset would break every --elevate run).
func TestSeededElevationPoliciesValid(t *testing.T) {
	for _, ep := range ElevationPolicies {
		pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + ep.RulesJSON + `}`))
		if err != nil {
			t.Fatalf("preset elevation policy %s: %v", ep.Name, err)
		}
		if _, err := pol.RenderSudoers("partout"); err != nil {
			t.Fatalf("preset elevation policy %s: render: %v", ep.Name, err)
		}
		if pol.PolicyHash() == "" {
			t.Fatalf("preset elevation policy %s: empty hash", ep.Name)
		}
	}
}

// TestSeededTiers pins the tier contract: the preset seeds the three
// tiers, the broad tier covers every command shape the agent itself
// invokes (the entire point of broad-as-default — no field-discovered
// incantations for day-2 work) and elevates no shell, and the full tier
// is the standalone NOPASSWD: ALL grant. default-strict seeds the old
// field-validated baseline document: narrower than broad but
// wildcard-shaped, so Tier() reports it honestly (the description says
// the same in plain words).
func TestSeededTiers(t *testing.T) {
	seeded := map[string]*elevate.Policy{}
	for _, ep := range ElevationPolicies {
		pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + ep.RulesJSON + `}`))
		if err != nil {
			t.Fatalf("preset elevation policy %s: %v", ep.Name, err)
		}
		seeded[ep.Name] = pol
	}
	if seeded["default-broad"].Tier() != "broad" {
		t.Errorf("default-broad: Tier() = %q, want broad", seeded["default-broad"].Tier())
	}
	if seeded["default-full"].Tier() != "full" {
		t.Errorf("default-full: Tier() = %q, want full", seeded["default-full"].Tier())
	}
	// The seeded strict document is narrower than broad (standard units
	// only) but not wildcard-free; its classifier verdict is broad and
	// its description says so. What must hold: it grants strictly less
	// than default-broad.
	strict, broadLocal := seeded["default-strict"], seeded["default-broad"]
	for _, argv := range [][]string{
		{"systemctl", "restart", "my-own-unit"},
		{"useradd", "--system", "--no-create-home", "myapp"},
		{"groupadd", "docker"},
		{"systemctl", "daemon-reload"},
	} {
		if strict.Check(argv[0], argv[1:]) == elevate.Elevated {
			t.Errorf("default-strict elevates %v — it must be narrower than default-broad", argv)
		}
		if broadLocal.Check(argv[0], argv[1:]) != elevate.Elevated {
			t.Errorf("default-broad does NOT elevate the agent-invoked shape: %v", argv)
		}
	}
	for _, name := range []string{"default-broad", "default-strict", "default-full"} {
		if seeded[name] == nil {
			t.Errorf("preset does not seed %s", name)
		}
	}
	// Role-shaped profiles (P3.3): tier classification + scope contracts.
	if seeded["profile-web"].Tier() != "broad" {
		t.Errorf("profile-web: Tier() = %q, want broad (prefix + unit-scoped grants)", seeded["profile-web"].Tier())
	}
	if seeded["profile-database"].Tier() != "broad" {
		t.Errorf("profile-database: Tier() = %q, want broad (wildcard units)", seeded["profile-database"].Tier())
	}
	if seeded["profile-minimal"].Tier() != "strict" {
		t.Errorf("profile-minimal: Tier() = %q, want strict (exact-argv only)", seeded["profile-minimal"].Tier())
	}
	for _, name := range []string{"profile-web", "profile-database", "profile-minimal"} {
		if seeded[name] == nil {
			t.Errorf("preset does not seed %s", name)
		}
	}
	// profile-web: web fleet verbs elevate, non-web scope does not.
	web := seeded["profile-web"]
	for _, argv := range [][]string{
		{"nginx", "-t"},
		{"haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"},
		{"caddy", "validate", "--config", "Caddyfile"},
		{"systemctl", "restart", "nginx"},
		{"cat", "/etc/nginx/nginx.conf"},
		{"apt-get", "-y", "upgrade"},
		{"reboot"},
	} {
		if web.Check(argv[0], argv[1:]) != elevate.Elevated {
			t.Errorf("profile-web does NOT elevate the web shape: %v", argv)
		}
	}
	for _, argv := range [][]string{
		{"useradd", "--system", "myapp"},
		{"systemctl", "restart", "postgresql"},
		{"bash"},
	} {
		if web.Check(argv[0], argv[1:]) == elevate.Elevated {
			t.Errorf("profile-web elevates out-of-profile scope: %v", argv)
		}
	}
	// profile-database: DB unit verbs + package updates elevate; no
	// reboot, no config reads, no non-DB units.
	db := seeded["profile-database"]
	for _, argv := range [][]string{
		{"systemctl", "status", "postgresql"},
		{"systemctl", "restart", "mysqld"},
		{"apt-get", "-y", "upgrade"},
	} {
		if db.Check(argv[0], argv[1:]) != elevate.Elevated {
			t.Errorf("profile-database does NOT elevate the DB shape: %v", argv)
		}
	}
	for _, argv := range [][]string{
		{"reboot"},
		{"cat", "/etc/postgresql/postgresql.conf"},
		{"systemctl", "restart", "nginx"},
		{"useradd", "foo"},
	} {
		if db.Check(argv[0], argv[1:]) == elevate.Elevated {
			t.Errorf("profile-database elevates out-of-profile scope: %v", argv)
		}
	}
	// profile-minimal: upgrades + self-grant only.
	minimal := seeded["profile-minimal"]
	for _, argv := range [][]string{
		{"apt-get", "-y", "upgrade"},
		{"dnf", "-y", "upgrade"},
		{"/usr/local/bin/partout", "ctl", "elevation", "apply", "-"},
	} {
		if minimal.Check(argv[0], argv[1:]) != elevate.Elevated {
			t.Errorf("profile-minimal does NOT elevate the minimal shape: %v", argv)
		}
	}
	for _, argv := range [][]string{
		{"reboot"},
		{"systemctl", "restart", "nginx"},
		{"nginx", "-t"},
		{"cat", "/etc/nginx/nginx.conf"},
	} {
		if minimal.Check(argv[0], argv[1:]) == elevate.Elevated {
			t.Errorf("profile-minimal elevates out-of-profile scope: %v", argv)
		}
	}
	broadPol := seeded["default-broad"]
	// The exact command shapes the agent invokes (internal/agent pkg +
	// task executor): every one must elevate under broad.
	shapes := [][]string{
		{"apt-get", "-qq", "update"},
		{"apt-get", "-o", "Dpkg::Progress-Focus=full", "-s", "upgrade"},
		{"apt-get", "-o", "Dpkg::Progress-Focus=full", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade"},
		{"apt-get", "-y", "install", "vim", "fail2ban", "btop"},
		{"apt-get", "-y", "remove", "cowsay"},
		{"dnf", "-q", "makecache"},
		{"dnf", "-y", "upgrade"},
		{"dnf", "check-update"},
		{"dnf", "upgrade", "--assumeno"},
		{"dnf", "-y", "install", "htop"},
		{"systemctl", "restart", "partout-agent"},
		{"systemctl", "start", "myapp"},
		{"systemctl", "enable", "nginx"},
		{"systemctl", "is-active", "sshd"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "reboot"},
		{"useradd", "--system", "--no-create-home", "myapp"},
		{"groupadd", "docker"},
		{"hostnamectl", "set-hostname", "web05"},
		{"nginx", "-t"},
		{"haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"},
		{"cat", "/etc/haproxy/haproxy.cfg"},
		{"shutdown", "-r", "now"},
		{"reboot"},
		{"/usr/local/bin/partout", "ctl", "elevation", "apply", "-"},
	}
	for _, argv := range shapes {
		if broadPol.Check(argv[0], argv[1:]) != elevate.Elevated {
			t.Errorf("broad tier does NOT elevate the agent-invoked shape: %v", argv)
		}
	}
	// And it must NOT elevate a shell (the point of broad over full).
	for _, argv := range [][]string{{"bash"}, {"sh", "-c", "id"}, {"/bin/sh"}, {"sudo", "bash"}} {
		if broadPol.Check(argv[0], argv[1:]) == elevate.Elevated {
			t.Errorf("broad tier elevates a shell: %v", argv)
		}
	}
}

// TestSeededTasksDecode: the seeded task steps must decode (the jobs
// controller loads them on reconcile) — and every `when` guard must parse
// against the live evaluator (a broken guard skips the step silently).
func TestSeededTasksDecode(t *testing.T) {
	for _, td := range Tasks {
		steps, err := store.DecodeTaskSteps(td.StepsJSON)
		if err != nil {
			t.Fatalf("preset task %s: %v", td.Name, err)
		}
		if len(steps) == 0 {
			t.Fatalf("preset task %s: no steps", td.Name)
		}
		// A real fact set: every guard must EVALUATE (true or false —
		// a guard that errors against live facts skips its step silently).
		w := task.NewWhenEvaluator(map[string]string{"host.distro": "rocky"})
		for _, st := range steps {
			if st.When == "" {
				continue
			}
			if _, err := w.Eval(st.When); err != nil {
				t.Fatalf("preset task %s: step %q guard %q: %v", td.Name, st.Name, st.When, err)
			}
		}
	}
}

// TestSeededEOLUpgradeRule: default-require-approval-eol-upgrade gates
// package applies on ended hosts (pkg.apply + eol=ended →
// require_approval) and leaves supported hosts alone. Task upgrade steps
// evaluate under the same class server-side (tasks.StepActions).
func TestSeededEOLUpgradeRule(t *testing.T) {
	var rule *policy.Rule
	for _, p := range Policies {
		if p.Name == "default-require-approval-eol-upgrade" {
			m := p.Match
			r := policy.Rule{Name: p.Name, Match: m, Effect: p.Effect}
			rule = &r
			break
		}
	}
	if rule == nil {
		t.Fatal("preset EOL upgrade rule missing")
	}
	// Ended host + pkg.apply → require_approval.
	d := policy.Evaluate([]policy.Rule{*rule}, policy.Action{
		ActionClass: policy.ActionPkgApply, HostEOL: policy.EOLEnded,
		CommandLine: "apt-get -y upgrade",
	})
	if d.Effect != policy.EffectRequireApproval {
		t.Fatalf("ended host pkg.apply: effect = %s, want require_approval", d.Effect)
	}
	// Supported host + pkg.apply → allow.
	d = policy.Evaluate([]policy.Rule{*rule}, policy.Action{
		ActionClass: policy.ActionPkgApply, HostEOL: policy.EOLSupported,
		CommandLine: "apt-get -y upgrade",
	})
	if d.Effect != policy.EffectAllow {
		t.Fatalf("supported host pkg.apply: effect = %s, want allow", d.Effect)
	}
	// A task upgrade step on an ended host evaluates the same (server-side
	// step gating maps package/upgrade steps to the pkg.apply class).
	steps := []*pb.TaskStep{{Kind: "upgrade", Name: "daily upgrade"}}
	sd := tasks.EvaluateRunSteps([]policy.Rule{*rule}, policy.Action{
		ActionClass: policy.ActionTaskRun, HostEOL: policy.EOLEnded, ActorRole: "admin",
	}, steps)
	if sd.Effect != policy.EffectRequireApproval {
		t.Fatalf("ended host task upgrade: effect = %s, want require_approval", sd.Effect)
	}
	// The same step on a supported host is fine.
	sd = tasks.EvaluateRunSteps([]policy.Rule{*rule}, policy.Action{
		ActionClass: policy.ActionTaskRun, HostEOL: policy.EOLSupported, ActorRole: "admin",
	}, steps)
	if sd.Effect != policy.EffectAllow {
		t.Fatalf("supported host task upgrade: effect = %s, want allow", sd.Effect)
	}
}
