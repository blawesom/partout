package preset

import (
	"testing"

	"github.com/blawesom/partout/internal/agent/elevate"

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

// TestSeededTasksDecode: the seeded task steps must decode (the jobs
// controller loads them on reconcile).
func TestSeededTasksDecode(t *testing.T) {
	for _, td := range Tasks {
		steps, err := store.DecodeTaskSteps(td.StepsJSON)
		if err != nil {
			t.Fatalf("preset task %s: %v", td.Name, err)
		}
		if len(steps) == 0 {
			t.Fatalf("preset task %s: no steps", td.Name)
		}
	}
}
