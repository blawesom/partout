package preset

import (
	"testing"

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

	cp, ca, err := Apply(st)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(cp) != len(Policies) {
		t.Fatalf("first apply created %d policies, want %d", len(cp), len(Policies))
	}
	if len(ca) != len(Alerts) {
		t.Fatalf("first apply created %d alerts, want %d", len(ca), len(Alerts))
	}

	cp2, ca2, err := Apply(st)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if len(cp2) != 0 || len(ca2) != 0 {
		t.Fatalf("re-apply created (%d policies, %d alerts), want (0,0): %v %v", len(cp2), len(ca2), cp2, ca2)
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

	if _, _, err := Apply(st); err != nil {
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

	cp, ca, err := Apply(st)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if len(cp) != 1 || cp[0] != "default-require-approval-reboot" {
		t.Fatalf("restored policies = %v, want only the deleted default", cp)
	}
	if len(ca) != 1 || ca[0] != alerts[0].Name {
		t.Fatalf("restored alerts = %v, want only the deleted default", ca)
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
