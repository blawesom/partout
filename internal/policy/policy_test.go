package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func keypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// --- Evaluate basics ---

func TestEvaluateEmptyRules(t *testing.T) {
	d := Evaluate(nil, Action{CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Fatalf("effect = %q, want %q", d.Effect, EffectAllow)
	}
}

func TestEvaluateSingleDeny(t *testing.T) {
	d := Evaluate([]Rule{
		{ID: "r1", Match: Match{ActorRoles: []string{"operator"}}, Effect: EffectDeny},
	}, Action{ActorRole: "operator", CommandLine: "echo hi"})
	if d.Effect != EffectDeny {
		t.Fatalf("effect = %q, want deny", d.Effect)
	}
	if len(d.MatchedRules) != 1 || d.MatchedRules[0] != "r1" {
		t.Errorf("matched = %v", d.MatchedRules)
	}
}

func TestEvaluateDenyWinsOverAllow(t *testing.T) {
	d := Evaluate([]Rule{
		{ID: "r1", Match: Match{}, Effect: EffectAllow},
		{ID: "r2", Match: Match{}, Effect: EffectDeny},
	}, Action{})
	if d.Effect != EffectDeny {
		t.Fatalf("effect = %q, want deny (deny > allow)", d.Effect)
	}
}

func TestEvaluateRequireApprovalWinsOverAllow(t *testing.T) {
	d := Evaluate([]Rule{
		{ID: "r1", Effect: EffectAllow},
		{ID: "r2", Effect: EffectRequireApproval},
	}, Action{})
	if d.Effect != EffectRequireApproval {
		t.Fatalf("effect = %q, want require_approval (require_approval > allow)", d.Effect)
	}
}

func TestEvaluateNoMatchDefaultAllow(t *testing.T) {
	d := Evaluate([]Rule{
		{ID: "r1", Match: Match{CommandRegex: "^systemctl\\s+restart"}},
	}, Action{CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Fatalf("effect = %q, want allow (no rule matched)", d.Effect)
	}
}

func TestEvaluateActorRoleFilter(t *testing.T) {
	rule := Rule{ID: "r1", Match: Match{ActorRoles: []string{"admin"}}, Effect: EffectDeny}
	// admin → deny
	d := Evaluate([]Rule{rule}, Action{ActorRole: "admin", CommandLine: "echo hi"})
	if d.Effect != EffectDeny {
		t.Fatalf("admin: effect = %q, want deny", d.Effect)
	}
	// operator → allow (not in the rule's actor_roles)
	d = Evaluate([]Rule{rule}, Action{ActorRole: "operator", CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Fatalf("operator: effect = %q, want allow", d.Effect)
	}
}

func TestEvaluateCommandRegex(t *testing.T) {
	rule := Rule{ID: "r1", Match: Match{CommandRegex: "^systemctl\\s+restart"}, Effect: EffectDeny}
	for _, tc := range []struct {
		line string
		want string
	}{
		{"systemctl restart nginx", EffectDeny},
		{"systemctl  restart  nginx", EffectDeny}, // regex \s+
		{"echo systemctl restart nginx", EffectAllow},
		{"apt-get upgrade", EffectAllow},
	} {
		d := Evaluate([]Rule{rule}, Action{CommandLine: tc.line})
		if d.Effect != tc.want {
			t.Errorf("line %q: effect = %q, want %q", tc.line, d.Effect, tc.want)
		}
	}
}

func TestEvaluateHostSelectorRole(t *testing.T) {
	rule := Rule{ID: "r1", Match: Match{Hosts: "role:prod"}, Effect: EffectDeny}
	// host with role prod → deny
	d := Evaluate([]Rule{rule}, Action{HostID: "ag_1", HostRoles: []string{"prod"}, CommandLine: "echo hi"})
	if d.Effect != EffectDeny {
		t.Errorf("role:prod on prod host: effect = %q, want deny", d.Effect)
	}
	// host with role web → allow
	d = Evaluate([]Rule{rule}, Action{HostID: "ag_2", HostRoles: []string{"web"}, CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Errorf("role:prod on web host: effect = %q, want allow", d.Effect)
	}
	// host with no roles → allow
	d = Evaluate([]Rule{rule}, Action{HostID: "ag_3", CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Errorf("role:prod on no-role host: effect = %q, want allow", d.Effect)
	}
}

func TestEvaluateHostSelectorTag(t *testing.T) {
	rule := Rule{ID: "r1", Match: Match{Hosts: "tag:env=prod"}, Effect: EffectDeny}
	d := Evaluate([]Rule{rule}, Action{HostTags: map[string]string{"env": "prod"}, CommandLine: "echo hi"})
	if d.Effect != EffectDeny {
		t.Errorf("tag:env=prod on matching host: effect = %q, want deny", d.Effect)
	}
	d = Evaluate([]Rule{rule}, Action{HostTags: map[string]string{"env": "dev"}, CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Errorf("tag:env=prod on non-matching host: effect = %q, want allow", d.Effect)
	}
	d = Evaluate([]Rule{rule}, Action{HostTags: map[string]string{}, CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Errorf("tag:env=prod on host without tag: effect = %q, want allow", d.Effect)
	}
}

func TestEvaluateHostSelectorKeyOnly(t *testing.T) {
	rule := Rule{ID: "r1", Match: Match{Hosts: "tag:env"}, Effect: EffectDeny}
	// has the key → match
	d := Evaluate([]Rule{rule}, Action{HostTags: map[string]string{"env": "prod"}, CommandLine: "echo hi"})
	if d.Effect != EffectDeny {
		t.Errorf("tag:env on host with key: effect = %q, want deny", d.Effect)
	}
	// missing key → no match
	d = Evaluate([]Rule{rule}, Action{HostTags: map[string]string{"foo": "bar"}, CommandLine: "echo hi"})
	if d.Effect != EffectAllow {
		t.Errorf("tag:env on host without key: effect = %q, want allow", d.Effect)
	}
}

func TestEvaluateHostSelectorAll(t *testing.T) {
	rule := Rule{ID: "r1", Match: Match{Hosts: "all"}, Effect: EffectDeny}
	d := Evaluate([]Rule{rule}, Action{})
	if d.Effect != EffectDeny {
		t.Errorf("hosts=on all host: effect = %q, want deny", d.Effect)
	}
}

// --- BuildBundle ---

func TestBuildBundle(t *testing.T) {
	rules := []Rule{
		{ID: "r2", Name: "B", Effect: EffectDeny},
		{ID: "r1", Name: "A", Effect: EffectAllow},
	}
	v, hash, j := BuildBundle(rules)
	if v != 2 {
		t.Errorf("version = %d, want 2", v)
	}
	if hash == "" {
		t.Error("empty hash")
	}
	// JSON must be sorted by ID.
	if j[0] != '[' {
		t.Fatalf("bad JSON array: %s", j[:80])
	}
}

func TestBuildBundleEmpty(t *testing.T) {
	v, _, j := BuildBundle(nil)
	if v != 0 {
		t.Errorf("version = %d, want 0", v)
	}
	if j != "[]" {
		t.Errorf("JSON = %q, want []", j)
	}
}

// --- Decision signing ---

func TestSignVerify(t *testing.T) {
	pub, priv := keypair()
	runID := "run_test"
	sig := SignDecision(priv, runID, 42, EffectDeny, []string{"r1", "r2"}, "")
	if len(sig) != 64 {
		t.Fatalf("sig len = %d, want 64", len(sig))
	}
	if !VerifyDecision(pub, runID, 42, EffectDeny, []string{"r1", "r2"}, "", sig) {
		t.Fatal("VerifyDecision failed for valid sig")
	}
}

func TestSignVerifyTampered(t *testing.T) {
	pub, priv := keypair()
	sig := SignDecision(priv, "run_a", 10, EffectAllow, nil, "")
	if VerifyDecision(pub, "run_b", 10, EffectAllow, nil, "", sig) {
		t.Error("sig verified with different runID")
	}
	if VerifyDecision(pub, "run_a", 99, EffectAllow, nil, "", sig) {
		t.Error("sig verified with different version")
	}
	if VerifyDecision(pub, "run_a", 10, EffectDeny, nil, "", sig) {
		t.Error("sig verified with different effect")
	}
}

func TestSignVerifyNoMatchedRules(t *testing.T) {
	pub, priv := keypair()
	sig := SignDecision(priv, "run_x", 1, EffectAllow, nil, "")
	if !VerifyDecision(pub, "run_x", 1, EffectAllow, nil, "", sig) {
		t.Fatal("sig failed for nil matched rules")
	}
}

func TestSignVerifyEmptyRuleList(t *testing.T) {
	_, priv := keypair()
	// Both nil → must produce identical payloads.
	sig1 := SignDecision(priv, "r", 1, EffectAllow, nil, "")
	sig2 := SignDecision(priv, "r", 1, EffectAllow, []string{}, "")
	if string(sig1) != string(sig2) {
		t.Fatal("nil vs empty []string produce different sigs")
	}
}
