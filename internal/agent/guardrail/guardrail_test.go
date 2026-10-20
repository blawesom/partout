package guardrail

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
)

func testServerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func bundleWith(rules []policy.Rule, serverPub []byte) *pb.PolicyBundle {
	rulesJSON, _ := json.Marshal(rules)
	return &pb.PolicyBundle{
		Version:      7,
		ContentHash:  "test-hash",
		RulesJson:    string(rulesJSON),
		ServerPubkey: []byte(base64.StdEncoding.EncodeToString(serverPub)),
		HostTags:     map[string]string{"env": "prod"},
		HostRoles:    []string{"web"},
		AgentId:      "ag_test",
	}
}

// No bundle received → deny (fail closed).
func TestRecheckNoBundle(t *testing.T) {
	g := NewGuard("ag_test", t.TempDir())
	ok, reason := g.Recheck(&pb.Command{RunId: "r1", Cmd: "ls"})
	if ok {
		t.Fatal("should deny with no bundle")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

// Empty rule set (default allow) + valid signed allow → pass.
func TestRecheckEmptyRulesAllow(t *testing.T) {
	pub, priv := testServerKey(t)
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(nil, pub))
	sig := policy.SignDecision(priv, "r1", 7, policy.EffectAllow, nil, "admin", "")
	cmd := &pb.Command{RunId: "r1", Cmd: "ls", Args: []string{"-la"}}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	ok, reason := g.Recheck(cmd)
	if !ok {
		t.Fatalf("empty rules should allow, got: %s", reason)
	}
}

// Bundle version mismatch → deny.
func TestRecheckVersionMismatch(t *testing.T) {
	pub, priv := testServerKey(t)
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(nil, pub))
	sig := policy.SignDecision(priv, "r1", 6, policy.EffectAllow, nil, "admin", "")
	cmd := &pb.Command{RunId: "r1", Cmd: "ls"}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 6, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	ok, reason := g.Recheck(cmd)
	if ok {
		t.Fatal("should deny version mismatch")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

// No decision in command → deny.
func TestRecheckNoDecision(t *testing.T) {
	pub, _ := testServerKey(t)
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(nil, pub))
	cmd := &pb.Command{RunId: "r1", Cmd: "ls"}
	ok, reason := g.Recheck(cmd)
	if ok {
		t.Fatal("should deny with no decision")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

// Invalid signature → deny.
func TestRecheckBadSignature(t *testing.T) {
	pub, _ := testServerKey(t)
	_, otherPriv := testServerKey(t)
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(nil, pub))
	sig := policy.SignDecision(otherPriv, "r1", 7, policy.EffectAllow, nil, "admin", "")
	cmd := &pb.Command{RunId: "r1", Cmd: "ls"}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	ok, reason := g.Recheck(cmd)
	if ok {
		t.Fatal("should deny bad signature")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

// Local re-check catches a rule the server missed: deny rule matches,
// server signed allow → fail closed.
func TestRecheckLocalDenyOverrides(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID:       "no-rm",
		Effect:   policy.EffectDeny,
		Priority: 1,
		Match: policy.Match{
			CommandRegex: `rm\s+-rf`,
		},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(rules, pub))
	// Server signed allow (pretending it didn't match the deny rule).
	sig := policy.SignDecision(priv, "r1", 7, policy.EffectAllow, nil, "admin", "")
	cmd := &pb.Command{RunId: "r1", Cmd: "rm", Args: []string{"-rf", "/"}}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	ok, reason := g.Recheck(cmd)
	if ok {
		t.Fatal("local re-check should deny rm -rf")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

// Host-tag-scoped deny: rule targets tag env=prod; agent has env=prod → deny.
func TestRecheckHostTagScoped(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID:       "no-prod-deploy",
		Effect:   policy.EffectDeny,
		Priority: 1,
		Match: policy.Match{
			Hosts:        "tag:env=prod",
			CommandRegex: "deploy",
		},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(rules, pub))
	sig := policy.SignDecision(priv, "r2", 7, policy.EffectAllow, nil, "admin", "")
	cmd := &pb.Command{RunId: "r2", Cmd: "deploy"}
	cmd.Decision = &pb.Decision{
		RunId: "r2", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	ok, reason := g.Recheck(cmd)
	if ok {
		t.Fatal("host-tag-scoped deny should fire")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

// Bundle + server public key persist across restarts.
func TestPersistAndLoad(t *testing.T) {
	dir := t.TempDir()
	pub, _ := testServerKey(t)
	rules := []policy.Rule{{
		ID: "r1", Effect: policy.EffectDeny, Priority: 1,
		Match: policy.Match{Actions: []string{"reboot"}},
	}}
	g := NewGuard("ag_test", dir)
	g.OnBundle(bundleWith(rules, pub))

	// New guard, load from disk.
	g2 := NewGuard("ag_test", dir)
	if err := g2.Load(); err != nil {
		t.Fatal(err)
	}
	if !g2.Loaded() {
		t.Fatal("should load from disk")
	}
	if g2.BundleVersion() != 7 {
		t.Fatalf("version = %d, want 7", g2.BundleVersion())
	}
	if len(g2.rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(g2.rules))
	}
	if len(g2.serverPub) == 0 {
		t.Fatal("server pub should persist")
	}
	for _, f := range []string{"policy.json", "policy.meta", "server.pub"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
}

// M4: an approved decision (EffectAllow + approval_id, signed) passes even
// when the local bundle still carries the require_approval rule that parked
// the action — the signed decision is the authority.
func TestRecheckApprovedDecisionPassesRequireApproval(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID:       "approval-rm",
		Effect:   policy.EffectRequireApproval,
		Priority: 1,
		Match:    policy.Match{CommandRegex: `rm\s+-rf`},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(rules, pub))

	sig := policy.SignDecision(priv, "r1", 7, policy.EffectAllow,
		[]string{"approval-rm"}, "operator", "apr_1")
	cmd := &pb.Command{RunId: "r1", Cmd: "rm", Args: []string{"-rf", "/tmp/junk"}}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 7, Effect: policy.EffectAllow,
		MatchedRules: []string{"approval-rm"}, ActorRole: "operator",
		ApprovalId: "apr_1", Sig: sig,
	}
	ok, reason := g.Recheck(cmd)
	if !ok {
		t.Fatalf("approved decision should pass; reason: %s", reason)
	}
}

// M4: a forged approval id (signature covers the approval ref) is rejected.
func TestRecheckApprovedDecisionBadSignature(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "approval-rm", Effect: policy.EffectRequireApproval, Priority: 1,
		Match: policy.Match{CommandRegex: `rm\s+-rf`},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(rules, pub))

	// Sign for approval apr_1, then graft a foreign approval id apr_2.
	sig := policy.SignDecision(priv, "r1", 7, policy.EffectAllow,
		[]string{"approval-rm"}, "operator", "apr_1")
	cmd := &pb.Command{RunId: "r1", Cmd: "rm", Args: []string{"-rf", "/"}}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 7, Effect: policy.EffectAllow,
		MatchedRules: []string{"approval-rm"}, ActorRole: "operator",
		ApprovalId: "apr_2", Sig: sig,
	}
	if ok, _ := g.Recheck(cmd); ok {
		t.Fatal("forged approval ref must be rejected")
	}
}

// M4: an approval does NOT override a local hard deny.
func TestRecheckApprovedDecisionHardDenyWins(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "hard-deny-rm", Effect: policy.EffectDeny, Priority: 1,
		Match: policy.Match{CommandRegex: `rm\s+-rf`},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(rules, pub))

	sig := policy.SignDecision(priv, "r1", 7, policy.EffectAllow,
		[]string{"hard-deny-rm"}, "admin", "apr_1")
	cmd := &pb.Command{RunId: "r1", Cmd: "rm", Args: []string{"-rf", "/"}}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 7, Effect: policy.EffectAllow,
		MatchedRules: []string{"hard-deny-rm"}, ActorRole: "admin",
		ApprovalId: "apr_1", Sig: sig,
	}
	if ok, reason := g.Recheck(cmd); ok {
		t.Fatal("hard deny must win over an approval")
	} else if reason == "" {
		t.Fatal("expected a deny reason")
	}
}

// M4: an approved decision with a non-allow effect is rejected.
func TestRecheckApprovedDecisionWrongEffect(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "approval-rm", Effect: policy.EffectRequireApproval, Priority: 1,
		Match: policy.Match{CommandRegex: `rm\s+-rf`},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWith(rules, pub))

	sig := policy.SignDecision(priv, "r1", 7, policy.EffectDeny,
		[]string{"approval-rm"}, "admin", "apr_1")
	cmd := &pb.Command{RunId: "r1", Cmd: "rm", Args: []string{"-rf", "/"}}
	cmd.Decision = &pb.Decision{
		RunId: "r1", BundleVersion: 7, Effect: policy.EffectDeny,
		MatchedRules: []string{"approval-rm"}, ActorRole: "admin",
		ApprovalId: "apr_1", Sig: sig,
	}
	if ok, _ := g.Recheck(cmd); ok {
		t.Fatal("deny-effect decision must not pass")
	}
}

// --- EOL predicate (PRD §5.6 EOL→policy gating) ---

// bundleWithEOL is bundleWith plus the host's EOL state (rides in the
// PolicyBundle like tags/roles).
func bundleWithEOL(rules []policy.Rule, serverPub []byte, hostEOL string) *pb.PolicyBundle {
	b := bundleWith(rules, serverPub)
	b.HostEol = hostEOL
	return b
}

// TestRecheckPkgEOLEndedHostFailsClosed: the bundle carries the seeded
// EOL require-approval rule and the host's ended state; a server-signed
// allow for a pkg apply is rejected locally (the server must park it for
// approval instead).
func TestRecheckPkgEOLEndedHostFailsClosed(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "default-require-approval-eol-upgrade", Effect: policy.EffectRequireApproval, Priority: 1,
		Match: policy.Match{Actions: []string{policy.ActionPkgApply}, EOL: policy.EOLEnded},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWithEOL(rules, pub, policy.EOLEnded))

	// Server signed allow (pretending the rule did not match).
	sig := policy.SignDecision(priv, "op1", 7, policy.EffectAllow, nil, "admin", "")
	op := &pb.PkgOp{OpId: "op1", Kind: pb.PkgOpKind_PKG_APPLY}
	op.Decision = &pb.Decision{
		RunId: "op1", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	ok, reason := g.RecheckPkg(op)
	if ok {
		t.Fatal("ended-host pkg.apply must fail the local re-check")
	}
	if reason == "" {
		t.Fatal("expected a reason")
	}
}

// TestRecheckPkgEOLSupportedHostAllowed: same rule, supported state → the
// signed allow passes the re-check.
func TestRecheckPkgEOLSupportedHostAllowed(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "default-require-approval-eol-upgrade", Effect: policy.EffectRequireApproval, Priority: 1,
		Match: policy.Match{Actions: []string{policy.ActionPkgApply}, EOL: policy.EOLEnded},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWithEOL(rules, pub, policy.EOLSupported))

	sig := policy.SignDecision(priv, "op1", 7, policy.EffectAllow, nil, "admin", "")
	op := &pb.PkgOp{OpId: "op1", Kind: pb.PkgOpKind_PKG_APPLY}
	op.Decision = &pb.Decision{
		RunId: "op1", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	if ok, reason := g.RecheckPkg(op); !ok {
		t.Fatalf("supported-host pkg.apply should pass; reason: %s", reason)
	}
}

// TestRecheckPkgDecisionEOLStateWins: when the signed Decision carries the
// EOL state (dispatch-time context), it is authoritative for the re-check —
// even over a stale bundle snapshot.
func TestRecheckPkgDecisionEOLStateWins(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "default-require-approval-eol-upgrade", Effect: policy.EffectRequireApproval, Priority: 1,
		Match: policy.Match{Actions: []string{policy.ActionPkgApply}, EOL: policy.EOLEnded},
	}}
	// Bundle says supported (stale); the decision says ended.
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWithEOL(rules, pub, policy.EOLSupported))

	sig := policy.SignDecision(priv, "op1", 7, policy.EffectAllow, nil, "admin", "")
	op := &pb.PkgOp{OpId: "op1", Kind: pb.PkgOpKind_PKG_APPLY}
	op.Decision = &pb.Decision{
		RunId: "op1", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig, EolState: policy.EOLEnded,
	}
	if ok, _ := g.RecheckPkg(op); ok {
		t.Fatal("decision's ended state must drive the re-check (rule must match)")
	}
}

// TestRecheckTaskPackageStepEOL: a task run with a package/upgrade step is
// re-checked as a pkg.apply-class action — the EOL rule gates task upgrades
// agent-side too.
func TestRecheckTaskPackageStepEOL(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "default-require-approval-eol-upgrade", Effect: policy.EffectRequireApproval, Priority: 1,
		Match: policy.Match{Actions: []string{policy.ActionPkgApply}, EOL: policy.EOLEnded},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWithEOL(rules, pub, policy.EOLEnded))

	sig := policy.SignDecision(priv, "run1", 7, policy.EffectAllow, nil, "admin", "")
	run := &pb.TaskRun{RunId: "run1", Steps: []*pb.TaskStep{
		{Kind: "upgrade", Name: "daily upgrade"},
	}}
	run.Decision = &pb.Decision{
		RunId: "run1", BundleVersion: 7, Effect: policy.EffectAllow,
		ActorRole: "admin", Sig: sig,
	}
	if ok, _ := g.RecheckTask(run); ok {
		t.Fatal("ended-host task upgrade step must fail the local re-check")
	}
}

// TestRecheckApprovedEOLPkgApply: after a human approves, the signed
// approval decision passes even though the bundle still carries the EOL
// require-approval rule.
func TestRecheckApprovedEOLPkgApply(t *testing.T) {
	pub, priv := testServerKey(t)
	rules := []policy.Rule{{
		ID: "default-require-approval-eol-upgrade", Effect: policy.EffectRequireApproval, Priority: 1,
		Match: policy.Match{Actions: []string{policy.ActionPkgApply}, EOL: policy.EOLEnded},
	}}
	g := NewGuard("ag_test", t.TempDir())
	g.OnBundle(bundleWithEOL(rules, pub, policy.EOLEnded))

	sig := policy.SignDecision(priv, "op1", 7, policy.EffectAllow,
		[]string{"default-require-approval-eol-upgrade"}, "operator", "apr_9")
	op := &pb.PkgOp{OpId: "op1", Kind: pb.PkgOpKind_PKG_APPLY}
	op.Decision = &pb.Decision{
		RunId: "op1", BundleVersion: 7, Effect: policy.EffectAllow,
		MatchedRules: []string{"default-require-approval-eol-upgrade"},
		ActorRole:    "operator", ApprovalId: "apr_9", Sig: sig,
	}
	if ok, reason := g.RecheckPkg(op); !ok {
		t.Fatalf("approved ended-host pkg.apply should pass; reason: %s", reason)
	}
}
