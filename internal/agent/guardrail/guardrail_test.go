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
	sig := policy.SignDecision(priv, "r1", 7, policy.EffectAllow, nil, "admin")
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
	sig := policy.SignDecision(priv, "r1", 6, policy.EffectAllow, nil, "admin")
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
	sig := policy.SignDecision(otherPriv, "r1", 7, policy.EffectAllow, nil, "admin")
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
	sig := policy.SignDecision(priv, "r1", 7, policy.EffectAllow, nil, "admin")
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
	sig := policy.SignDecision(priv, "r2", 7, policy.EffectAllow, nil, "admin")
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
