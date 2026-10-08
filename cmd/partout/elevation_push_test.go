// P2: server-signed elevation policy push — signature + verification + the
// root-context apply contract.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/cryptoutil"
	"github.com/blawesom/partout/internal/policy"
)

// helpers over the real types (the test lives in package main)
type elevatePolicy = elevate.Policy
type elevateDecision = elevate.Decision

func writePinnedKey(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	p := filepath.Join(dir, "server-policy.pub")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(pub)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func pushBundle(pushID, name, rulesJSON, sha string, sig []byte) []byte {
	b, _ := json.Marshal(elevationBundle{
		PushID: pushID, PolicyName: name, RulesJSON: rulesJSON, PolicySHA: sha,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	return b
}

func TestParseAndVerifyElevationBundle(t *testing.T) {
	kp, err := cryptoutil.NewKeyPairEd25519()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := writePinnedKey(t, dir, kp.Pub)

	rules := `[{"allow":"reboot"},{"allow":"/usr/local/bin/partout","args":["ctl","elevation","apply","*"]}]`
	sha := policyHashOf(rules)
	if sha == "" {
		t.Fatal("policyHashOf failed")
	}
	sig := policy.SignElevationPush(kp.Priv, "epp_test1", "default-baseline", sha)
	raw := pushBundle("epp_test1", "default-baseline", rules, sha, sig)

	bundle, pol, err := parseAndVerifyElevationBundle(raw, keyPath)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if bundle.PolicyName != "default-baseline" || len(pol.Rules) != 2 {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}

	// A forged signature (different key) must be refused.
	bad, _ := cryptoutil.NewKeyPairEd25519()
	sig2 := policy.SignElevationPush(bad.Priv, "epp_test1", "default-baseline", sha)
	if _, _, err := parseAndVerifyElevationBundle(pushBundle("epp_test1", "default-baseline", rules, sha, sig2), keyPath); err == nil {
		t.Fatal("forged signature accepted")
	}

	// Tampered policy content (sha no longer matches the signature's claim
	// target, and the hash check catches the substitution).
	if _, _, err := parseAndVerifyElevationBundle(pushBundle("epp_test1", "default-baseline", `[{"allow":"cat","files":["/etc/shadow"]}]`, sha, sig), keyPath); err == nil {
		t.Fatal("tampered policy accepted")
	}

	// A wrong pinned key file is refused, never bypassed.
	if _, _, err := parseAndVerifyElevationBundle(raw, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing pinned key accepted")
	}

	// The signature is domain-separated from Decisions: a Decision-style
	// signature over the same key does not verify as a push.
	if policy.VerifyElevationPush(kp.Pub, "epp_test1", "default-baseline", sha, policy.SignDecision(kp.Priv, "epp_test1", 1, "allow", nil, "admin", "")) {
		t.Fatal("decision signature accepted as a push signature")
	}
}

func TestSelfGrantRendersIntoSudoers(t *testing.T) {
	// The self-grant rule must render into the sudoers drop-in exactly as
	// the agent will invoke it (argv match): ctl elevation apply <path>.
	// Rendering resolves the binary via LookPath, so the test uses a real
	// (temp) executable; the argv pattern is what matters.
	bin := filepath.Join(t.TempDir(), "partout")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pol, err := elevateLoadRules(`[{"allow":"` + bin + `","args":["ctl","elevation","apply","-"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := pol.RenderSudoers("partout")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, bin+" ctl elevation apply -") {
		t.Fatalf("self-grant not rendered as an argv-matching grant:\n%s", rendered)
	}
	// And the matcher agrees: the apply invocation matches, an arbitrary
	// invocation of the binary does not.
	if pol.Check(bin, []string{"ctl", "elevation", "apply", "-"}) != elevateElevated() {
		t.Fatal("apply invocation does not match the self-grant")
	}
	if pol.Check(bin, []string{"ctl", "auth", "login", "evil"}) == elevateElevated() {
		t.Fatal("arbitrary ctl invocation matched the self-grant")
	}
}

// elevateLoadRules loads a rules array as a policy (test helper).
func elevateLoadRules(rulesJSON string) (*elevatePolicy, error) {
	return elevate.LoadPolicyJSON([]byte(`{"rules":` + rulesJSON + `}`))
}

// elevateElevated returns the match decision constant (test helper).
func elevateElevated() elevateDecision { return elevate.Elevated }
