package elevate

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRenderTiersSudoersSmoke renders the full and broad tiers and
// visudo-checks them when visudo is available (it is on the dev box and
// the Rocky CI leg; skipped elsewhere). The full tier must be the
// one-line NOPASSWD: ALL artifact; the broad tier's prefix grant must
// render with the trailing `*`.
func TestRenderTiersSudoersSmoke(t *testing.T) {
	full, err := LoadPolicyJSON([]byte(`{"rules":[{"full":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if full.Tier() != "full" {
		t.Fatalf("tier = %q, want full", full.Tier())
	}
	out, err := full.RenderSudoers("partout")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "NOPASSWD: ALL") {
		t.Fatalf("full tier render missing NOPASSWD: ALL:\n%s", out)
	}

	broad, err := LoadPolicyJSON([]byte(`{"rules":[
		{"allow":"apt-get","args_prefix":["-y","install"]},
		{"allow":"systemctl","verbs":["restart","reload"],"units":["*"]},
		{"allow":"reboot"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if broad.Tier() != "broad" {
		t.Fatalf("tier = %q, want broad", broad.Tier())
	}
	out2, err := broad.RenderSudoers("partout")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, "/usr/bin/apt-get -y install *") {
		t.Fatalf("broad render missing prefix grant line:\n%s", out2)
	}

	// visudo validation (best-effort; the renderer's contract is that its
	// output passes `visudo -cf`).
	if _, err := exec.LookPath("visudo"); err != nil {
		t.Skip("visudo not available")
	}
	for i, doc := range []string{out, out2} {
		tmp, err := os.CreateTemp("", "suders-*.tmp")
		if err != nil {
			t.Fatal(err)
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)
		if _, err := tmp.WriteString(doc); err != nil {
			t.Fatal(err)
		}
		tmp.Close()
		if b, err := exec.Command("visudo", "-cf", tmpName).CombinedOutput(); err != nil {
			t.Fatalf("doc %d: visudo rejected:\n%s\n%s", i, err, b)
		}
	}
}

// TestArgsPrefixMatching pins the prefix matcher semantics: the argv head
// must match element-wise, any remainder is allowed.
func TestArgsPrefixMatching(t *testing.T) {
	pol, err := LoadPolicyJSON([]byte(`{"rules":[{"allow":"apt-get","args_prefix":["-y","install"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"apt-get", "-y", "install", "vim", "btop"}, true},
		{[]string{"apt-get", "-y", "install"}, true},
		{[]string{"apt-get", "-y"}, false},             // prefix longer than argv
		{[]string{"apt-get", "install", "vim"}, false}, // head mismatch
		{[]string{"dnf", "-y", "install", "vim"}, false},
	}
	for _, c := range cases {
		if got := pol.Check(c.argv[0], c.argv[1:]) == Elevated; got != c.want {
			t.Errorf("Check(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

// TestFullTierValidation pins the full-tier document contract.
func TestFullTierValidation(t *testing.T) {
	bad := []string{
		`{"rules":[{"full":true,"allow":"bash"}]}`,       // scoped full
		`{"rules":[{"full":true,"args":["x"]}]}`,         // args with full
		`{"rules":[{"full":true},{"allow":"reboot"}]}`,   // mixed document
		`{"rules":[{"full":true,"args_prefix":["-y"]}]}`, // prefix with full
	}
	for _, js := range bad {
		if _, err := LoadPolicyJSON([]byte(js)); err == nil {
			t.Errorf("expected rejection for %s", js)
		}
	}
	if _, err := LoadPolicyJSON([]byte(`{"rules":[{"full":false,"allow":"reboot"}]}`)); err != nil {
		t.Errorf("explicit full:false must be a normal rule: %v", err)
	}
}
