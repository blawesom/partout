package elevate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func mustPolicy(t *testing.T, json string) *Policy {
	t.Helper()
	p, err := LoadPolicyJSON([]byte(json))
	if err != nil {
		t.Fatalf("LoadPolicyJSON: %v", err)
	}
	return p
}

func TestRuleMatchExactArgs(t *testing.T) {
	p := mustPolicy(t, `{"rules":[{"allow":"haproxy","args":["-c","-f","/etc/haproxy/haproxy.cfg"]}]}`)
	if p.Check("haproxy", []string{"-c", "-f", "/etc/haproxy/haproxy.cfg"}) != Elevated {
		t.Error("exact args: want Elevated")
	}
	if p.Check("haproxy", []string{"-v"}) != Denied {
		t.Error("haproxy -v: want Denied")
	}
	if p.Check("haproxy", []string{"-c", "-f", "/etc/other.cfg"}) != Denied {
		t.Error("different file: want Denied")
	}
	if p.Check("nginx", []string{"-c", "-f", "/etc/haproxy/haproxy.cfg"}) != Denied {
		t.Error("different binary: want Denied")
	}
}

func TestRuleMatchVerbUnits(t *testing.T) {
	p := mustPolicy(t, `{"rules":[{"allow":"systemctl","verbs":["status","restart","reload"],"units":["haproxy*","nginx*","partout-*"]}]}`)
	cases := []struct {
		args []string
		want Decision
	}{
		{[]string{"restart", "haproxy"}, Elevated},
		{[]string{"restart", "haproxy.service"}, Elevated}, // * crosses the suffix dot
		{[]string{"status", "nginx"}, Elevated},
		{[]string{"status", "partout-agent.service"}, Elevated},
		{[]string{"start", "haproxy"}, Denied}, // start not in verbs
		{[]string{"restart", "ssh"}, Denied},   // unit not in scope
		{[]string{"restart", "haproxy", "--now"}, Denied},
		{[]string{"restart"}, Denied},
	}
	for _, c := range cases {
		if got := p.Check("systemctl", c.args); got != c.want {
			t.Errorf("systemctl %v = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestRuleMatchFiles(t *testing.T) {
	p := mustPolicy(t, `{"rules":[{"allow":"cat","files":["/etc/haproxy/*","/etc/nginx/*"]}]}`)
	if p.Check("cat", []string{"/etc/haproxy/haproxy.cfg"}) != Elevated {
		t.Error("haproxy.cfg: want Elevated")
	}
	if p.Check("cat", []string{"/etc/nginx/nginx.conf"}) != Elevated {
		t.Error("nginx.conf: want Elevated")
	}
	if p.Check("cat", []string{"/etc/shadow"}) != Denied {
		t.Error("/etc/shadow: want Denied (fail closed)")
	}
	if p.Check("cat", []string{"/etc/haproxy/haproxy.cfg", "/etc/shadow"}) != Denied {
		t.Error("two files: want Denied")
	}
}

func TestRuleAlternationAndGlobArgs(t *testing.T) {
	p := mustPolicy(t, `{"rules":[{"allow":"apt-get|dnf","args":["-y","*"]}]}`)
	if p.Check("apt-get", []string{"-y", "install", "nginx"}) == Elevated {
		t.Error("three args vs two patterns: want Denied")
	}
	if p.Check("apt-get", []string{"-y", "install"}) != Elevated {
		t.Error("apt-get -y install: want Elevated (* matches 'install')")
	}
	if p.Check("dnf", []string{"-y", "install"}) != Elevated {
		t.Error("dnf via alternation: want Elevated")
	}
}

func TestNilPolicyDenies(t *testing.T) {
	var p *Policy
	if p.Check("cat", []string{"/etc/passwd"}) != Denied {
		t.Error("nil policy: want Denied")
	}
	if p.RuleFor("cat", []string{"/etc/passwd"}) != nil {
		t.Error("nil policy: RuleFor want nil")
	}
}

func TestLoadRejectsBadRules(t *testing.T) {
	bad := []string{
		`{"rules":[{"args":["x"]}]}`,                              // empty allow
		`{"rules":[{"allow":"cat"}]}`,                             // no matcher
		`{"rules":[{"allow":"cat","files":["/x"],"args":["y"]}]}`, // two matchers
		`{"rules":[{"allow":"systemctl","verbs":["restart"]}]}`,   // verbs without units
		`{"rules":[{"allow":"cat","files":["a[b"]}]}`,             // bad glob
		`{not json`,
	}
	for _, s := range bad {
		if _, err := LoadPolicyJSON([]byte(s)); err == nil {
			t.Errorf("LoadPolicyJSON(%s): want error", s)
		}
	}
}

func TestLoadMergeOrderAndSources(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("10-base.json", `{"rules":[{"allow":"cat","files":["/etc/a/*"]}]}`)
	write("20-extra.json", `{"rules":[{"allow":"haproxy","args":["-c","-f","/etc/a/h.cfg"]}]}`)
	write("README.md", "not a policy — must be ignored")

	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("merged rules = %d, want 2", len(p.Rules))
	}
	if p.Rules[0].Allow != "cat" || p.Rules[1].Allow != "haproxy" {
		t.Errorf("merge order wrong: %v", p.Rules)
	}
	if len(p.Source()) != 2 {
		t.Errorf("sources = %v, want 2 files", p.Source())
	}

	// Empty dir = no policy, not an error.
	empty := t.TempDir()
	if p, err := Load(empty); err != nil || p != nil {
		t.Errorf("empty dir: got (%v, %v), want (nil, nil)", p, err)
	}
	// Empty / nonexistent path = no policy.
	if p, err := Load(""); err != nil || p != nil {
		t.Errorf("empty path: got (%v, %v), want (nil, nil)", p, err)
	}
	if _, err := Load(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("nonexistent file: want error")
	}

	// Single file works too.
	f := filepath.Join(dir, "solo.json")
	if err := os.WriteFile(f, []byte(`{"rules":[{"allow":"cat","files":["/x"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(f)
	if err != nil || len(p.Rules) != 1 || !reflect.DeepEqual(p.Source(), []string{f}) {
		t.Errorf("single file: got (%v, %v, %v)", p, err, p.Source())
	}
}

func TestPolicyHashStable(t *testing.T) {
	a := mustPolicy(t, `{"rules":[{"allow":"cat","files":["/x"]}]}`)
	b := mustPolicy(t, `{"rules":[{"allow":"cat","files":["/x"]}]}`)
	if a.PolicyHash() != b.PolicyHash() {
		t.Error("identical policies: hash must match")
	}
	c := mustPolicy(t, `{"rules":[{"allow":"cat","files":["/y"]}]}`)
	if a.PolicyHash() == c.PolicyHash() {
		t.Error("different policies: hash must differ")
	}
}
