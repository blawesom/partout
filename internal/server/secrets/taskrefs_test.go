package secrets

import (
	"testing"

	"github.com/blawesom/partout/internal/proto"
)

func TestStepSecretRefs(t *testing.T) {
	steps := []*proto.TaskStep{
		{Kind: "command", Command: "echo", Args: []string{"secret:db_password"}},
		{Kind: "command", Env: map[string]string{"TOKEN": "secret:api_key"}},
		{Kind: "file", Content: "config with secret:db_password inline"},
		{Kind: "template", Template: "{{.pw}}", Vars: map[string]string{"pw": "secret:db_password"}},
		{Kind: "service", Service: "nginx"},
		{Kind: "command", Env: map[string]string{"PATH": "/usr/bin"}},
		{Kind: "assert", Expr: "host.distro == ubuntu"},
	}
	got := StepSecretRefs(steps)
	want := []string{"db_password", "api_key"}
	if len(got) != len(want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("refs = %v, want %v", got, want)
		}
	}
	if refs := StepSecretRefs(nil); len(refs) != 0 {
		t.Fatalf("nil steps: refs = %v, want empty", refs)
	}
	if refs := StepSecretRefs([]*proto.TaskStep{{Kind: "command", Command: "echo"}}); len(refs) != 0 {
		t.Fatalf("no-secret steps: refs = %v, want empty", refs)
	}
}

func TestParseSecretRef(t *testing.T) {
	for _, c := range []struct {
		in   string
		name string
		ok   bool
	}{
		{"secret:db_password", "db_password", true},
		{"secret:api.key-2_3", "api.key-2_3", true},
		{"secret:", "", false},
		{"secretx:foo", "", false},
		{"plain value", "", false},
		{"", "", false},
	} {
		name, ok := ParseSecretRef(c.in)
		if ok != c.ok || name != c.name {
			t.Errorf("ParseSecretRef(%q) = (%q, %v), want (%q, %v)", c.in, name, ok, c.name, c.ok)
		}
	}
}

// fakeMaterializer records calls and can fail selected names.
type fakeMaterializer struct {
	calls   []string
	failOn  map[string]bool
	onCall  func(name string)
	failAll bool
}

func (f *fakeMaterializer) Materialize(agentID, name, ref string) (int64, error) {
	f.calls = append(f.calls, name)
	if f.onCall != nil {
		f.onCall(name)
	}
	if f.failAll || f.failOn[name] {
		return 0, &fakeErr{"materialize " + name + " failed"}
	}
	return 1, nil
}

type fakeErr struct{ msg string }

func (e *fakeErr) Error() string { return e.msg }

func TestMaterializeForRun(t *testing.T) {
	// No refs: no calls, nil error.
	m := &fakeMaterializer{}
	if err := MaterializeForRun(m, "ag1", "run1", nil); err != nil {
		t.Fatalf("no refs: err = %v, want nil", err)
	}
	if len(m.calls) != 0 {
		t.Fatalf("no refs: calls = %v, want none", m.calls)
	}

	// Bound refs materialize exactly once each (distinct refs).
	m = &fakeMaterializer{}
	if err := MaterializeForRun(m, "ag1", "run1", []string{"db_password", "api_key"}); err != nil {
		t.Fatalf("bound refs: err = %v", err)
	}
	if len(m.calls) != 2 {
		t.Fatalf("calls = %v, want 2", m.calls)
	}

	// Unbound ref: error names the ref, nothing else materializes.
	m = &fakeMaterializer{failOn: map[string]bool{"api_key": true}}
	err := MaterializeForRun(m, "ag1", "run1", []string{"db_password", "api_key"})
	if err == nil {
		t.Fatal("unbound ref: want error")
	}
	if want := `secret "api_key": materialize api_key failed`; err.Error() != want {
		t.Fatalf("err = %q, want %q", err.Error(), want)
	}

	// Secrets feature off (nil materializer) + declaring task: clear error.
	err = MaterializeForRun(nil, "ag1", "run1", []string{"db_password"})
	if err == nil {
		t.Fatal("nil materializer: want error")
	}
	if want := "task declares secrets"; err.Error()[:len(want)] != want {
		t.Fatalf("err = %q, want prefix %q", err.Error(), want)
	}
	// Feature off + non-declaring task: no error (nil materializer, no refs).
	if err := MaterializeForRun(nil, "ag1", "run1", nil); err != nil {
		t.Fatalf("feature off, no refs: err = %v, want nil", err)
	}
}
