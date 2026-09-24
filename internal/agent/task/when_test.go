package task

import "testing"

func TestWhenEval(t *testing.T) {
	facts := map[string]string{
		"host.distro":           "ubuntu",
		"host.distro_version":   "24.04",
		"host.os":               "linux",
		"host.arch":             "amd64",
		"partout.agent_uuid":    "test-uuid",
	}
	tests := []struct {
		expr  string
		want  bool
		err   bool
	}{
		// Basic comparisons.
		{`host.distro == 'ubuntu'`, true, false},
		{`host.distro == 'debian'`, false, false},
		{`host.distro != 'debian'`, true, false},
		{`host.os == 'linux'`, true, false},
		// In list.
		{`host.distro in ['ubuntu','debian']`, true, false},
		{`host.distro in ['rhel','fedora']`, false, false},
		// Boolean literals.
		{`true`, true, false},
		{`false`, false, false},
		// Negation.
		{`!host.distro == 'debian'`, true, false},
		{`!false`, true, false},
		// AND.
		{`host.distro == 'ubuntu' and host.arch == 'amd64'`, true, false},
		{`host.distro == 'ubuntu' and host.distro == 'debian'`, false, false},
		// OR.
		{`host.distro == 'ubuntu' or host.distro == 'debian'`, true, false},
		{`host.distro == 'centos' or host.distro == 'rhel'`, false, false},
		// Nested.
		{`((host.distro == 'ubuntu') or (host.distro == 'debian')) and host.arch == 'amd64'`, true, false},
		// Empty → true.
		{"", true, false},
		// Error cases.
		{`host.distro == "ubuntu"`, true, false}, // double-quote string is ok
		{`bad_func('x')`, false, true},            // unknown identifier
	}
	for _, tc := range tests {
		w := NewWhenEvaluator(facts)
		got, err := w.Eval(tc.expr)
		hasErr := err != nil
		if hasErr != tc.err {
			t.Errorf("%q: got err=%v, want err=%v", tc.expr, err, tc.err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestWhenFileExists(t *testing.T) {
	facts := map[string]string{"host.distro": "ubuntu"}
	w := NewWhenEvaluator(facts)
	w.SetFileExists(func(p string) bool {
		return p == "/tmp/partout"
	})
	tests := []struct {
		expr  string
		want  bool
		err   bool
	}{
		{`file.exists('/tmp/partout')`, true, false},
		{`file.exists('/nonexistent')`, false, false},
		{`!file.exists('/nonexistent')`, true, false},
	}
	for _, tc := range tests {
		got, err := w.Eval(tc.expr)
		if (err != nil) != tc.err {
			t.Errorf("%q: err=%v, want err=%v", tc.expr, err, tc.err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.expr, got, tc.want)
		}
	}
}