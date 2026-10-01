package elevate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
		ok   bool
	}{
		{"", None, true},
		{"none", None, true},
		{"NONE", None, true},
		{"sudo", Sudo, true},
		{" sudo ", Sudo, true},
		{"sudoers", Sudo, true},
		{"root", None, false},
		{"always", None, false},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.ok && err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Errorf("Parse(%q) expected error, got %v", c.in, got)
		}
		if c.ok && got != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRun(t *testing.T) {
	// none: untouched
	n, a := None.Run("apt-get", "upgrade")
	if n != "apt-get" || len(a) != 1 || a[0] != "upgrade" {
		t.Errorf("None.Run = (%q, %v), want (apt-get, [upgrade])", n, a)
	}
	// sudo: prefixed, original command intact after `--`
	n, a = Sudo.Run("apt-get", "-y", "upgrade")
	want := []string{"-n", "--", "apt-get", "-y", "upgrade"}
	if n != "sudo" || len(a) != len(want) {
		t.Fatalf("Sudo.Run = (%q, %v), want (sudo, %v)", n, a, want)
	}
	for i := range want {
		if a[i] != want[i] {
			t.Fatalf("Sudo.Run args = %v, want %v", a, want)
		}
	}
	// SudoPrefix
	if Sudo.SudoPrefix() == nil || None.SudoPrefix() != nil {
		t.Error("SudoPrefix wrong")
	}
}

func TestReadFileDirect(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, m := range []Mode{None, Sudo} {
		b, err := ReadFile(m, p)
		if err != nil || string(b) != "hello" {
			t.Errorf("ReadFile(%v) = %q, %v; want hello, nil", m, b, err)
		}
	}
}

func TestReadFileFallbackOnPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads anything; EACCES path not exercisable")
	}
	p := filepath.Join(t.TempDir(), "secret.cfg")
	if err := os.WriteFile(p, []byte("top-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0o600)

	// none: plain permission error, no elevation attempted.
	if _, err := ReadFile(None, p); !os.IsPermission(err) {
		t.Errorf("ReadFile(None) err = %v, want permission error", err)
	}

	// sudo: falls back to the (stubbed) elevated read.
	orig := elevatedOutput
	t.Cleanup(func() { elevatedOutput = orig })
	elevatedOutput = func(path string) ([]byte, error) {
		if path != p {
			t.Errorf("elevatedOutput called with %q", path)
		}
		return []byte("top-secret"), nil
	}
	b, err := ReadFile(Sudo, p)
	if err != nil || string(b) != "top-secret" {
		t.Errorf("ReadFile(Sudo) = %q, %v; want top-secret via fallback", b, err)
	}

	// sudo + elevated denial surfaces ErrDenied (stub returns what
	// classifyExitError would produce for a sudoers denial).
	elevatedOutput = func(path string) ([]byte, error) {
		return nil, classifyExitError("sudo: user is not allowed to execute /usr/bin/cat")
	}
	_, err = ReadFile(Sudo, p)
	if !errors.Is(err, ErrDenied) {
		t.Errorf("ReadFile(Sudo) err = %v, want ErrDenied", err)
	}
}

func TestElevatedOutputClassifiesDenial(t *testing.T) {
	if err := classifyExitError("sudo: outscale is not allowed to execute /usr/bin/cat."); err == nil || !errors.Is(err, ErrDenied) {
		t.Errorf("classify(%q) = %v, want ErrDenied", "sudo: outscale is not allowed to execute /usr/bin/cat.", err)
	}
	if err := classifyExitError("sudo: a password is required"); err == nil || !errors.Is(err, ErrDenied) {
		t.Errorf("classify(%q) = %v, want ErrDenied", "sudo: a password is required", err)
	}
	if err := classifyExitError("cat: /etc/x: No such file"); !strings.Contains(err.Error(), "No such file") {
		t.Errorf("classify(%q) = %v, want passthrough error", "cat: /etc/x: No such file", err)
	}
}
