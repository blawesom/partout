// Master-key bootstrap (Setup checklist backend): the UI's one-click enable
// generates a 32-byte key into the data-dir default file, adopts an
// existing file instead of clobbering it, and LoadMasterKeyWithDefault
// picks it up with env vars keeping precedence.
package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapKeyGenerateAndAdopt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.key")

	k1, err := BootstrapKey(p)
	if err != nil {
		t.Fatalf("BootstrapKey: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("key length = %d, want 32", len(k1))
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %o, want 0600", perm)
	}

	// A second bootstrap adopts the same key — never rotates it.
	k2, err := BootstrapKey(p)
	if err != nil {
		t.Fatalf("second BootstrapKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("second bootstrap returned a different key (rotation risk)")
	}

	// The default-path fallback loads it without any env configuration.
	k3, err := LoadMasterKeyWithDefault(p)
	if err != nil {
		t.Fatalf("LoadMasterKeyWithDefault: %v", err)
	}
	if !bytes.Equal(k1, k3) {
		t.Fatalf("fallback key differs from bootstrapped key")
	}
}

func TestLoadMasterKeyWithDefaultPrecedence(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.key")

	// No env, no file → disabled.
	if _, err := LoadMasterKeyWithDefault(p); !errors.Is(err, ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}

	// Env beats the data-dir file.
	k, err := BootstrapKey(p)
	if err != nil {
		t.Fatalf("BootstrapKey: %v", err)
	}
	t.Setenv("PARTOUT_SECRET_KEY", "01234567890123456789012345678901")
	got, err := LoadMasterKeyWithDefault(p)
	if err != nil {
		t.Fatalf("LoadMasterKeyWithDefault: %v", err)
	}
	if bytes.Equal(got, k) {
		t.Fatalf("env key did not take precedence over the default file")
	}
}

func TestBootstrapKeyRefusesBadExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(p, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapKey(p); err == nil {
		t.Fatalf("bootstrap over a wrong-size key file must fail, not clobber it")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "too-short" {
		t.Fatalf("existing key file was modified")
	}
}
