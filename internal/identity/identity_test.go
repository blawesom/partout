package identity

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if id.UUID == "" {
		t.Fatal("empty uuid")
	}
	if len(id.Ed25519Priv) != 64 {
		t.Fatalf("ed25519 priv len = %d, want 64", len(id.Ed25519Priv))
	}
	if len(id.X25519Priv) != 32 {
		t.Fatalf("x25519 priv len = %d, want 32", len(id.X25519Priv))
	}
	if len(id.Ed25519Pub) != 32 {
		t.Fatalf("ed25519 pub len = %d, want 32", len(id.Ed25519Pub))
	}

	// Load the same identity.
	id2, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if id.UUID != id2.UUID {
		t.Fatalf("uuid mismatch: %s vs %s", id.UUID, id2.UUID)
	}
	if len(id2.Ed25519Priv) != 64 || len(id2.X25519Priv) != 32 {
		t.Fatal("load corrupted keys")
	}

	// Verify file permissions.
	info, err := os.Stat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Errorf("identity.json mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestSign(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	msg := []byte("test message")
	sig := id.Sign(msg)
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	// Verify with the public key.
	if !ed25519.Verify(id.Ed25519Pub, msg, sig) {
		t.Fatal("signature verification failed")
	}
}
