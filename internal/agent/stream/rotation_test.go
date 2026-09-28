package stream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/identity"
)

// setupTLSCertDir writes a CA + an initial agent leaf + key to dir and returns
// the CA, the agent key, and the leaf's UUID (CN).
func setupTLSCertDir(t *testing.T, uuid string) (*certutil.CA, *ecdsa.PrivateKey, string) {
	t.Helper()
	ca, err := certutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, _, err := ca.SignLeafForPublicKey(&key.PublicKey, uuid, []string{uuid})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte(ca.CertPEM()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.crt"), []byte(leafPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), certutil.PEMKey(key), 0o600); err != nil {
		t.Fatal(err)
	}
	return ca, key, dir
}

// TestRotateLeaf verifies a freshly signed leaf is hot-swapped into the live
// client certificate, persisted to disk, and that an invalid leaf is rejected
// (leaving the current cert untouched).
func TestRotateLeaf(t *testing.T) {
	uuid := "ag_rotateleaf_test"
	ca, key, dir := setupTLSCertDir(t, uuid)

	id := &identity.Identity{UUID: uuid}
	cfg := Config{
		CAFile:   filepath.Join(dir, "ca.crt"),
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "key.pem"),
		TLSDir:   dir,
	}
	c := New(id, cfg, nil)

	before, ok := c.LeafNotAfter()
	if !ok {
		t.Fatal("no initial leaf loaded")
	}

	// Sign a NEW leaf for the SAME key (rotation re-signs the enrolled key).
	newLeaf, _, err := ca.SignLeafForPublicKey(&key.PublicKey, uuid, []string{uuid})
	if err != nil {
		t.Fatal(err)
	}
	caPEM := []byte(ca.CertPEM())
	if err := c.RotateLeaf([]byte(newLeaf), caPEM); err != nil {
		t.Fatalf("RotateLeaf (valid): %v", err)
	}
	after, ok := c.LeafNotAfter()
	if !ok {
		t.Fatal("no leaf after rotation")
	}
	// A freshly signed leaf must not expire before the old one did (and for a
	// same-key re-sign it is a brand-new 2-year window).
	if !after.After(before) && !after.Equal(before) {
		t.Errorf("rotated leaf expiry %s not >= original %s", after, before)
	}
	// Persisted to disk.
	onDisk, err := os.ReadFile(filepath.Join(dir, "agent.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != newLeaf {
		t.Error("rotated leaf not persisted to TLSDir/agent.crt")
	}

	// Invalid leaf (wrong CN) must be rejected and leave the cert untouched.
	badLeaf, _, err := ca.SignLeafForPublicKey(&key.PublicKey, "ag_wrong_cn", []string{"ag_wrong_cn"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RotateLeaf([]byte(badLeaf), caPEM); err == nil {
		t.Error("RotateLeaf accepted a leaf with a mismatched CN")
	}
	if cur, _ := c.LeafNotAfter(); !cur.Equal(after) {
		t.Error("rejected rotation changed the live cert")
	}
}

// TestRotateLeafNoTLS is a no-op guard: in plaintext mode there is nothing to
// rotate and RotateLeaf reports an error rather than panicking.
func TestRotateLeafNoTLS(t *testing.T) {
	id := &identity.Identity{UUID: "ag_plain"}
	c := New(id, Config{ServerURL: "localhost:1"}, nil) // no TLS material
	ca, err := certutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RotateLeaf([]byte("not-a-cert"), []byte(ca.CertPEM())); err == nil {
		t.Error("RotateLeaf with an invalid leaf should fail")
	}
}
