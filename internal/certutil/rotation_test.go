package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSignLeafForPublicKey_RoundTrip verifies the rotation primitives: sign a
// leaf from a stored public key, then verify it (valid CN, valid CA), and that
// a wrong CN or a different CA is rejected.
func TestSignLeafForPublicKey_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	agentID := "ag_rotation_test"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, serial, err := ca.SignLeafForPublicKey(&key.PublicKey, agentID, []string{agentID})
	if err != nil {
		t.Fatalf("SignLeafForPublicKey: %v", err)
	}
	if leafPEM == "" || serial == "" {
		t.Fatalf("empty leaf/serial: %q %q", leafPEM, serial)
	}

	// Valid: chains to CA, CN matches.
	if err := VerifyAgentLeaf([]byte(leafPEM), []byte(ca.CertPEM()), agentID); err != nil {
		t.Errorf("VerifyAgentLeaf (valid): %v", err)
	}
	// Wrong CN.
	if err := VerifyAgentLeaf([]byte(leafPEM), []byte(ca.CertPEM()), "ag_other"); err == nil {
		t.Error("VerifyAgentLeaf accepted a mismatched CN")
	}
	// Different CA.
	dir2 := t.TempDir()
	ca2, err := LoadOrCreateCA(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAgentLeaf([]byte(leafPEM), []byte(ca2.CertPEM()), agentID); err == nil {
		t.Error("VerifyAgentLeaf accepted a leaf signed by a different CA")
	}

	// NotAfter should be roughly LeafValidity out.
	na, err := ParseLeafNotAfter([]byte(leafPEM))
	if err != nil {
		t.Fatalf("ParseLeafNotAfter: %v", err)
	}
	if days := int(na.Sub(time.Now()) / (24 * 3600 * 1e9)); days < 700 || days > 750 {
		t.Errorf("leaf validity = %d days, want ~730", days)
	}
}

// TestCSRPubKey verifies the CSR public-key extraction used to persist the
// enrolled key at enrollment time.
func TestCSRPubKey(t *testing.T) {
	csrPEM, key, err := NewCSR("cn-test", []string{"cn-test"})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := CSRPubKey(csrPEM)
	if err != nil {
		t.Fatalf("CSRPubKey: %v", err)
	}
	if pub.Equal(&key.PublicKey) != true {
		t.Error("CSRPubKey did not return the CSR's public key")
	}
	if _, err := CSRPubKey([]byte("not a csr")); err == nil {
		t.Error("CSRPubKey accepted garbage")
	}
}

// TestPersistCAKeypair is a guard that the CA dir persists (rotation relies on
// the CA surviving restarts).
func TestPersistCAKeypair(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s: %v", f, err)
		}
	}
}
