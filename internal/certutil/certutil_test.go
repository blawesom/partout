package certutil

import (
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestCAIdempotent(t *testing.T) {
	dir := t.TempDir()

	ca1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	if !ca1.Cert.IsCA {
		t.Fatal("CA cert missing IsCA")
	}

	// Second load must return the same CA (cert bytes equal).
	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("reload CA: %v", err)
	}
	if string(ca1.Cert.Raw) != string(ca2.Cert.Raw) {
		t.Fatal("reloaded CA differs from original")
	}

	// Key file must be 0600.
	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ca.key mode = %o, want 0600", perm)
	}
}

func TestServerCertSANs(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	sc, err := LoadOrCreateServerCert(dir, ca, []string{"localhost", "127.0.0.1", "dev.example"})
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(sc.Certificate[0])
	if err != nil {
		t.Fatalf("parse server leaf: %v", err)
	}
	if len(leaf.DNSNames) != 2 || len(leaf.IPAddresses) != 1 {
		t.Fatalf("SANs: %v ips: %v", leaf.DNSNames, leaf.IPAddresses)
	}
	for _, want := range []string{"localhost", "dev.example"} {
		found := false
		for _, n := range leaf.DNSNames {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("server cert missing DNS SAN %q (have %v)", want, leaf.DNSNames)
		}
	}

	// Reload — must be identical (idempotent).
	sc2, err := LoadOrCreateServerCert(dir, ca, []string{"localhost"})
	if err != nil {
		t.Fatalf("reload server cert: %v", err)
	}
	if string(sc.Certificate[0]) != string(sc2.Certificate[0]) {
		t.Fatal("reloaded server cert differs")
	}
}

func TestServerCertVerifiesAgainstCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	sc, err := LoadOrCreateServerCert(dir, ca, []string{"localhost"})
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}

	leaf, err := x509.ParseCertificate(sc.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("server cert does not verify against CA: %v", err)
	}

	// Must NOT verify against a different CA.
	dir2 := t.TempDir()
	other, err := LoadOrCreateCA(dir2)
	if err != nil {
		t.Fatalf("create second CA: %v", err)
	}
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(other.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: otherRoots}); err == nil {
		t.Fatal("server cert verified against wrong CA")
	}
}

func TestAgentCSRFullRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	// Agent side: generate key + CSR (CN = agent uuid).
	uuid := "9f2c1a4e-0000-0000-0000-000000000001"
	csrPEM, key, err := NewCSR(uuid, nil)
	if err != nil {
		t.Fatalf("NewCSR: %v", err)
	}
	if key == nil {
		t.Fatal("NewCSR returned nil key")
	}

	// Server side: sign.
	leafPEM, err := ca.SignAgentCert(csrPEM, "ag_test")
	if err != nil {
		t.Fatalf("SignAgentCert: %v", err)
	}

	// The leaf must verify against the CA and carry the agent's public key.
	leafCert, err := parseCertPEM([]byte(leafPEM))
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leafCert.Subject.CommonName != "ag_test" {
		t.Fatalf("leaf CN = %q, want ag_test", leafCert.Subject.CommonName)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("agent leaf does not verify (clientAuth) against CA: %v", err)
	}
	leafPub, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key type = %T, want *ecdsa.PublicKey", leafCert.PublicKey)
	}
	if !leafPub.Equal(&key.PublicKey) {
		t.Fatal("leaf public key != CSR key public key")
	}
}

func TestPEMKeyRoundTrip(t *testing.T) {
	csrPEM, key, err := NewCSR("test", nil)
	if err != nil {
		t.Fatalf("NewCSR: %v", err)
	}
	_ = csrPEM
	enc := PEMKey(key)
	dec, err := parseECDSAKeyPEM(enc)
	if err != nil {
		t.Fatalf("parseECDSAKeyPEM: %v", err)
	}
	if !dec.Equal(key) {
		t.Fatal("key round-trip mismatch")
	}
}
