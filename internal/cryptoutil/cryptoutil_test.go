package cryptoutil

import (
	"bytes"
	"testing"
)

func TestEd25519SignVerify(t *testing.T) {
	kp, err := NewKeyPairEd25519()
	if err != nil {
		t.Fatalf("NewKeyPairEd25519: %v", err)
	}
	msg := []byte("partout: sign(nonce || uuid || ts_be64)")
	sig := SignEd25519(kp.Priv, msg)
	if !VerifyEd25519(kp.Pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	// Tampered message must fail.
	if VerifyEd25519(kp.Pub, append([]byte("x"), msg...), sig) {
		t.Fatal("tampered message accepted")
	}
	// Different key must fail.
	other, _ := NewKeyPairEd25519()
	if VerifyEd25519(other.Pub, msg, sig) {
		t.Fatal("wrong key accepted")
	}
}

func TestX25519SharedSecret(t *testing.T) {
	a, err := NewKeyPairX25519()
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	b, err := NewKeyPairX25519()
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	sab, err := X25519(a.Priv, b.Pub)
	if err != nil {
		t.Fatalf("X25519(A,B): %v", err)
	}
	sba, err := X25519(b.Priv, a.Pub)
	if err != nil {
		t.Fatalf("X25519(B,A): %v", err)
	}
	if !bytes.Equal(sab, sba) {
		t.Fatal("shared secrets differ")
	}
	if len(sab) != 32 {
		t.Fatalf("shared secret length = %d, want 32", len(sab))
	}
}

func TestX25519BadSize(t *testing.T) {
	if _, err := X25519(make([]byte, 16), make([]byte, 32)); err == nil {
		t.Fatal("expected error for bad key size")
	}
}

func TestHKDFDeterministic(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	k1 := DeriveKey(master, []byte("secret:db_password"))
	k2 := DeriveKey(master, []byte("secret:db_password"))
	if !bytes.Equal(k1, k2) {
		t.Fatal("HKDF not deterministic")
	}
	k3 := DeriveKey(master, []byte("secret:other"))
	if bytes.Equal(k1, k3) {
		t.Fatal("different info produced identical key")
	}
	if len(k1) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(k1))
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	key := DeriveKey(bytes.Repeat([]byte{1}, 32), []byte("spool"))
	plain := []byte("super-secret envelope payload")
	ct, err := Seal(key, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := OpenKey(key, ct)
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatal("roundtrip mismatch")
	}
	// Wrong key must fail auth.
	bad := DeriveKey(bytes.Repeat([]byte{2}, 32), []byte("spool"))
	if _, err := OpenKey(bad, ct); err == nil {
		t.Fatal("wrong key opened ciphertext")
	}
}

func TestPEMRoundtrip(t *testing.T) {
	kp, err := NewKeyPairEd25519()
	if err != nil {
		t.Fatalf("NewKeyPairEd25519: %v", err)
	}
	pubPEM, err := PubToPEM(kp.Pub)
	if err != nil {
		t.Fatalf("PubToPEM: %v", err)
	}
	privPEM, err := PrivToPEM(kp.Priv)
	if err != nil {
		t.Fatalf("PrivToPEM: %v", err)
	}
	if len(pubPEM) == 0 || len(privPEM) == 0 {
		t.Fatal("empty PEM output")
	}
}
