package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/blawesom/partout/internal/cryptoutil"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	kp, err := cryptoutil.NewKeyPairEd25519()
	if err != nil {
		t.Fatalf("NewKeyPairEd25519: %v", err)
	}
	return kp.Pub, kp.Priv
}

// goodSHA is a valid 64-char hex digest (only its form is exercised here).
const goodSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	m := Manifest{Version: "v0.9.0", Arch: "linux-amd64", Kind: "agent", SHA256: goodSHA}
	sig := Sign(priv, m)
	if !Verify(pub, m, sig) {
		t.Fatal("valid signature rejected")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	pub, priv := testKey(t)
	m := Manifest{Version: "v0.9.0", Arch: "linux-amd64", Kind: "agent", SHA256: goodSHA}
	sig := Sign(priv, m)

	cases := map[string]Manifest{
		"version": {Version: "v0.9.1", Arch: m.Arch, Kind: m.Kind, SHA256: m.SHA256},
		"arch":    {Version: m.Version, Arch: "linux-arm64", Kind: m.Kind, SHA256: m.SHA256},
		"kind":    {Version: m.Version, Arch: m.Arch, Kind: "server", SHA256: m.SHA256},
		"sha":     {Version: m.Version, Arch: m.Arch, Kind: m.Kind, SHA256: "0" + goodSHA[1:]},
	}
	for name, tampered := range cases {
		if Verify(pub, tampered, sig) {
			t.Errorf("%s: tampered manifest accepted", name)
		}
	}
	// Case-only sha changes normalize (Canonical lowercases) — by design.
	if !Verify(pub, Manifest{Version: m.Version, Arch: m.Arch, Kind: m.Kind, SHA256: "E" + goodSHA[1:]}, sig) {
		t.Error("uppercase-sha manifest should verify (canonical form is lower-case)")
	}
	if Verify(pub, m, sig[:len(sig)-1]) {
		t.Error("truncated signature accepted")
	}
	if Verify(pub, m, []byte("nope")) {
		t.Error("garbage signature accepted")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv := testKey(t)
	otherPub, _ := testKey(t)
	m := Manifest{Version: "v1", Arch: "linux-amd64", Kind: "agent", SHA256: goodSHA}
	if Verify(otherPub, m, Sign(priv, m)) {
		t.Fatal("signature accepted under a different public key")
	}
}

func TestKeyEncodingRoundTrip(t *testing.T) {
	kp, err := cryptoutil.NewKeyPairEd25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub, err := PubKeyFromB64(PubKeyB64(kp.Pub))
	if err != nil {
		t.Fatalf("pub round-trip: %v", err)
	}
	if string(pub) != string(kp.Pub) {
		t.Fatal("pub round-trip mismatch")
	}
	priv, err := PrivKeyFromB64(PrivKeyB64(kp.Priv))
	if err != nil {
		t.Fatalf("priv round-trip (seed): %v", err)
	}
	fullPriv, err := PrivKeyFromB64(base64.StdEncoding.EncodeToString(kp.Priv))
	if err != nil {
		t.Fatalf("priv round-trip (full key): %v", err)
	}
	m := Manifest{Version: "v1", Arch: "linux-amd64", Kind: "agent", SHA256: goodSHA}
	if !Verify(pub, m, Sign(priv, m)) || !Verify(pub, m, Sign(fullPriv, m)) {
		t.Fatal("decoded keys do not sign/verify consistently")
	}
}

func TestKeyEncodingRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "!!not-base64!!", "YWFh"} {
		if _, err := PubKeyFromB64(s); err == nil {
			t.Errorf("PubKeyFromB64(%q): want error", s)
		}
	}
	for _, s := range []string{"", "YWFh", "YWFhYWFh"} {
		if _, err := PrivKeyFromB64(s); err == nil {
			t.Errorf("PrivKeyFromB64(%q): want error", s)
		}
	}
}

func TestManifestValid(t *testing.T) {
	base := Manifest{Version: "v0.9.0", Arch: "linux-amd64", Kind: "agent", SHA256: goodSHA}
	if err := base.Valid(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	cases := map[string]Manifest{
		"no version":  {Arch: base.Arch, Kind: base.Kind, SHA256: base.SHA256},
		"no arch":     {Version: base.Version, Kind: base.Kind, SHA256: base.SHA256},
		"bad kind":    {Version: base.Version, Arch: base.Arch, Kind: "daemon", SHA256: base.SHA256},
		"short sha":   {Version: base.Version, Arch: base.Arch, Kind: base.Kind, SHA256: "abc"},
		"non-hex sha": {Version: base.Version, Arch: base.Arch, Kind: base.Kind, SHA256: "z" + goodSHA[1:]},
	}
	for name, m := range cases {
		if err := m.Valid(); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
	if err := (Manifest{Version: "v1", Arch: "linux-amd64", Kind: "server", SHA256: goodSHA}).Valid(); err != nil {
		t.Errorf("server kind rejected: %v", err)
	}
}

func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "artifact")
	data := []byte("partout release artifact")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := FileSHA256(p)
	if err != nil {
		t.Fatalf("FileSHA256: %v", err)
	}
	want := sha256.Sum256(data)
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("digest = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	again, _ := FileSHA256(p)
	if got != again {
		t.Fatal("FileSHA256 not deterministic")
	}
	if _, err := FileSHA256(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file: want error")
	}
}
