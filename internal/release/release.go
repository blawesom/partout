// Package release implements M8.1 release-artifact signing.
//
// A partout release artifact (the binary) is identified by a Manifest:
// version, arch, kind, and the artifact's sha256. The operator's Ed25519
// release key signs the manifest's canonical form. The agent (and
// `partout ctl update verify`) verifies the signature against the
// operator-provisioned public key before an artifact is ever executed.
//
// The server is a store-and-forward, not a trust anchor: it stores and
// serves artifacts but never decides whether they are genuine. A hash
// alone is insufficient for the same reason — it would make the server's
// word the trust point.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blawesom/partout/internal/cryptoutil"
)

// Kind classifies a release artifact.
type Kind string

const (
	KindAgent  Kind = "agent"  // the per-host agent binary
	KindServer Kind = "server" // the control-plane binary
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k == KindAgent || k == KindServer }

// Manifest identifies one release artifact. SHA256 is the lower-case hex
// digest of the artifact file.
type Manifest struct {
	Version string // e.g. "v0.9.0"
	Arch    string // e.g. "linux-amd64", "linux-arm64"
	Kind    string // "agent" | "server"
	SHA256  string // 64 hex chars
}

// Canonical is the exact byte string the release key signs:
// "version|arch|kind|sha256" (sha256 lower-cased).
func (m Manifest) Canonical() []byte {
	return []byte(strings.Join([]string{
		m.Version, m.Arch, m.Kind, strings.ToLower(m.SHA256),
	}, "|"))
}

// Valid checks the manifest is well-formed.
func (m Manifest) Valid() error {
	if m.Version == "" {
		return fmt.Errorf("release: version required")
	}
	if m.Arch == "" {
		return fmt.Errorf("release: arch required")
	}
	if !Kind(m.Kind).Valid() {
		return fmt.Errorf("release: kind must be %q or %q (got %q)", KindAgent, KindServer, m.Kind)
	}
	if len(m.SHA256) != 64 {
		return fmt.Errorf("release: sha256 must be 64 hex chars (got %d)", len(m.SHA256))
	}
	if _, err := hex.DecodeString(strings.ToLower(m.SHA256)); err != nil {
		return fmt.Errorf("release: sha256 is not hex: %w", err)
	}
	return nil
}

// Sign computes the Ed25519 signature over m.Canonical().
func Sign(priv ed25519.PrivateKey, m Manifest) []byte {
	return cryptoutil.SignEd25519(priv, m.Canonical())
}

// Verify checks sig against m with the release public key.
func Verify(pub ed25519.PublicKey, m Manifest, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return cryptoutil.VerifyEd25519(pub, m.Canonical(), sig)
}

// PubKeyFromB64 decodes a base64 std raw 32-byte Ed25519 public key.
func PubKeyFromB64(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("release: pubkey: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release: pubkey must be %d bytes (got %d)", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// PrivKeyFromB64 decodes a base64 std Ed25519 private key: either the
// 64-byte full key or the 32-byte seed (expanded to the full key).
func PrivKeyFromB64(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("release: privkey: %w", err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("release: privkey must be %d or %d bytes (got %d)",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
}

// PubKeyB64 encodes a public key the way PubKeyFromB64 parses it.
func PubKeyB64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// PrivKeyB64 encodes the 32-byte seed (smallest portable form).
func PrivKeyB64(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Seed())
}

// FileSHA256 returns the lower-case hex sha256 of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("release: open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("release: read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
