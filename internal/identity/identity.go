// Package identity loads or generates the agent identity: uuid, Ed25519 (for
// stream auth), X25519 (for transport encryption). Persisted as
// identity.json (mode 0600) on first start (PRD R3).
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blawesom/partout/internal/cryptoutil"
)

// Raw is the on-disk format (JSON, raw keys).
type Raw struct {
	UUID        string `json:"uuid"`
	Ed25519Pub  []byte `json:"ed25519_pub"`
	Ed25519Priv []byte `json:"ed25519_priv"`
	X25519Pub   []byte `json:"x25519_pub"`
	X25519Priv  []byte `json:"x25519_priv"`
}

// Identity holds the loaded or generated key material.
type Identity struct {
	UUID        string
	Ed25519Priv ed25519.PrivateKey
	Ed25519Pub  ed25519.PublicKey
	X25519Priv  []byte
	X25519Pub   []byte
}

// Sign computes an Ed25519 signature over msg.
func (i *Identity) Sign(msg []byte) []byte {
	return cryptoutil.SignEd25519(i.Ed25519Priv, msg)
}

// Ed25519PubB64 returns the base64-encoded Ed25519 public key.
func (i *Identity) Ed25519PubB64() string {
	return base64.StdEncoding.EncodeToString(i.Ed25519Pub)
}

// X25519PubB64 returns the base64-encoded X25519 public key.
func (i *Identity) X25519PubB64() string {
	return base64.StdEncoding.EncodeToString(i.X25519Pub)
}

// LoadOrGenerate reads identity.json from dir, or generates and writes one.
func LoadOrGenerate(dir string) (*Identity, error) {
	path := filepath.Join(dir, "identity.json")
	if data, err := os.ReadFile(path); err == nil {
		return loadFrom(data)
	}
	return generate(path)
}

func generate(path string) (*Identity, error) {
	kp1, err := cryptoutil.NewKeyPairEd25519()
	if err != nil {
		return nil, err
	}
	kp2, err := cryptoutil.NewKeyPairX25519()
	if err != nil {
		return nil, err
	}
	id := &Identity{
		UUID:        uuidV4(),
		Ed25519Priv: kp1.Priv,
		Ed25519Pub:  kp1.Pub,
		X25519Priv:  kp2.Priv,
		X25519Pub:   kp2.Pub,
	}
	raw := Raw{
		UUID:        id.UUID,
		Ed25519Pub:  id.Ed25519Pub,
		Ed25519Priv: id.Ed25519Priv,
		X25519Pub:   id.X25519Pub,
		X25519Priv:  id.X25519Priv,
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return id, nil
}

func loadFrom(data []byte) (*Identity, error) {
	var raw Raw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("identity: parse: %w", err)
	}
	if len(raw.Ed25519Priv) != ed25519.PrivateKeySize || len(raw.X25519Priv) != 32 {
		return nil, fmt.Errorf("identity: malformed key sizes")
	}
	return &Identity{
		UUID:        raw.UUID,
		Ed25519Priv: ed25519.PrivateKey(raw.Ed25519Priv),
		Ed25519Pub:  ed25519.PublicKey(raw.Ed25519Pub),
		X25519Priv:  raw.X25519Priv,
		X25519Pub:   raw.X25519Pub,
	}, nil
}

// uuidV4 generates a simple v4 UUID using crypto/rand (hex, 32 chars).
func uuidV4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("identity: rand: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return hex.EncodeToString(b[:])
}
