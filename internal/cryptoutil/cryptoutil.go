// Package cryptoutil provides low-level crypto helpers shared by the server
// and the agent: Ed25519 (identity), X25519 (transport key exchange), HKDF
// (secret derivation), and AES-256-GCM AEAD (spool/envelope encryption).
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var (
	// ErrInvalidKeySize is returned when a key is the wrong length.
	ErrInvalidKeySize = errors.New("cryptoutil: invalid key size")
)

// ---- Ed25519 identity -----------------------------------------------------

// KeyPairEd25519 holds a generated Ed25519 key pair.
type KeyPairEd25519 struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// NewKeyPairEd25519 generates a fresh Ed25519 key pair.
func NewKeyPairEd25519() (*KeyPairEd25519, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPairEd25519{Pub: pub, Priv: priv}, nil
}

// SignEd25519 returns an Ed25519 signature over msg using priv.
func SignEd25519(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// VerifyEd25519 returns true if sig is a valid Ed25519 signature over msg
// using the given public key.
func VerifyEd25519(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

// ---- X25519 key exchange --------------------------------------------------

// KeyPairX25519 holds a generated X25519 key pair (32-byte keys).
type KeyPairX25519 struct {
	Priv []byte
	Pub  []byte
}

// NewKeyPairX25519 generates a fresh X25519 key pair.
func NewKeyPairX25519() (*KeyPairX25519, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var privArr [32]byte
	copy(privArr[:], priv)
	var pubArr [32]byte
	curve25519.ScalarBaseMult(&pubArr, &privArr)

	return &KeyPairX25519{Pub: pubArr[:], Priv: priv}, nil
}

// X25519 computes the shared secret from the local private key and remote
// public key. Both must be 32 bytes.
func X25519(priv, pub []byte) ([]byte, error) {
	if len(priv) != 32 || len(pub) != 32 {
		return nil, ErrInvalidKeySize
	}
	var privArr, pubArr, shared [32]byte
	copy(privArr[:], priv)
	copy(pubArr[:], pub)
	curve25519.ScalarMult(&shared, &privArr, &pubArr)
	return shared[:], nil
}

// ---- HKDF -----------------------------------------------------------------

// DeriveKey derives a 32-byte sub-key from master using info as context, via
// HKDF-SHA256 (IKM=master, salt=nil, info=info).
func DeriveKey(master, info []byte) []byte {
	h := hkdf.New(sha256.New, master, info, nil)
	buf := make([]byte, 32)
	if _, err := h.Read(buf); err != nil {
		panic("cryptoutil: hkdf read should not fail with sha256: " + err.Error())
	}
	return buf
}

// ---- AEAD (AES-256-GCM) ---------------------------------------------------

// AEAD constructs an AES-256-GCM cipher from a 32-byte key.
func AEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext with key, using a fresh random nonce. The result is
// nonce || ciphertext, suitable for storage/transmission and OpenKey later.
func Seal(key, plaintext []byte) ([]byte, error) {
	a, err := AEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plaintext, nil), nil
}

// OpenKey decrypts data produced by Seal (nonce || ciphertext) using key.
func OpenKey(key, data []byte) ([]byte, error) {
	a, err := AEAD(key)
	if err != nil {
		return nil, err
	}
	ns := a.NonceSize()
	if len(data) < ns {
		return nil, errors.New("cryptoutil: ciphertext too short")
	}
	return a.Open(nil, data[:ns], data[ns:], nil)
}

// ---- Encoding helpers (PEM) -----------------------------------------------

// PubToPEM encodes an Ed25519 public key as PEM (SubjectPublicKeyInfo).
func PubToPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// PrivToPEM encodes an Ed25519 private key as PEM (PKCS#8).
func PrivToPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
