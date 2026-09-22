// Package certutil implements the v1 TLS bootstrap (see README "TLS /
// transport security"):
//
//   - The server generates a local root CA on first run (persisted in its
//     data dir) and serves its own leaf cert for the control-plane port.
//   - At enrollment, the agent presents a CSR for a locally-generated key;
//     the server signs it with the root CA and returns the leaf cert. The
//     agent private key never leaves the host.
//   - Result: mutual TLS with one trust anchor, zero per-host cert
//     management. Ed25519 stream auth still gates every agent.
package certutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	CAValidity   = 10 * 365 * 24 * time.Hour
	LeafValidity = 2 * 365 * 24 * time.Hour
)

// CA is a root certificate authority (cert + signing key).
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	dir  string
}

// LoadOrCreateCA loads <dir>/ca.crt + ca.key, or generates a fresh root CA
// and persists it (key 0600, cert 0644) if absent.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		cert, err := parseCertPEM(certPEM)
		if err != nil {
			return nil, fmt.Errorf("certutil: load ca.crt: %w", err)
		}
		key, err := parseECDSAKeyPEM(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("certutil: load ca.key: %w", err)
		}
		return &CA{Cert: cert, Key: key, dir: dir}, nil
	}

	// Generate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certutil: generate CA key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "Partout Root CA", Organization: []string{"Partout"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("certutil: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pemKey(key), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, pemCert(cert), 0o644); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, dir: dir}, nil
}

// CertPEM returns the CA certificate in PEM form.
func (ca *CA) CertPEM() string {
	return string(pemCert(ca.Cert))
}

// SignAgentCert signs an agent CSR (PEM) for mTLS client authentication.
// The signed leaf has CN=<agentID> and SAN = the CSR's requested names
// (the agent puts its UUID there).
func (ca *CA) SignAgentCert(csrPEM []byte, agentID string) (string, error) {
	csr, err := parseCSRPEM(csrPEM)
	if err != nil {
		return "", fmt.Errorf("certutil: parse CSR: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"Partout"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(LeafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return "", fmt.Errorf("certutil: sign agent cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return string(pemCert(leaf)), nil
}

// LoadOrCreateServerCert loads or generates the server's own leaf cert
// (signed by the CA) covering the given names (hostnames and/or IPs).
func LoadOrCreateServerCert(dir string, ca *CA, names []string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("certutil: load server cert: %w", err)
		}
		return cert, nil
	}

	dnsNames, ips := splitNames(names)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: "Partout Server", Organization: []string{"Partout"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(LeafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, pemKey(key), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, pemCert(leaf), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// ---- CSR helpers (agent side) ---------------------------------------------

// NewCSR generates an ECDSA P-256 key and a PEM CSR for it. The private key
// is returned so the caller can persist it; it never crosses the wire.
func NewCSR(commonName string, extraDNSNames []string) (csrPEM []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName, Organization: []string{"Partout"}},
		DNSNames: extraDNSNames,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key, nil
}

// PEMKey encodes an ECDSA private key as PEM (PKCS#8).
func PEMKey(key *ecdsa.PrivateKey) []byte { return pemKey(key) }

// VerifyServerCert verifies that a server leaf (PEM) chains to the CA (PEM)
// and is currently valid. Used by the enroll client to fail fast on a bad CA.
func VerifyServerCert(serverCertPEM, caPEM []byte) error {
	serverCert, err := parseCertPEM(serverCertPEM)
	if err != nil {
		return err
	}
	caCert, err := parseCertPEM(caPEM)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = serverCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// ---- PEM / parsing helpers -------------------------------------------------

func newSerial() *big.Int {
	b := make([]byte, 16)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}

func splitNames(names []string) (dns []string, ips []net.IP) {
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	return
}

func pemKey(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pemCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("certutil: no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECDSAKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("certutil: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("certutil: key is not ECDSA")
	}
	return ecKey, nil
}

func parseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("certutil: no PEM block found in CSR")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// ServerIdentity is the server's Ed25519 keypair used to sign policy
// Decisions (architecture §5.3).  The public key is distributed to agents
// via the policy bundle; the private key never leaves the server.
type ServerIdentity struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
	dir  string
}

// LoadOrCreateServerIdentity loads <dir>/server_identity.key (0600) or
// generates a fresh Ed25519 key and persists it if absent.
func LoadOrCreateServerIdentity(dir string) (*ServerIdentity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("certutil: mkdir %s: %w", dir, err)
	}
	keyPath := filepath.Join(dir, "server_identity.key")

	if data, err := os.ReadFile(keyPath); err == nil {
		priv, err := parseEd25519KeyPEM(data)
		if err != nil {
			return nil, fmt.Errorf("certutil: parse server identity: %w", err)
		}
		return &ServerIdentity{Pub: priv.Public().(ed25519.PublicKey), Priv: priv, dir: dir}, nil
	}

	priv, err := generateEd25519()
	if err != nil {
		return nil, fmt.Errorf("certutil: generate server identity: %w", err)
	}
	if err := os.WriteFile(keyPath, pemEd25519Key(priv), 0o600); err != nil {
		return nil, fmt.Errorf("certutil: write server identity: %w", err)
	}
	return &ServerIdentity{Pub: priv.Public().(ed25519.PublicKey), Priv: priv, dir: dir}, nil
}

// PubB64 returns the base64-encoded public key (for the policy bundle).
func (s *ServerIdentity) PubB64() string {
	return base64.StdEncoding.EncodeToString(s.Pub)
}

func generateEd25519() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func pemEd25519Key(key ed25519.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func parseEd25519KeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("certutil: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("certutil: key is not Ed25519")
	}
	return ed, nil
}
