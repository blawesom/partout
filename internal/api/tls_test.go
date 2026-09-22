package api_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/identity"
)

// createEnrollToken creates a one-time enrollment token and returns the plain
// value. Uses the httptest server from startAPITest via the global scope.
func createEnrollToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	resp, err := http.Post(srv.URL+"/api/v1/agents/enrollment-tokens", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	defer resp.Body.Close()
	var data struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if data.Token == "" {
		t.Fatal("empty token")
	}
	return data.Token
}

func TestTLSEnrollIssuesSignedLeaf(t *testing.T) {
	apiH, _, srv := startAPITest(t)

	ca, err := certutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	apiH.SetTLS(ca)

	token := createEnrollToken(t, srv)

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	csrPEM, _, err := certutil.NewCSR(id.UUID, []string{id.UUID})
	if err != nil {
		t.Fatalf("NewCSR: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"token":         token,
		"uuid":          id.UUID,
		"ed25519_pub":   id.Ed25519PubB64(),
		"x25519_pub":    id.X25519PubB64(),
		"agent_version": "1.0",
		"csr":           string(csrPEM),
	})
	resp, err := http.Post(srv.URL+"/api/v1/agents/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d, body = %s", resp.StatusCode, rb)
	}

	var out struct {
		AgentID string `json:"agent_id"`
		TLS     *struct {
			CACert   string `json:"ca_cert"`
			LeafCert string `json:"leaf_cert"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		t.Fatalf("parse enroll: %v", err)
	}
	if out.AgentID == "" || out.TLS == nil {
		t.Fatalf("enroll response incomplete: %s", rb)
	}

	// Leaf must chain to the CA and have the agent ID as CN.
	leaf, err := parsePEMCert([]byte(out.TLS.LeafCert))
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(out.TLS.CACert))
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify as clientAuth against CA: %v", err)
	}
	if leaf.Subject.CommonName != out.AgentID {
		t.Fatalf("leaf CN = %q, want agent id %q", leaf.Subject.CommonName, out.AgentID)
	}
}

func TestTLSEnrollRequiresCSR(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	apiH.SetTLS(newTestCA(t))
	token := createEnrollToken(t, srv)

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"token":         token,
		"uuid":          id.UUID,
		"ed25519_pub":   id.Ed25519PubB64(),
		"x25519_pub":    id.X25519PubB64(),
		"agent_version": "1.0",
	})
	resp, err := http.Post(srv.URL+"/api/v1/agents/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enroll without CSR status = %d, want 400", resp.StatusCode)
	}
}

func TestPlaintextEnrollUnchanged(t *testing.T) {
	// No CA set → enrollment must NOT return TLS material.
	_, _, srv := startAPITest(t)
	token := createEnrollToken(t, srv)

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"token":         token,
		"uuid":          id.UUID,
		"ed25519_pub":   id.Ed25519PubB64(),
		"x25519_pub":    id.X25519PubB64(),
		"agent_version": "1.0",
	})
	resp, err := http.Post(srv.URL+"/api/v1/agents/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, rb)
	}
	var out struct {
		AgentID string    `json:"agent_id"`
		TLS     *struct{} `json:"tls"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.TLS != nil {
		t.Fatal("plaintext enrollment must not include TLS material")
	}
}

func TestTLSCAEndpoint(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	apiH.SetTLS(newTestCA(t))

	resp, err := http.Get(srv.URL + "/api/v1/tls/ca")
	if err != nil {
		t.Fatalf("GET /tls/ca: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var res struct {
		Cert string `json:"cert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cert, err := parsePEMCert([]byte(res.Cert))
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("CA endpoint returned a non-CA certificate")
	}
}

func TestTLSCAEndpointDisabled(t *testing.T) {
	// No CA set → 503.
	_, _, srv := startAPITest(t)
	resp, err := http.Get(srv.URL + "/api/v1/tls/ca")
	if err != nil {
		t.Fatalf("GET /tls/ca: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// newTestCA creates a throwaway CA for tests.
func newTestCA(t *testing.T) *certutil.CA {
	ca, err := certutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	return ca
}

func parsePEMCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

var _ = base64.StdEncoding
