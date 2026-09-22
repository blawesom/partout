// Package agent — one-time enrollment over REST (PRD R2, architecture §3.1):
// the agent presents a single-use token + its fresh public keys to the server,
// which registers an agent row and consumes the token.
//
// In TLS mode the agent additionally generates a local ECDSA P-256 keypair,
// ships a CSR, and receives back the CA + a signed leaf cert for mTLS. The
// private key is returned to the caller (via EnrollResult.TLSKey) for local
// persistence and never leaves the host.
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/identity"
)

// EnrollResult is the server's response to a successful enrollment. TLSKey is
// local-only (never sent over the wire) and holds the agent's private key.
type EnrollResult struct {
	AgentID string `json:"agent_id"`
	UUID    string `json:"uuid"`
	TLS     *TLS   `json:"tls,omitempty"`

	// TLSKey is the agent's local ECDSA private key when TLS was used.
	TLSKey *ecdsa.PrivateKey `json:"-"`
}

// TLS carries the agent's mTLS material returned by a TLS-mode enrollment.
type TLS struct {
	CACert   string `json:"ca_cert"`
	LeafCert string `json:"leaf_cert"`
}

type enrollRequest struct {
	Token        string            `json:"token"`
	UUID         string            `json:"uuid"`
	ED25519Pub   string            `json:"ed25519_pub"`
	X25519Pub    string            `json:"x25519_pub"`
	AgentVersion string            `json:"agent_version"`
	Facts        map[string]string `json:"facts"`
	CSR          string            `json:"csr,omitempty"`
}

// EnrollOptions controls TLS behavior for the enroll call.
type EnrollOptions struct {
	// CAFile, when non-empty, means "enroll over TLS": the agent talks to
	// https://<server>, trusts CAFile as the server's root, and ships a CSR.
	CAFile string
}

// Enroll posts the agent's identity + token to the server.
//
// serverURL is "host:port"; the REST API shares the server's single listener
// (single-port demux). In TLS mode the agent generates an ECDSA P-256 key,
// sends a CSR, and returns the CA + signed leaf in res.TLS (plus the local
// private key in res.TLSKey).
func Enroll(ctx context.Context, serverURL, token string, id *identity.Identity, factsMap map[string]string, opts EnrollOptions) (*EnrollResult, error) {
	if token == "" {
		return nil, fmt.Errorf("agent: enroll: empty token")
	}

	var key *ecdsa.PrivateKey
	var csrPEM []byte
	if opts.CAFile != "" {
		var err error
		csrPEM, key, err = certutil.NewCSR(id.UUID, []string{id.UUID})
		if err != nil {
			return nil, fmt.Errorf("agent: enroll: generate CSR: %w", err)
		}
	}

	req := enrollRequest{
		Token:        token,
		UUID:         id.UUID,
		ED25519Pub:   id.Ed25519PubB64(),
		X25519Pub:    id.X25519PubB64(),
		AgentVersion: facts.Version,
		Facts:        factsMap,
	}
	if len(csrPEM) > 0 {
		req.CSR = string(csrPEM)
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("agent: enroll: marshal: %w", err)
	}

	base := serverURL
	if !strings.Contains(base, "://") {
		scheme := "http"
		if opts.CAFile != "" {
			scheme = "https"
		}
		base = scheme + "://" + base
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/agents/enroll", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("agent: enroll: request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	if opts.CAFile != "" {
		transport, err := newTLSTransport(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("agent: enroll: tls: %w", err)
		}
		client.Transport = transport
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("agent: enroll: do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: enroll: server returned %d", resp.StatusCode)
	}
	var out EnrollResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("agent: enroll: decode: %w", err)
	}
	if out.TLS != nil {
		out.TLSKey = key
	}
	return &out, nil
}

// newTLSTransport builds an http.Transport that trusts caFile as the root CA.
func newTLSTransport(caFile string) (*http.Transport, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid certificate in %s", caFile)
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}, nil
}
