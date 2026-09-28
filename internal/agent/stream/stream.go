// Package stream implements the agent-side gRPC stream client: connects to the
// server, performs the Ed25519 handshake, and manages the bidirectional
// envelope loop (commands down, heartbeats/facts/outputs up).
package stream

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
)

// Config holds the stream parameters.
type Config struct {
	ServerURL string
	// TLS material (all three required together; empty = plaintext h2c).
	CAFile   string
	CertFile string // agent leaf cert (PEM)
	KeyFile  string // agent private key (PEM)
	// TLSDir, when non-empty, is where RotateLeaf persists a rotated leaf
	// (agent.crt) so it survives an agent restart. Empty = rotation not
	// persisted (in-memory only).
	TLSDir string
}

// Client connects to the server over gRPC, authenticates, and manages the
// bidirectional envelope loop.
type Client struct {
	id   *identity.Identity
	cfg  Config
	log  *log.Logger
	conn *grpc.ClientConn
	mu   sync.Mutex
	s    pb.AgentStream_StreamClient

	// certMu guards cert (the in-memory mTLS client certificate). It is
	// swapped in place by RotateLeaf so a rotated leaf is used on the next
	// connection without a config reload.
	certMu sync.Mutex
	cert   *tls.Certificate
	keyPEM []byte // agent private key PEM (for re-building the cert on rotation)
	caPEM  []byte // root CA PEM (for verifying rotated leaves)
}

// New creates a client. When TLS is configured it loads the mTLS client
// certificate into memory (so RotateLeaf can hot-swap it).
func New(id *identity.Identity, cfg Config, lg *log.Logger) *Client {
	if lg == nil {
		lg = log.Default()
	}
	c := &Client{id: id, cfg: cfg, log: lg}
	c.loadCert()
	return c
}

// loadCert reads the mTLS client cert + key + CA into memory (TLS mode only).
func (c *Client) loadCert() {
	if c.cfg.CAFile == "" {
		return
	}
	caPEM, err := os.ReadFile(c.cfg.CAFile)
	if err != nil {
		c.log.Printf("stream: load CA %s: %v", c.cfg.CAFile, err)
		return
	}
	cert, err := tls.LoadX509KeyPair(c.cfg.CertFile, c.cfg.KeyFile)
	if err != nil {
		c.log.Printf("stream: load client cert: %v", err)
		return
	}
	keyPEM, kerr := os.ReadFile(c.cfg.KeyFile)
	if kerr != nil {
		keyPEM = nil
	}
	c.certMu.Lock()
	c.caPEM = caPEM
	c.keyPEM = keyPEM
	c.cert = &cert
	c.certMu.Unlock()
}

// currentCert returns a copy of the live client certificate (nil = plaintext).
func (c *Client) currentCert() *tls.Certificate {
	c.certMu.Lock()
	defer c.certMu.Unlock()
	if c.cert == nil {
		return nil
	}
	cp := *c.cert
	return &cp
}

// LeafNotAfter returns the expiry of the current client leaf (ok=false when
// there is no TLS cert loaded).
func (c *Client) LeafNotAfter() (time.Time, bool) {
	c.certMu.Lock()
	defer c.certMu.Unlock()
	if c.cert == nil || len(c.cert.Certificate) == 0 {
		return time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(c.cert.Certificate[0])
	if err != nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}

// RotateLeaf verifies a newly signed leaf (PEM) against the root CA and this
// agent's identity, then hot-swaps it into the live client certificate and
// persists it to TLSDir/agent.crt (when configured). The private key is
// unchanged — the server re-signed the same enrolled key.
func (c *Client) RotateLeaf(leafPEM []byte, caPEM []byte) error {
	if caPEM == nil {
		caPEM = c.caPEM
	}
	if err := certutil.VerifyAgentLeaf(leafPEM, caPEM, c.id.UUID); err != nil {
		return err
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return errors.New("stream: rotate: no PEM block in leaf")
	}
	leafCert, perr := x509.ParseCertificate(block.Bytes)
	if perr != nil {
		return fmt.Errorf("stream: rotate: parse leaf: %w", perr)
	}
	c.certMu.Lock()
	// Refuse a leaf that does not match the private key we hold: installing it
	// would break the handshake and — because it is persisted — survive a
	// restart, bricking the agent until the file is removed by hand.
	var haveKey crypto.Signer
	if c.cert != nil {
		if s, ok := c.cert.PrivateKey.(crypto.Signer); ok {
			haveKey = s
		}
	}
	if haveKey == nil {
		key, kerr := parsePEMKey(c.keyPEM)
		if kerr != nil {
			c.certMu.Unlock()
			return fmt.Errorf("stream: rotate: no key to validate leaf against: %w", kerr)
		}
		s, ok := key.(crypto.Signer)
		if !ok {
			c.certMu.Unlock()
			return errors.New("stream: rotate: agent key is not a signer")
		}
		haveKey = s
	}
	leafPub, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		c.certMu.Unlock()
		return errors.New("stream: rotate: leaf public key is not ECDSA")
	}
	if !leafPub.Equal(haveKey.Public()) {
		c.certMu.Unlock()
		return errors.New("stream: rotate: leaf public key does not match the agent key")
	}
	if c.cert == nil {
		// No prior cert (e.g. loaded after a transient failure): rebuild from
		// the persisted key + the new leaf (haveKey is the parsed key).
		c.cert = &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: haveKey}
	} else {
		c.cert.Certificate = [][]byte{block.Bytes}
	}
	newCert := *c.cert
	c.certMu.Unlock()

	if c.cfg.TLSDir != "" {
		if err := os.WriteFile(filepath.Join(c.cfg.TLSDir, "agent.crt"), leafPEM, 0o644); err != nil {
			c.log.Printf("stream: persist rotated leaf: %v", err)
		}
	}
	c.log.Printf("stream: mTLS leaf rotated in place")
	_ = newCert
	return nil
}

func parsePEMKey(pemBytes []byte) (any, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("empty key PEM")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block in key")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// connectDial builds the transport credentials (mTLS if TLS material is
// configured, plaintext otherwise). The client certificate is supplied via
// GetClientCertificate so a rotated leaf (RotateLeaf) is used on the next
// connection without rebuilding the credentials.
func (c *Client) transportCredentials() (credentials.TransportCredentials, error) {
	if c.cfg.CAFile == "" {
		return insecure.NewCredentials(), nil
	}
	caPEM, err := os.ReadFile(c.cfg.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("stream: no certificate found in CA file " + c.cfg.CAFile)
	}
	if c.currentCert() == nil {
		return nil, errors.New("stream: TLS configured but no client certificate loaded")
	}
	return credentials.NewTLS(&tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return c.currentCert(), nil
		},
	}), nil
}

// Connect opens the gRPC stream and performs the handshake. Returns nil on
// success; the caller may retry with backoff.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	creds, err := c.transportCredentials()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(c.cfg.ServerURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	streamClient, err := pb.NewAgentStreamClient(conn).Stream(ctx)
	if err != nil {
		conn.Close()
		return err
	}

	// Receive challenge.
	env, err := streamClient.Recv()
	if err != nil {
		conn.Close()
		return err
	}
	ch := env.GetChallenge()
	if ch == nil {
		conn.Close()
		return errors.New("stream: expected CHALLENGE, got " + env.Kind.String())
	}

	// Sign and reply.
	ts := time.Now().Unix()
	sig := c.id.Sign(hsauth.BuildMsg(ch.Nonce, c.id.UUID, ts))
	if err := streamClient.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: c.id.UUID, Ts: ts, Sig: sig,
		}},
	}); err != nil {
		conn.Close()
		return err
	}

	c.conn = conn
	c.s = streamClient
	c.log.Printf("stream: agent %s connected", c.id.UUID)
	return nil
}

// Send sends an up envelope. Returns an error if the client is not connected.
func (c *Client) Send(ctx context.Context, env *pb.Envelope) error {
	c.mu.Lock()
	s := c.s
	c.mu.Unlock()
	if s == nil {
		return errors.New("stream: not connected")
	}
	return s.Send(env)
}

// Recv blocks until a down envelope is available.
func (c *Client) Recv(ctx context.Context) (*pb.Envelope, error) {
	c.mu.Lock()
	s := c.s
	c.mu.Unlock()
	if s == nil {
		return nil, errors.New("stream: not connected")
	}
	return s.Recv()
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.s = nil
	return nil
}
