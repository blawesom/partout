// Package stream implements the agent-side gRPC stream client: connects to the
// server, performs the Ed25519 handshake, and manages the bidirectional
// envelope loop (commands down, heartbeats/facts/outputs up).
package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

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
}

// Client connects to the server over gRPC, authenticates, and manages the
// bidirectional envelope loop. For M0, the connection is insecure.
type Client struct {
	id   *identity.Identity
	cfg  Config
	log  *log.Logger
	conn *grpc.ClientConn
	mu   sync.Mutex
	s    pb.AgentStream_StreamClient
}

// New creates a client.
func New(id *identity.Identity, cfg Config, lg *log.Logger) *Client {
	if lg == nil {
		lg = log.Default()
	}
	return &Client{id: id, cfg: cfg, log: lg}
}

// connectDial builds the transport credentials (mTLS if TLS material is
// configured, plaintext otherwise).
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
	cert, err := tls.LoadX509KeyPair(c.cfg.CertFile, c.cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
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
