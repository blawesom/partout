package stream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/store"
)

// TestRotateAgentCert verifies the server re-signs an agent's leaf from its
// enrolled public key, delivers a TlsCert down to the live session, and records
// the new expiry in the store.
func TestRotateAgentCert(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New("sqlite:" + dir + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	uuid := "ag_rotate_cert_server"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(der)

	agentID := "ag_test1"
	if err := st.UpsertAgent(store.Agent{ID: agentID, UUID: uuid, ED25519Pub: "e", X25519Pub: "x", State: "connected"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAgentTLS(agentID, pubB64, time.Now().Add(24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	ca, err := certutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(st, nil, nil)
	h.SetCA(ca)

	// Fake session that captures the down envelope.
	var got *pb.Envelope
	sess := &Session{AgentID: agentID, send: func(env *pb.Envelope) error { got = env; return nil }}
	h.mu.Lock()
	h.sessions[agentID] = sess
	h.mu.Unlock()

	serial, err := h.RotateAgentCert(agentID)
	if err != nil {
		t.Fatalf("RotateAgentCert: %v", err)
	}
	if serial == "" {
		t.Fatal("empty serial")
	}
	if got == nil || got.Kind != pb.EnvelopeKind_TLS_CERT {
		t.Fatalf("expected TLS_CERT down, got %v", got)
	}
	tc := got.GetTlsCert()
	if tc == nil || tc.LeafCert == "" {
		t.Fatal("empty TlsCert payload")
	}
	// The delivered leaf must verify against the CA for this agent.
	if err := certutil.VerifyAgentLeaf([]byte(tc.LeafCert), []byte(ca.CertPEM()), agentID); err != nil {
		t.Errorf("delivered leaf does not verify: %v", err)
	}
	// Store updated to a later expiry.
	a, _ := st.Agent(agentID)
	if a.TlsNotAfter <= time.Now().Add(24*time.Hour).Unix() {
		t.Errorf("store tls_not_after not advanced: %d", a.TlsNotAfter)
	}
	if a.TlsPub != pubB64 {
		t.Error("rotation must not change the enrolled public key")
	}
}

// TestRotateAgentCert_NotConnected verifies rotating an offline agent errors
// (the leaf is not delivered) rather than panicking.
func TestRotateAgentCert_NotConnected(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.New("sqlite:" + dir + "/t.db")
	defer st.Close()
	ca, _ := certutil.LoadOrCreateCA(t.TempDir())
	h := NewHandler(st, nil, nil)
	h.SetCA(ca)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(der)
	agentID := "ag_offline"
	_ = st.UpsertAgent(store.Agent{ID: agentID, UUID: "uuid-offline", ED25519Pub: "e", X25519Pub: "x"})
	_ = st.SetAgentTLS(agentID, pubB64, time.Now().Unix())

	if _, err := h.RotateAgentCert(agentID); err == nil {
		t.Error("expected error rotating a not-connected agent")
	}
}

// TestRotateAgentCert_Plaintext verifies rotation is disabled (clear error)
// when no CA is installed.
func TestRotateAgentCert_Plaintext(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.New("sqlite:" + dir + "/t.db")
	defer st.Close()
	h := NewHandler(st, nil, nil) // no CA
	if _, err := h.RotateAgentCert("ag_x"); err == nil {
		t.Error("expected error rotating in plaintext mode")
	}
}
