package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/cryptoutil"
	pb "github.com/blawesom/partout/internal/proto"
)

// sealForAgent mimics the server's distribution: ephemeral X25519 ECDH with
// the agent's public key, HKDF, AES-GCM seal.
func sealForAgent(t *testing.T, agentPub []byte, ref string, version int64, value string) *pb.SecretMaterialize {
	t.Helper()
	eph, err := cryptoutil.NewKeyPairX25519()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := cryptoutil.X25519(eph.Priv, agentPub)
	if err != nil {
		t.Fatal(err)
	}
	key := cryptoutil.DeriveKey(shared, []byte(InfoE2E+ref+":"+itoa(version)))
	sealed, err := cryptoutil.Seal(key, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return &pb.SecretMaterialize{
		Ref: ref, Version: version, EphPub: eph.Pub, Sealed: sealed,
	}
}

func agentKeys(t *testing.T) (priv, pub []byte) {
	t.Helper()
	kp, err := cryptoutil.NewKeyPairX25519()
	if err != nil {
		t.Fatal(err)
	}
	return kp.Priv, kp.Pub
}

func TestCacheHandleAndGet(t *testing.T) {
	priv, pub := agentKeys(t)
	c, err := New(t.TempDir(), priv)
	if err != nil {
		t.Fatal(err)
	}

	sm := sealForAgent(t, pub, "db-pass", 1, "s3cr3t")
	if _, err := c.Handle(sm); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if v, ok := c.Get("db-pass"); !ok || v != "s3cr3t" {
		t.Fatalf("Get = %q ok=%v", v, ok)
	}
	if v, ok := c.Get("unknown"); ok {
		t.Fatalf("unknown ref returned %q", v)
	}
}

func TestCacheBadEphPub(t *testing.T) {
	priv, _ := agentKeys(t)
	c, err := New(t.TempDir(), priv)
	if err != nil {
		t.Fatal(err)
	}
	sm := &pb.SecretMaterialize{Ref: "x", Version: 1, EphPub: []byte("short"), Sealed: []byte("x")}
	if _, err := c.Handle(sm); err == nil {
		t.Fatal("bad eph_pub: want error")
	}
	// Wrong agent key → decrypt fails, value not stored.
	otherPriv, otherPub := agentKeys(t)
	_ = otherPriv
	sm2 := sealForAgent(t, otherPub, "x", 1, "v")
	if _, err := c.Handle(sm2); err == nil {
		t.Fatal("cross-agent seal: want decrypt error")
	}
	if _, ok := c.Get("x"); ok {
		t.Fatal("value stored despite failed decrypt")
	}
}

func TestCacheDiskPersistenceNoPlaintext(t *testing.T) {
	priv, pub := agentKeys(t)
	dir := t.TempDir()
	c, err := New(dir, priv)
	if err != nil {
		t.Fatal(err)
	}

	const value = "the-plaintext-secret"
	sm := sealForAgent(t, pub, "tok", 1, value)
	sm.CacheTtlS = 3600
	if _, err := c.Handle(sm); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	// The on-disk file must exist and must NOT contain the plaintext.
	b, err := os.ReadFile(filepath.Join(dir, "secret_cache.json"))
	if err != nil {
		t.Fatalf("cache file: %v", err)
	}
	if strings.Contains(string(b), value) {
		t.Fatal("plaintext written to disk cache — security violation")
	}

	// A fresh cache (agent restart) reads the sealed form and opens it.
	reborn, err := New(dir, priv)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := reborn.Get("tok"); !ok || v != value {
		t.Fatalf("reopen: %q ok=%v", v, ok)
	}
}

func TestCacheExpiry(t *testing.T) {
	priv, pub := agentKeys(t)
	c, err := New(t.TempDir(), priv)
	if err != nil {
		t.Fatal(err)
	}
	// now = 1000s; entry expires at 2000s.
	c.now = func() time.Time { return time.Unix(1000, 0) }
	sm := sealForAgent(t, pub, "exp", 1, "v")
	sm.CacheTtlS = 1000
	if _, err := c.Handle(sm); err != nil {
		t.Fatal(err)
	}
	if v, ok := c.Get("exp"); !ok || v != "v" {
		t.Fatalf("within window: %q ok=%v", v, ok)
	}
	// Advance past expiry.
	c.now = func() time.Time { return time.Unix(2001, 0) }
	if _, ok := c.Get("exp"); ok {
		t.Fatal("expired entry still served")
	}
	c.Prune()
	if v, ok := c.Get("exp"); ok {
		t.Fatalf("expired entry survived prune: %q", v)
	}
}

func TestCacheDrop(t *testing.T) {
	priv, pub := agentKeys(t)
	c, err := New(t.TempDir(), priv)
	if err != nil {
		t.Fatal(err)
	}
	sm := sealForAgent(t, pub, "d", 1, "v")
	sm.CacheTtlS = 3600
	if _, err := c.Handle(sm); err != nil {
		t.Fatal(err)
	}
	c.Drop("d")
	if _, ok := c.Get("d"); ok {
		t.Fatal("dropped secret still served")
	}
}
