// Package secrets is the agent-side secret materialization cache (M3,
// PRD §5.7).
//
// The server delivers each secret E2E-encrypted (ephemeral X25519 ECDH to
// this agent's enrolled key). The cache:
//
//   - holds the plaintext in memory for the lifetime of the declaring run;
//   - when cache_ttl_s > 0, persists the SEALED form (eph_pub + ciphertext,
//     never the plaintext) so offline runs within the window can still
//     materialize; the plaintext is only ever re-derived in memory;
//   - prunes expired entries on load and on each save.
//
// A step that declares a secret which is not present fails closed — the
// task runner reports "secret unavailable" (PRD §5.7 offline rule).
package secrets

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/blawesom/partout/internal/cryptoutil"
	pb "github.com/blawesom/partout/internal/proto"
)

// InfoE2E mirrors the server's HKDF context (secrets.E2EKey).
const InfoE2E = "partout:secret-e2e:v1:"

// Cache holds materialized secrets.
type Cache struct {
	mu     sync.RWMutex
	mem    map[string]memEntry // key: ref
	file   string
	xpriv  []byte // agent X25519 private key
	now    func() time.Time
	loaded map[string]cachedEntry // disk cache, loaded lazily
}

type memEntry struct {
	value   string
	version int64
	expires time.Time // zero = live only (no disk persistence)
}

// cachedEntry is the on-disk sealed form (never plaintext).
type cachedEntry struct {
	Version     int64  `json:"version"`
	EphPubB64   string `json:"eph_pub_b64"`
	SealedB64   string `json:"sealed_b64"`
	ExpiresUnix int64  `json:"expires_unix"`
}

// New builds a cache rooted at dir (typically <data>/agent). The disk file
// is 0600 and holds only sealed material.
func New(dir string, xpriv []byte) (*Cache, error) {
	if len(xpriv) != 32 {
		return nil, fmt.Errorf("secrets: agent x25519 private key required (32 bytes)")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &Cache{
		mem:   make(map[string]memEntry),
		file:  filepath.Join(dir, "secret_cache.json"),
		xpriv: xpriv,
		now:   time.Now,
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// Handle processes one SecretMaterialize envelope from the server.
// It returns the plaintext value (for the caller to hand to the declaring
// run) and persists the sealed form when cache_ttl_s > 0.
func (c *Cache) Handle(sm *pb.SecretMaterialize) (string, error) {
	if len(sm.EphPub) != 32 {
		return "", fmt.Errorf("secrets: bad eph_pub length %d", len(sm.EphPub))
	}
	shared, err := cryptoutil.X25519(c.xpriv, sm.EphPub)
	if err != nil {
		return "", fmt.Errorf("secrets: x25519: %w", err)
	}
	key := cryptoutil.DeriveKey(shared, []byte(InfoE2E+sm.Ref+":"+itoa(sm.Version)))
	plaintext, err := cryptoutil.OpenKey(key, sm.Sealed)
	if err != nil {
		return "", fmt.Errorf("secrets: decrypt %s: %w", sm.Ref, err)
	}

	expires := time.Time{}
	if sm.CacheTtlS > 0 {
		expires = c.now().Add(time.Duration(sm.CacheTtlS) * time.Second)
	}
	c.mu.Lock()
	c.mem[sm.Ref] = memEntry{value: string(plaintext), version: sm.Version, expires: expires}
	if sm.CacheTtlS > 0 {
		c.loaded[sm.Ref] = cachedEntry{
			Version:     sm.Version,
			EphPubB64:   base64.StdEncoding.EncodeToString(sm.EphPub),
			SealedB64:   base64.StdEncoding.EncodeToString(sm.Sealed),
			ExpiresUnix: expires.Unix(),
		}
		if err := c.writeLocked(); err != nil {
			c.mu.Unlock()
			return "", fmt.Errorf("secrets: persist %s: %w", sm.Ref, err)
		}
	}
	c.mu.Unlock()
	return string(plaintext), nil
}

// Get returns the plaintext value for ref, from memory first, then the
// sealed disk cache. ok=false means the secret is unavailable → the
// declaring step fails closed.
func (c *Cache) Get(ref string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.mem[ref]; ok {
		if !e.expires.IsZero() && c.now().After(e.expires) {
			return "", false
		}
		return e.value, true
	}
	ce, ok := c.loaded[ref]
	if !ok {
		return "", false
	}
	if c.now().Unix() > ce.ExpiresUnix {
		delete(c.loaded, ref)
		_ = c.writeLocked()
		return "", false
	}
	ephPub, err := base64.StdEncoding.DecodeString(ce.EphPubB64)
	if err != nil {
		return "", false
	}
	sealed, err := base64.StdEncoding.DecodeString(ce.SealedB64)
	if err != nil {
		return "", false
	}
	shared, err := cryptoutil.X25519(c.xpriv, ephPub)
	if err != nil {
		return "", false
	}
	key := cryptoutil.DeriveKey(shared, []byte(InfoE2E+ref+":"+itoa(ce.Version)))
	plaintext, err := cryptoutil.OpenKey(key, sealed)
	if err != nil {
		return "", false
	}
	// Promote into memory for the remainder of this process lifetime.
	c.mem[ref] = memEntry{value: string(plaintext), version: ce.Version,
		expires: time.Unix(ce.ExpiresUnix, 0)}
	return string(plaintext), true
}

// Drop forgets in-memory + disk copies of ref (e.g. run finished).
func (c *Cache) Drop(ref string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.mem, ref)
	if _, ok := c.loaded[ref]; ok {
		delete(c.loaded, ref)
		_ = c.writeLocked()
	}
}

// Prune removes expired in-memory and disk entries (agent calls it
// periodically; Get also prunes lazily on read).
func (c *Cache) Prune() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := false
	for ref, e := range c.mem {
		if !e.expires.IsZero() && now.After(e.expires) {
			delete(c.mem, ref)
			changed = true
		}
	}
	for ref, e := range c.loaded {
		if e.ExpiresUnix > 0 && now.Unix() > e.ExpiresUnix {
			delete(c.loaded, ref)
			changed = true
		}
	}
	if changed {
		_ = c.writeLocked()
	}
}

// ---- disk persistence (sealed form only) -----------------------------------

// load reads the on-disk sealed cache (0600). A missing file is normal on a
// fresh agent; a corrupt file is replaced with an empty cache (never fails
// the agent).
func (c *Cache) load() error {
	c.loaded = make(map[string]cachedEntry)
	b, err := os.ReadFile(c.file)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("secrets: read cache: %w", err)
	}
	if err := json.Unmarshal(b, &c.loaded); err != nil {
		c.loaded = make(map[string]cachedEntry)
	}
	// Prune expired entries while loading.
	now := c.now()
	for ref, e := range c.loaded {
		if e.ExpiresUnix > 0 && now.Unix() > e.ExpiresUnix {
			delete(c.loaded, ref)
		}
	}
	return nil
}

func (c *Cache) writeLocked() error {
	b, err := json.Marshal(c.loaded)
	if err != nil {
		return err
	}
	tmp := c.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.file)
}

func itoa(v int64) string {
	return fmt.Sprint(v)
}