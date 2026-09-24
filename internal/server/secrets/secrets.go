// Package secrets implements the server-side secret store (M3, PRD §5.7):
//
//   - Master key from PARTOUT_SECRET_KEY_FILE (0600) or PARTOUT_SECRET_KEY.
//     No key configured → the feature is disabled with a clear error.
//   - Values are encrypted at rest with per-secret keys derived via HKDF from
//     the master key; versioned; a rotation revokes all prior versions.
//   - Distribution is E2E: the server decrypts the at-rest ciphertext, then
//     seals the plaintext to the agent with ephemeral X25519 ECDH so the
//     server holds the cleartext only for the duration of one materialization.
//   - Read APIs return metadata only; values are never serialized by the
//     REST layer. Materializations are audited (which version, which host,
//     which run).
package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/cryptoutil"
	"github.com/blawesom/partout/internal/id"
	pb "github.com/blawesom/partout/internal/proto"
	selectorpkg "github.com/blawesom/partout/internal/selector"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/store"
)

// InfoAtRest and InfoE2E are the HKDF context strings (versioned so a
// protocol change can force re-encryption without ambiguity).
const (
	InfoAtRest = "partout:secret-at-rest:v1:"
	InfoE2E    = "partout:secret-e2e:v1:"
)

// MaxValue is the largest secret value accepted (64 KiB).
const MaxValue = 64 << 10

// ErrDisabled is returned when no master key is configured.
var ErrDisabled = errors.New("secrets: no master key configured (set PARTOUT_SECRET_KEY_FILE or PARTOUT_SECRET_KEY)")

// LoadMasterKey reads the 32-byte master key from a file or env value.
// The file must be mode 0600; file/env contents may be raw 32 bytes or
// base64 of 32 bytes.
func LoadMasterKey() ([]byte, error) {
	if f := os.Getenv("PARTOUT_SECRET_KEY_FILE"); f != "" {
		fi, err := os.Stat(f)
		if err != nil {
			return nil, fmt.Errorf("secrets: master key file: %w", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			return nil, fmt.Errorf("secrets: master key file %s must be mode 0600 (got %o)", f, perm)
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("secrets: read key file: %w", err)
		}
		b = []byte(strings.TrimSpace(string(b)))
		if k, err := base64.StdEncoding.DecodeString(string(b)); err == nil && len(k) == 32 {
			b = k
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("secrets: master key file must hold 32 bytes (or base64 of 32), got %d", len(b))
		}
		return b, nil
	}
	if e := os.Getenv("PARTOUT_SECRET_KEY"); e != "" {
		b := []byte(e)
		if k, err := base64.StdEncoding.DecodeString(e); err == nil && len(k) == 32 {
			b = k
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("secrets: PARTOUT_SECRET_KEY must be 32 bytes (or base64 of 32), got %d", len(b))
		}
		return b, nil
	}
	return nil, ErrDisabled
}

// KeyFor derives the 32-byte AES-256-GCM key guarding one secret at rest.
func KeyFor(master []byte, secretID string) []byte {
	return cryptoutil.DeriveKey(master, []byte(InfoAtRest+secretID))
}

// E2EKey derives the per-materialization E2E key. The server computes it
// from (eph_priv, agent_pub); the agent computes the same bytes from
// (agent_priv, eph_pub).
func E2EKey(shared []byte, name string, version int64) []byte {
	return cryptoutil.DeriveKey(shared, []byte(InfoE2E+name+":"+strconv.FormatInt(version, 10)))
}

// Manager serves the secret store.
type Manager struct {
	st     *store.Store
	h      *stream.Handler
	log    *log.Logger
	master []byte
	// masterDigest is the sha256 of the master key, recorded in audit rows
	// so rotations of the master key are visible (never the key itself).
	masterDigest string
}

// New builds a Manager from a configured master key.
func New(st *store.Store, h *stream.Handler, master []byte, lg *log.Logger) (*Manager, error) {
	if master == nil {
		return nil, ErrDisabled
	}
	if lg == nil {
		lg = log.Default()
	}
	d := sha256.Sum256(master)
	return &Manager{st: st, h: h, log: lg, master: master,
		masterDigest: base64.StdEncoding.EncodeToString(d[:])}, nil
}

// CreateSecret stores a new secret at v1. The selector gates which hosts may
// materialize it ("all" / empty = every host).
func (m *Manager) CreateSecret(name, value, selector string, offlineTTL int64, actor string) (*store.Secret, error) {
	if !validName(name) {
		return nil, errors.New("secrets: invalid name (use [A-Za-z0-9._-], 1-64 chars)")
	}
	if len(value) > MaxValue {
		return nil, fmt.Errorf("secrets: value exceeds %d bytes", MaxValue)
	}
	if _, err := m.st.GetSecret(name); err == nil {
		return nil, fmt.Errorf("secrets: %q already exists", name)
	}
	if selector != "" {
		if _, err := selectorpkg.Parse(selector); err != nil {
			return nil, fmt.Errorf("secrets: selector syntax: %w", err)
		}
	}
	// Note: an empty match is allowed at creation time — a host may be
	// tagged later. Materialization is where the binding is enforced.
	secID := id.New("sec")
	ct, err := cryptoutil.Seal(KeyFor(m.master, secID), []byte(value))
	if err != nil {
		return nil, err
	}
	sec := store.Secret{ID: secID, Name: name, Selector: selector, OfflineTTL: offlineTTL}
	v1 := store.SecretVersion{ID: id.New("secv"), SecretID: secID, Version: 1, Ciphertext: ct}
	if err := m.st.CreateSecret(sec, v1); err != nil {
		return nil, err
	}
	m.audit("secret.created", sec.ID, 1, "", "", actor, name)
	return &sec, nil
}

// RotateSecret stores a new value as the next version and revokes all prior
// versions (PRD §5.7: a new version invalidates prior bindings).
func (m *Manager) RotateSecret(name, newValue string, actor string) (int64, error) {
	sec, err := m.st.GetSecret(name)
	if err != nil {
		return 0, err
	}
	if len(newValue) > MaxValue {
		return 0, fmt.Errorf("secrets: value exceeds %d bytes", MaxValue)
	}
	ct, err := cryptoutil.Seal(KeyFor(m.master, sec.ID), []byte(newValue))
	if err != nil {
		return 0, err
	}
	v, err := m.st.RotateSecret(sec.ID, ct)
	if err != nil {
		return 0, err
	}
	m.audit("secret.rotated", sec.ID, v, "", "", actor, name)
	return v, nil
}

// RevokeSecret revokes the secret's current version (value becomes
// unmaterializable; the row remains for audit).
func (m *Manager) RevokeSecret(name, actor string) error {
	sec, err := m.st.GetSecret(name)
	if err != nil {
		return err
	}
	v, err := m.st.GetLatestSecretVersion(sec.ID)
	if err != nil {
		return errors.New("secrets: no active version to revoke")
	}
	if err := m.st.RevokeSecretVersion(sec.ID, v.Version); err != nil {
		return err
	}
	m.audit("secret.revoked", sec.ID, v.Version, "", "", actor, name)
	return nil
}

// UpdateMeta changes selector / offline_ttl without touching versions.
// Zero values leave the field unchanged.
func (m *Manager) UpdateMeta(name, selector string, offlineTTL *int64, actor string) error {
	sec, err := m.st.GetSecret(name)
	if err != nil {
		return err
	}
	if selector == "" {
		selector = sec.Selector
	} else if _, err := m.resolve(selector); err != nil {
		return fmt.Errorf("secrets: selector: %w", err)
	}
	ttl := sec.OfflineTTL
	if offlineTTL != nil {
		ttl = *offlineTTL
	}
	if err := m.st.UpdateSecretMeta(sec.ID, selector, ttl); err != nil {
		return err
	}
	m.audit("secret.updated", sec.ID, 0, "", "", actor, name)
	return nil
}

// DeleteSecret removes a secret and all versions (admin).
func (m *Manager) DeleteSecret(name, actor string) error {
	sec, err := m.st.GetSecret(name)
	if err != nil {
		return err
	}
	if err := m.st.DeleteSecret(sec.ID); err != nil {
		return err
	}
	m.audit("secret.deleted", sec.ID, 0, "", "", actor, name)
	return nil
}

// View is the metadata returned by read APIs. It never carries a value.
type View struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Selector   string `json:"selector"`
	OfflineTTL int64  `json:"offline_ttl_s"`
	Created    int64  `json:"created"`
	Updated    int64  `json:"updated"`
	Version    int64  `json:"version"` // latest non-revoked version (0 = all revoked)
	AgentCount int    `json:"agent_count"`
}

// Get returns metadata for one secret.
func (m *Manager) Get(name string) (*View, error) {
	sec, err := m.st.GetSecret(name)
	if err != nil {
		return nil, err
	}
	return m.view(sec)
}

// List returns metadata for all secrets (never values).
func (m *Manager) List() ([]*View, error) {
	list, err := m.st.ListSecrets()
	if err != nil {
		return nil, err
	}
	out := make([]*View, 0, len(list))
	for _, sec := range list {
		v, err := m.view(sec)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// Bindings returns materialization audit rows (which version was used on
// which host by which run).
func (m *Manager) Bindings(name string, limit int) ([]*store.SecretBinding, error) {
	sec, err := m.st.GetSecret(name)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	return m.st.ListSecretBindings(sec.ID, limit)
}

func (m *Manager) view(sec *store.Secret) (*View, error) {
	v := &View{
		ID: sec.ID, Name: sec.Name, Selector: sec.Selector,
		OfflineTTL: sec.OfflineTTL, Created: sec.Created, Updated: sec.Updated,
	}
	if sv, err := m.st.GetLatestSecretVersion(sec.ID); err == nil {
		v.Version = sv.Version
	}
	hosts, err := m.resolve(sec.Selector)
	if err != nil {
		return nil, err
	}
	v.AgentCount = len(hosts)
	return v, nil
}

// resolve resolves the secret's selector against the current fleet. An
// empty selector means "all hosts".
func (m *Manager) resolve(selectorExpr string) ([]string, error) {
	r := store.NewResolver(m.st)
	if selectorExpr == "" {
		selectorExpr = "all"
	}
	hosts, err := r.ResolveSelector(selectorExpr)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	return ids, nil
}

// Materialize decrypts the secret's current version and sends it to the
// agent E2E-encrypted. The cleartext exists in server memory only for the
// duration of the call. ref identifies the run that declared the secret
// (task run / execution id) for the audit binding.
//
// Returns the version materialized.
func (m *Manager) Materialize(agentID, name, ref string) (int64, error) {
	sec, err := m.st.GetSecret(name)
	if err != nil {
		return 0, err
	}
	agent, err := m.st.Agent(agentID)
	if err != nil {
		return 0, fmt.Errorf("secrets: agent %s: %w", agentID, err)
	}
	if hosts, err := m.resolve(sec.Selector); err != nil {
		return 0, err
	} else if !containsID(hosts, agentID) {
		return 0, fmt.Errorf("secrets: %q is not bound to agent %s", name, agentID)
	}
	sv, err := m.st.GetLatestSecretVersion(sec.ID)
	if err != nil {
		return 0, fmt.Errorf("secrets: %q has no active version (revoked?)", name)
	}
	plaintext, err := cryptoutil.OpenKey(KeyFor(m.master, sec.ID), sv.Ciphertext)
	if err != nil {
		return 0, fmt.Errorf("secrets: decrypt %q v%d: %w", name, sv.Version, err)
	}

	// E2E seal with an ephemeral key (forward-secrecy style): only this
	// agent's enrolled X25519 private key can open it, and the eph key is
	// dropped with this call.
	agentPub, err := base64.StdEncoding.DecodeString(agent.X25519Pub)
	if err != nil || len(agentPub) != 32 {
		return 0, fmt.Errorf("secrets: agent %s has no valid x25519 public key", agentID)
	}
	eph, err := cryptoutil.NewKeyPairX25519()
	if err != nil {
		return 0, err
	}
	shared, err := cryptoutil.X25519(eph.Priv, agentPub)
	if err != nil {
		return 0, err
	}
	sealed, err := cryptoutil.Seal(E2EKey(shared, name, sv.Version), plaintext)
	if err != nil {
		return 0, err
	}
	sm := &pb.SecretMaterialize{
		Ref:       name,
		Version:   sv.Version,
		EphPub:    eph.Pub,
		Sealed:    sealed,
		CacheTtlS: sec.OfflineTTL,
	}
	if err := m.h.SendSecretMaterialize(agentID, sm); err != nil {
		return 0, err
	}
	if err := m.st.RecordSecretBinding(store.SecretBinding{
		SecretID: sec.ID, Version: sv.Version, AgentID: agentID, Ref: ref,
	}); err != nil {
		m.log.Printf("secrets: record binding %s@%s: %v", name, agentID, err)
	}
	m.audit("secret.materialized", sec.ID, sv.Version, agentID, ref, "system", name)
	return sv.Version, nil
}

// audit writes an append-only audit event (value material is never included).
func (m *Manager) audit(kind, secretID string, version int64, agentID, ref, actor, name string) {
	p := map[string]string{
		"secret":        name,
		"secret_id":     secretID,
		"version":       strconv.FormatInt(version, 10),
		"master_digest": m.masterDigest,
	}
	if agentID != "" {
		p["agent_id"] = agentID
	}
	if ref != "" {
		p["ref"] = ref
	}
	b, _ := json.Marshal(p)
	_ = m.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: kind, Actor: actor, AgentID: agentID, Payload: string(b),
	})
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		ok := r == '.' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}
