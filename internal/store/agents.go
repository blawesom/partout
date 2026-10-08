package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Agent is a registered host/agent.
type Agent struct {
	ID         string
	UUID       string
	ED25519Pub string
	X25519Pub  string
	// TlsPub is the enrolled ECDSA public key (PKIX b64) used to re-sign mTLS
	// leaves on rotation; "" for a non-TLS agent. TlsNotAfter is the current
	// leaf's expiry (unix s; 0 = none), used for expiry-driven rotation.
	TlsPub      string
	TlsNotAfter int64
	Version     string
	State       string // pending|connected|disconnected|revoked
	FirstSeen   int64
	LastSeen    int64
	Created     int64
}

// Facts is a point-in-time fact set for a host.
type Facts struct {
	AgentID string
	TS      int64
	Data    map[string]string
}

// Tag is a key=value (or key-only) host tag.
type Tag struct {
	AgentID string
	Key     string
	Value   string
}

// Enrollment token creation.
type EnrollmentToken struct {
	TokenHash string
	TokenMask string
	Created   int64
	Expires   int64
	Used      int
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ---- agents ---------------------------------------------------------------

// UpsertAgent inserts or updates an agent row.
func (s *Store) UpsertAgent(a Agent) error {
	a.FirstSeen = now()
	a.LastSeen = now()
	a.Created = now()
	if a.State == "" {
		a.State = "pending"
	}
	_, err := s.db.Exec(`
		INSERT INTO agents(id, uuid, ed25519_pub, x25519_pub, version, state, first_seen, last_seen, created)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			version=excluded.version,
			state=excluded.state,
			last_seen=excluded.last_seen
	`, a.ID, a.UUID, a.ED25519Pub, a.X25519Pub, a.Version, a.State, a.FirstSeen, a.LastSeen, a.Created)
	return err
}

// Agent returns a single agent by id.
func (s *Store) Agent(id string) (*Agent, error) {
	row := s.db.QueryRow(`
		SELECT id, uuid, ed25519_pub, x25519_pub, COALESCE(tls_pub,''), COALESCE(tls_not_after,0),
		       version, state,
		       COALESCE(first_seen,0), COALESCE(last_seen,0), created
		FROM agents WHERE id = ?`, id)
	return scanAgent(row)
}

// AgentByUUID returns an agent by its unique uuid.
func (s *Store) AgentByUUID(uuid string) (*Agent, error) {
	row := s.db.QueryRow(`
		SELECT id, uuid, ed25519_pub, x25519_pub, COALESCE(tls_pub,''), COALESCE(tls_not_after,0),
		       version, state,
		       COALESCE(first_seen,0), COALESCE(last_seen,0), created
		FROM agents WHERE uuid = ?`, uuid)
	return scanAgent(row)
}

// Agents lists all agents.
func (s *Store) Agents() ([]*Agent, error) {
	rows, err := s.db.Query(`
		SELECT id, uuid, ed25519_pub, x25519_pub, COALESCE(tls_pub,''), COALESCE(tls_not_after,0),
		       version, state,
		       COALESCE(first_seen,0), COALESCE(last_seen,0), created
		FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAgentTLS records the agent's enrolled ECDSA public key (PKIX b64) and the
// current mTLS leaf's expiry. Called at enrollment (when a CSR is presented) and
// again after each rotation.
func (s *Store) SetAgentTLS(id, tlsPubB64 string, notAfter int64) error {
	_, err := s.db.Exec(`UPDATE agents SET tls_pub=?, tls_not_after=? WHERE id=?`, tlsPubB64, notAfter, id)
	return err
}

// MarkSeen updates last_seen for an agent.
func (s *Store) MarkSeen(id string) error {
	_, err := s.db.Exec(`UPDATE agents SET last_seen=? WHERE id=?`, now(), id)
	return err
}

// SetState updates an agent's connection state.
// SetAgentVersion updates the host's reported version (used by M8.1: a
// verified update result should show in the fleet table immediately, not
// wait for the next hourly facts collection).
func (s *Store) SetAgentVersion(id, version string) error {
	_, err := s.db.Exec(`UPDATE agents SET version=? WHERE id=?`, version, id)
	return err
}

func (s *Store) SetAgentState(id, state string) error {
	_, err := s.db.Exec(`UPDATE agents SET state=? WHERE id=?`, state, id)
	return err
}

// MarkAllDisconnected sets every "connected" agent to "disconnected". Called at
// server startup: a freshly-started server has no live streams, so any agent
// previously recorded as connected is, by definition, not connected right now.
// The agents will flip back to "connected" when they reconnect and re-handshake.
func (s *Store) MarkAllDisconnected() error {
	_, err := s.db.Exec(`UPDATE agents SET state='disconnected' WHERE state='connected'`)
	return err
}

// ExpireStaleOfflineRuns marks runs parked in "queued_offline" as "expired" and
// returns the distinct execution ids to finalize. The offline down-queue lives
// in server memory, so a server restart orphans those runs (nothing can deliver
// or expire them any more). Called at startup next to MarkAllDisconnected.
func (s *Store) ExpireStaleOfflineRuns() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT execution_id FROM execution_runs WHERE state='queued_offline'`)
	if err != nil {
		return nil, err
	}
	var execs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		execs = append(execs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(execs) == 0 {
		return nil, nil
	}
	if _, err := s.db.Exec(`UPDATE execution_runs SET state='expired', updated=? WHERE state='queued_offline'`, now()); err != nil {
		return nil, err
	}
	return execs, nil
}

// MarkQueuedOfflineIfQueued sets a run to queued_offline only if it is still in
// the initial "queued" state, reporting whether it changed the row. This closes
// a dispatch race: the agent can reconnect and the queue drain can mark the run
// "delivered"/"running" before the dispatcher's post-SendCommand write lands;
// without the guard that write would regress a delivered/running run.
func (s *Store) MarkQueuedOfflineIfQueued(id string) (bool, error) {
	res, err := s.db.Exec(`UPDATE execution_runs SET state='queued_offline', updated=? WHERE id=? AND state='queued'`, now(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// DeleteAgent removes an agent and all cascaded rows (PRD R7).
func (s *Store) DeleteAgent(id string) error {
	// Resolve the agent's firing alerts first: the alerts table has no FK
	// cascade on agent_id, so without this a deleted host leaves firing
	// alerts orphaned forever (field report: ccc.laplane.net — 6 stale
	// config_invalid alerts from pre-rejoin agents that no longer existed).
	// Resolved (not deleted) — the alert history stays for the audit trail.
	if _, err := s.db.Exec(`UPDATE alerts SET state='resolved', resolved_at=? WHERE agent_id=? AND state='firing'`,
		now(), id); err != nil {
		return fmt.Errorf("resolve alerts for deleted agent: %w", err)
	}
	_, err := s.db.Exec(`DELETE FROM agents WHERE id=?`, id)
	return err
}

func scanAgent(row interface{ Scan(...any) error }) (*Agent, error) {
	var a Agent
	if err := row.Scan(&a.ID, &a.UUID, &a.ED25519Pub, &a.X25519Pub, &a.TlsPub, &a.TlsNotAfter,
		&sqlNullString{&a.Version}, &a.State,
		&a.FirstSeen, &a.LastSeen, &a.Created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// sqlNullString handles NULL version.
type sqlNullString struct{ p *string }

func (n *sqlNullString) Scan(src any) error {
	if src == nil {
		*n.p = ""
		return nil
	}
	// Use reflection-free approach: delegate to database/sql NullString.
	var ns sql.NullString
	if err := (&ns).Scan(src); err != nil {
		return err
	}
	*n.p = ns.String
	return nil
}

// ---- enrollment tokens ----------------------------------------------------

// CreateEnrollmentToken creates a token and returns the token hash and mask.
// The caller must retain the cleartext (shown once); only the hash is stored.
func (s *Store) CreateEnrollmentToken(tokenHash, tokenMask string, ttlS int) error {
	_, err := s.db.Exec(`
		INSERT INTO enrollment_tokens(token_hash, token_mask, created, expires)
		VALUES(?,?,?,?)
	`, tokenHash, tokenMask, now(), now()+int64(ttlS))
	return err
}

// ValidateEnrollmentToken reports whether a token is known, unused, and
// unexpired WITHOUT consuming it. Used by the one-line join flow (E1):
// the join script and binary downloads may be fetched (and retried)
// within the token's TTL; only the agent's actual enrollment consumes it.
func (s *Store) ValidateEnrollmentToken(tokenHash string) error {
	var (
		used    int
		expires int64
	)
	err := s.db.QueryRow(`
		SELECT used, expires FROM enrollment_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&used, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if used != 0 {
		return fmt.Errorf("store: enrollment token already used")
	}
	if time.Now().Unix() > expires {
		return fmt.Errorf("store: enrollment token expired")
	}
	return nil
}

// ConsumeEnrollmentToken marks a token as used and returns true if it was
// valid and unused. Returns an error if the token is unknown or expired.
func (s *Store) ConsumeEnrollmentToken(tokenHash string) (bool, error) {
	var (
		used    int
		expires int64
	)
	err := s.db.QueryRow(`
		SELECT used, expires FROM enrollment_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&used, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if used != 0 {
		return false, nil // already used
	}
	if time.Now().Unix() > expires {
		return false, fmt.Errorf("store: enrollment token expired")
	}
	_, err = s.db.Exec(`
		UPDATE enrollment_tokens SET used=1, used_at=? WHERE token_hash=?
	`, now(), tokenHash)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---- facts ----------------------------------------------------------------
//
// host_facts.data is a single JSON document per host (architecture §7.3):
// flat fact keys (host.*, partout.*, runtime.*) as top-level string values,
// plus structured observe facts (M5, R18–R20) as nested objects under
// services_detailed / configs / certificates. Every upsert merges into the
// latest document so the two fact streams never clobber each other.
//
// Merge correctness: the read-modify-write below is guarded by a per-agent
// mutex (factMu). The flat fact ticker and the observe fact ticker are
// independent goroutines on the agent and land on independent server paths,
// so without this guard a concurrent upsert silently drops one side (last
// writer wins on the whole document).

// factMu serializes fact-document read-modify-write per agent. A single
// global mutex is unnecessary: documents never span agents. It is held only
// for the duration of one read+write pair, which is a local DB round trip.
var factMu sync.Map // agentID -> *sync.Mutex

func factLock(agentID string) func() {
	m, _ := factMu.LoadOrStore(agentID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// UpsertFacts stores a flat fact snapshot for an agent, merging the scalar
// keys into the latest host_facts document (structured observe facts are
// preserved).
func (s *Store) UpsertFacts(f Facts) error {
	if f.TS == 0 {
		f.TS = now()
	}
	defer factLock(f.AgentID)()
	doc, err := s.latestFactsDoc(f.AgentID)
	if err != nil {
		return err
	}
	for k, v := range f.Data {
		doc[k] = v
	}
	return s.writeFactsDoc(f.AgentID, f.TS, doc)
}

// LatestFacts returns the most recent flat fact set for an agent. Only
// string values are surfaced; structured observe fact objects are excluded
// from the flat view (read them via LatestHostFactsJSON).
func (s *Store) LatestFacts(agentID string) (*Facts, error) {
	var (
		ts   int64
		data string
	)
	err := s.db.QueryRow(`
		SELECT ts, data FROM host_facts WHERE agent_id=? ORDER BY ts DESC LIMIT 1
	`, agentID).Scan(&ts, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if data != "" {
		if err := json.Unmarshal([]byte(data), &doc); err != nil {
			return nil, err
		}
	}
	flat := make(map[string]string, len(doc))
	for k, v := range doc {
		if str, ok := v.(string); ok {
			flat[k] = str
		}
	}
	return &Facts{AgentID: agentID, TS: ts, Data: flat}, nil
}

// UpsertHostFactsJSON merges a structured observe-facts JSON document (M5,
// R18–R20) into the latest host_facts document, preserving the flat fact
// keys. The incoming document carries any of the domain keys
// services_detailed / configs / certificates.
func (s *Store) UpsertHostFactsJSON(agentID, blob string) error {
	if blob == "" {
		return nil
	}
	var incoming map[string]any
	if err := json.Unmarshal([]byte(blob), &incoming); err != nil {
		return fmt.Errorf("parse observe facts: %w", err)
	}
	defer factLock(agentID)()
	doc, err := s.latestFactsDoc(agentID)
	if err != nil {
		return err
	}
	for k, v := range incoming {
		doc[k] = v
	}
	return s.writeFactsDoc(agentID, now(), doc)
}

// LatestHostFactsJSON returns the full latest host_facts document (flat +
// structured) as a JSON string. Empty string when the host has no facts.
func (s *Store) LatestHostFactsJSON(agentID string) (string, error) {
	var data string
	err := s.db.QueryRow(`
		SELECT data FROM host_facts WHERE agent_id=? ORDER BY ts DESC LIMIT 1
	`, agentID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return data, err
}

// latestFactsDoc returns the latest host_facts document as a map (empty
// map when none exists).
func (s *Store) latestFactsDoc(agentID string) (map[string]any, error) {
	doc := make(map[string]any)
	var data string
	err := s.db.QueryRow(`
		SELECT data FROM host_facts WHERE agent_id=? ORDER BY ts DESC LIMIT 1
	`, agentID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return doc, nil
	}
	if err != nil {
		return nil, err
	}
	if data != "" {
		if err := json.Unmarshal([]byte(data), &doc); err != nil {
			return nil, err
		}
	}
	return doc, nil
}

// writeFactsDoc marshals the document and stores it as a new row (the table
// is an append-only snapshot log; readers always take the latest ts).
//
// The (agent_id, ts) primary key means two writes in the same second would
// collide and one document would overwrite the other. Bump the timestamp
// until the row is free so a same-second flat+observe pair both persist.
// Callers must hold the per-agent fact lock.
func (s *Store) writeFactsDoc(agentID string, ts int64, doc map[string]any) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	// Bounded probe: find a free second for this document. Under the per-agent
	// lock only a pathological clock could exhaust 64 slots; the ON CONFLICT
	// below then merges into the existing row rather than failing the write.
	for attempt := 0; attempt < 64; attempt++ {
		var exists int
		err := s.db.QueryRow(`SELECT COUNT(1) FROM host_facts WHERE agent_id=? AND ts=?`, agentID, ts).Scan(&exists)
		if err != nil {
			return err
		}
		if exists == 0 {
			break
		}
		ts++
	}
	_, err = s.db.Exec(`
		INSERT INTO host_facts(agent_id, ts, data) VALUES(?,?,?)
		ON CONFLICT(agent_id, ts) DO UPDATE SET data=excluded.data
	`, agentID, ts, string(data))
	return err
}

// ---- tags / roles ---------------------------------------------------------

// SetTag upserts a host tag.
func (s *Store) SetTag(agentID, key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO host_tags(agent_id, k, v) VALUES(?,?,?)
		ON CONFLICT(agent_id, k) DO UPDATE SET v=excluded.v
	`, agentID, key, value)
	return err
}

// DeleteTag removes a host tag.
func (s *Store) DeleteTag(agentID, key string) error {
	_, err := s.db.Exec(`DELETE FROM host_tags WHERE agent_id=? AND k=?`, agentID, key)
	return err
}

// SetRole adds a role to a host.
func (s *Store) SetRole(agentID, role string) error {
	_, err := s.db.Exec(`
		INSERT INTO host_roles(agent_id, role) VALUES(?,?)
		ON CONFLICT(agent_id, role) DO NOTHING
	`, agentID, role)
	return err
}

// DeleteRole removes a role from a host.
func (s *Store) DeleteRole(agentID, role string) error {
	_, err := s.db.Exec(`DELETE FROM host_roles WHERE agent_id=? AND role=?`, agentID, role)
	return err
}

// Tags returns all tags for a host as a map (key-only tags are "").
func (s *Store) Tags(agentID string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT k, v FROM host_tags WHERE agent_id=?`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// Roles returns all roles for a host.
func (s *Store) Roles(agentID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT role FROM host_roles WHERE agent_id=? ORDER BY role`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- groups ---------------------------------------------------------------

// Group is a named selector.
type Group struct {
	Name     string
	Selector string
	Created  int64
	Updated  int64
}

// UpsertGroup inserts or updates a group.
func (s *Store) UpsertGroup(g Group) error {
	if g.Created == 0 {
		g.Created = now()
	}
	g.Updated = now()
	_, err := s.db.Exec(`
		INSERT INTO groups(name, selector, created, updated) VALUES(?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET selector=excluded.selector, updated=excluded.updated
	`, g.Name, g.Selector, g.Created, g.Updated)
	return err
}

// DeleteGroup removes a group.
func (s *Store) DeleteGroup(name string) error {
	_, err := s.db.Exec(`DELETE FROM groups WHERE name=?`, name)
	return err
}

// Groups returns all groups as a name→selector map (for selector resolution).
func (s *Store) Groups() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT name, selector FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var name, sel string
		if err := rows.Scan(&name, &sel); err != nil {
			return nil, err
		}
		out[name] = sel
	}
	return out, rows.Err()
}
