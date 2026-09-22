package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Agent is a registered host/agent.
type Agent struct {
	ID         string
	UUID       string
	ED25519Pub string
	X25519Pub  string
	Version    string
	State      string // pending|connected|disconnected|revoked
	FirstSeen  int64
	LastSeen   int64
	Created    int64
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
		SELECT id, uuid, ed25519_pub, x25519_pub, version, state,
		       COALESCE(first_seen,0), COALESCE(last_seen,0), created
		FROM agents WHERE id = ?`, id)
	return scanAgent(row)
}

// AgentByUUID returns an agent by its unique uuid.
func (s *Store) AgentByUUID(uuid string) (*Agent, error) {
	row := s.db.QueryRow(`
		SELECT id, uuid, ed25519_pub, x25519_pub, version, state,
		       COALESCE(first_seen,0), COALESCE(last_seen,0), created
		FROM agents WHERE uuid = ?`, uuid)
	return scanAgent(row)
}

// Agents lists all agents.
func (s *Store) Agents() ([]*Agent, error) {
	rows, err := s.db.Query(`
		SELECT id, uuid, ed25519_pub, x25519_pub, version, state,
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

// MarkSeen updates last_seen for an agent.
func (s *Store) MarkSeen(id string) error {
	_, err := s.db.Exec(`UPDATE agents SET last_seen=? WHERE id=?`, now(), id)
	return err
}

// SetState updates an agent's connection state.
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

// DeleteAgent removes an agent and all cascaded rows (PRD R7).
func (s *Store) DeleteAgent(id string) error {
	_, err := s.db.Exec(`DELETE FROM agents WHERE id=?`, id)
	return err
}

func scanAgent(row interface{ Scan(...any) error }) (*Agent, error) {
	var a Agent
	if err := row.Scan(&a.ID, &a.UUID, &a.ED25519Pub, &a.X25519Pub,
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

// UpsertFacts stores a fact snapshot for an agent.
func (s *Store) UpsertFacts(f Facts) error {
	if f.TS == 0 {
		f.TS = now()
	}
	data, err := json.Marshal(f.Data)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO host_facts(agent_id, ts, data) VALUES(?,?,?)
		ON CONFLICT(agent_id, ts) DO UPDATE SET data=excluded.data
	`, f.AgentID, f.TS, string(data))
	return err
}

// LatestFacts returns the most recent fact set for an agent.
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
	var m map[string]string
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return nil, err
	}
	return &Facts{AgentID: agentID, TS: ts, Data: m}, nil
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
