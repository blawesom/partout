// Package store — audit log hash chain (PRD Decision 5, 1.0 gate).
//
// Every audit_events row carries hash over a canonical byte string of
// (prev_hash ‖ ts ‖ kind ‖ actor ‖ agent_id ‖ payload ‖ id), prefixed with a
// domain-separation tag. prev_hash is the hash of the preceding row (by id),
// making the log tamper-evident: editing or deleting any row breaks every
// hash after it.
//
// Two algorithms coexist, distinguished per row by audit_events.algo:
//   - algo=1: unkeyed sha256, domain "partout.audit.v1\x00" (legacy rows).
//   - algo=2: HMAC-SHA256 under a server-held key derived from the server
//     Ed25519 identity, domain "partout.audit.v2\x00". New rows get algo=2
//     once SetAuditKey ran, so an attacker with DB write access cannot
//     recompute the chain without the server identity key (which never
//     leaves <db dir>/identity). Verifying algo=2 rows without the key fails
//     closed.
//
// The chain head is memoized in audit_chain_state (one row) so an append is
// one head SELECT + one INSERT + one head UPDATE under the store's
// single-writer model — never a MAX(id) scan.
package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// auditChainDomain separates the audit chain from any other sha256 use in
// Partout so the same bytes can never be reinterpreted across contexts.
var auditChainDomain = []byte("partout.audit.v1\x00")

// auditChainDomainV2 is the keyed (HMAC) chain domain. Distinct from v1 so a
// v1 hash can never be reinterpreted as a v2 MAC.
var auditChainDomainV2 = []byte("partout.audit.v2\x00")

// Chain algorithm identifiers stored in audit_events.algo.
const (
	AuditAlgoV1 = 1 // unkeyed sha256 (legacy)
	AuditAlgoV2 = 2 // HMAC-SHA256 under the server-derived audit key
)

// auditHash computes the v1 (unkeyed sha256) chain hash for one row.
func auditHash(prevHash string, a *AuditEvent, id int64) string {
	h := sha256.New()
	h.Write(auditChainDomain)
	for _, f := range []string{
		prevHash,
		fmt.Sprintf("%d", a.TS),
		a.Kind,
		a.Actor,
		a.AgentID,
		a.Payload,
		fmt.Sprintf("%d", id),
	} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// auditHashKeyed computes the v2 (HMAC-SHA256) chain hash for one row.
func auditHashKeyed(key []byte, prevHash string, a *AuditEvent, id int64) string {
	h := hmac.New(sha256.New, key)
	h.Write(auditChainDomainV2)
	for _, f := range []string{
		prevHash,
		fmt.Sprintf("%d", a.TS),
		a.Kind,
		a.Actor,
		a.AgentID,
		a.Payload,
		fmt.Sprintf("%d", id),
	} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// rowHash computes the chain hash for a row according to its algo. ok=false
// means the row's algo cannot be verified in this process (algo=2 without a
// key) — callers treat that as a broken chain (fail closed).
func (s *Store) rowHash(algo int, prevHash string, a *AuditEvent, id int64) (string, bool) {
	switch algo {
	case AuditAlgoV2:
		if len(s.auditKey) == 0 {
			return "", false
		}
		return auditHashKeyed(s.auditKey, prevHash, a, id), true
	default:
		return auditHash(prevHash, a, id), true
	}
}

// nextAlgo returns the algo new rows get: v2 when an audit key is set.
func (s *Store) nextAlgo() int {
	if len(s.auditKey) > 0 {
		return AuditAlgoV2
	}
	return AuditAlgoV1
}

// auditChainHead returns the memoized chain head (last id + hash + key id).
// A missing row yields (0, "", "", nil): an empty (or legacy, pre-chain) log.
func (s *Store) auditChainHead(tx *sql.Tx) (int64, string, string, error) {
	var lastID int64
	var lastHash, keyID string
	err := tx.QueryRow(`SELECT last_id, last_hash, key_id FROM audit_chain_state WHERE id=1`).Scan(&lastID, &lastHash, &keyID)
	if err == sql.ErrNoRows {
		return 0, "", "", nil
	}
	if err != nil {
		return 0, "", "", fmt.Errorf("store: audit chain head: %w", err)
	}
	return lastID, lastHash, keyID, nil
}

// backfillAuditChain computes the chain over existing rows that predate the
// hash columns (or a migrated DB whose state row was never written), in id
// order, rewriting only the new chain columns — never row content. Called
// lazily inside the first append/verify transaction, once.
func (s *Store) backfillAuditChain(tx *sql.Tx) (int64, string, error) {
	rows, err := tx.Query(`SELECT id, ts, kind, actor, agent_id, payload FROM audit_events ORDER BY id ASC`)
	if err != nil {
		return 0, "", fmt.Errorf("store: audit backfill scan: %w", err)
	}
	defer rows.Close()
	var prevHash string
	var lastID int64
	for rows.Next() {
		a := &AuditEvent{}
		var id int64
		var agent sql.NullString
		if err := rows.Scan(&id, &a.TS, &a.Kind, &a.Actor, &agent, &a.Payload); err != nil {
			return 0, "", fmt.Errorf("store: audit backfill row: %w", err)
		}
		a.AgentID = agent.String
		hash := auditHash(prevHash, a, id)
		// Backfilled rows are always legacy algo=1 (they predate the keyed
		// chain; the key never sees them).
		if _, err := tx.Exec(`UPDATE audit_events SET prev_hash=?, hash=?, algo=? WHERE id=?`, prevHash, hash, AuditAlgoV1, id); err != nil {
			return 0, "", fmt.Errorf("store: audit backfill update: %w", err)
		}
		prevHash = hash
		lastID = id
	}
	if err := rows.Err(); err != nil {
		return 0, "", fmt.Errorf("store: audit backfill scan: %w", err)
	}
	return lastID, prevHash, nil
}

// ensureAuditChain returns the memoized head, backfilling the chain over
// legacy rows (a database from before the hash columns existed) once, in id
// order, if the state row is missing. Must run inside the caller's
// transaction.
func (s *Store) ensureAuditChain(tx *sql.Tx) (int64, string, error) {
	lastID, lastHash, _, err := s.auditChainHead(tx)
	if err != nil || lastID > 0 {
		return lastID, lastHash, err
	}
	// No memoized head: either an empty log or a legacy pre-chain database.
	// Backfill computes the chain without touching pre-existing row content.
	lastID, lastHash, err = s.backfillAuditChain(tx)
	if err != nil {
		return 0, "", err
	}
	if lastID == 0 {
		return 0, "", nil // empty log; the first append writes the state row
	}
	if _, err := tx.Exec(`INSERT INTO audit_chain_state(id, last_id, last_hash, key_id) VALUES(1, ?, ?, ?)`,
		lastID, lastHash, s.auditKeyID); err != nil {
		return 0, "", fmt.Errorf("store: audit chain state insert: %w", err)
	}
	return lastID, lastHash, nil
}

// ensureAuditChainCommitted runs the lazy backfill in its own transaction
// (verify-only path: no append pending).
func (s *Store) ensureAuditChainCommitted() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	if _, _, err := s.ensureAuditChain(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// AppendAuditChained appends an audit event with its hash-chain fields in a
// single transaction: read head, insert row, set its chain columns, update
// the head.
func (s *Store) AppendAuditChained(a AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	_, lastHash, err := s.ensureAuditChain(tx)
	if err != nil {
		return err
	}
	algo := s.nextAlgo()
	res, err := tx.Exec(`INSERT INTO audit_events(ts, kind, actor, agent_id, payload, algo) VALUES(?,?,?,?,?,?)`,
		a.TS, a.Kind, a.Actor, a.AgentID, a.Payload, algo)
	if err != nil {
		return fmt.Errorf("store: audit insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("store: audit insert id: %w", err)
	}
	hash, ok := s.rowHash(algo, lastHash, &a, id)
	if !ok {
		return fmt.Errorf("store: audit chain: algo=%d requires an audit key that is not set", algo)
	}
	if _, err := tx.Exec(`UPDATE audit_events SET prev_hash=?, hash=? WHERE id=?`, lastHash, hash, id); err != nil {
		return fmt.Errorf("store: audit chain update: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO audit_chain_state(id, last_id, last_hash, key_id) VALUES(1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id, last_hash=excluded.last_hash, key_id=excluded.key_id`,
		id, hash, s.auditKeyID); err != nil {
		return fmt.Errorf("store: audit chain state: %w", err)
	}
	return tx.Commit()
}

// AuditVerifyResult reports the outcome of walking the audit chain.
type AuditVerifyResult struct {
	OK          bool
	RowsChecked int64
	BrokenRowID int64 // 0 when OK
	Reason      string
}

// AuditChainKeyID returns the key id recorded in audit_chain_state WITHOUT
// triggering the legacy backfill (startup key-change guard: a fresh or legacy
// chain has "" and accepts any key; a keyed chain pins its key). Empty string
// = no keyed chain yet.
func (s *Store) AuditChainKeyID() (string, error) {
	var keyID string
	err := s.db.QueryRow(`SELECT key_id FROM audit_chain_state WHERE id=1`).Scan(&keyID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: audit chain key id: %w", err)
	}
	return keyID, nil
}

// AuditChainHead returns the memoized chain head (last row id + hash),
// backfilling legacy rows first if needed.
func (s *Store) AuditChainHead() (int64, string, error) {
	id, hash, _, err := s.AuditChainHeadFull()
	return id, hash, err
}

// AuditChainHeadFull is AuditChainHead plus the id of the HMAC key that
// verifies algo=2 rows. Used by the verify endpoint so an operator can anchor
// the head out-of-band (the API response carries an Ed25519 signature over the
// head when the server identity is installed).
func (s *Store) AuditChainHeadFull() (int64, string, string, error) {
	if err := s.ensureAuditChainCommitted(); err != nil {
		return 0, "", "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, "", "", fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	lastID, lastHash, keyID, err := s.auditChainHead(tx)
	if err != nil {
		return 0, "", "", err
	}
	return lastID, lastHash, keyID, tx.Commit()
}

// VerifyAuditChain walks the full chain in id order and reports whether every
// row's recorded hash matches its payload and every prev_hash links to the
// preceding row's hash. Each row is checked with its own algo (v1 unkeyed
// sha256, or v2 HMAC when an audit key is set); a v2 row verified without the
// key fails closed. Legacy rows not yet chained (an upgraded database
// with no append since) are chained first, once.
func (s *Store) VerifyAuditChain() (AuditVerifyResult, error) {
	if err := s.ensureAuditChainCommitted(); err != nil {
		return AuditVerifyResult{}, err
	}
	rows, err := s.db.Query(`SELECT id, ts, kind, actor, agent_id, payload, prev_hash, hash, algo FROM audit_events ORDER BY id ASC`)
	if err != nil {
		return AuditVerifyResult{}, fmt.Errorf("store: audit verify scan: %w", err)
	}
	defer rows.Close()
	var prevHash string
	var checked int64
	for rows.Next() {
		a := &AuditEvent{}
		var id int64
		var agent sql.NullString
		var algo int
		if err := rows.Scan(&id, &a.TS, &a.Kind, &a.Actor, &agent, &a.Payload, &a.PrevHash, &a.Hash, &algo); err != nil {
			return AuditVerifyResult{}, fmt.Errorf("store: audit verify row: %w", err)
		}
		a.AgentID = agent.String
		if a.PrevHash != prevHash {
			return AuditVerifyResult{OK: false, RowsChecked: checked, BrokenRowID: id, Reason: "prev_hash does not link to the previous row's hash"}, nil
		}
		want, ok := s.rowHash(algo, prevHash, a, id)
		if !ok {
			return AuditVerifyResult{OK: false, RowsChecked: checked, BrokenRowID: id,
				Reason: fmt.Sprintf("row uses keyed chain (algo=%d) but no audit key is configured", algo)}, nil
		}
		if a.Hash != want {
			return AuditVerifyResult{OK: false, RowsChecked: checked, BrokenRowID: id, Reason: "payload does not match recorded hash"}, nil
		}
		prevHash = a.Hash
		checked++
	}
	if err := rows.Err(); err != nil {
		return AuditVerifyResult{}, fmt.Errorf("store: audit verify scan: %w", err)
	}
	return AuditVerifyResult{OK: true, RowsChecked: checked}, nil
}
