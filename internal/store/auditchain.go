// Package store — audit log hash chain (PRD Decision 5, 1.0 gate).
//
// Every audit_events row carries hash = sha256 over a canonical byte string
// of (prev_hash ‖ ts ‖ kind ‖ actor ‖ agent_id ‖ payload ‖ id), prefixed with
// the domain-separation tag "partout.audit.v1\x00". prev_hash is the hash of
// the preceding row (by id), making the log tamper-evident: editing or
// deleting any row breaks every hash after it.
//
// The chain head is memoized in audit_chain_state (one row) so an append is
// one head SELECT + one INSERT + one head UPDATE under the store's
// single-writer model — never a MAX(id) scan.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// auditChainDomain separates the audit chain from any other sha256 use in
// Partout so the same bytes can never be reinterpreted across contexts.
var auditChainDomain = []byte("partout.audit.v1\x00")

// auditHash computes the chain hash for one row.
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

// auditChainHead returns the memoized chain head (last id + last hash).
// A missing row yields (0, "", nil): an empty (or legacy, pre-chain) log.
func (s *Store) auditChainHead(tx *sql.Tx) (int64, string, error) {
	var lastID int64
	var lastHash string
	err := tx.QueryRow(`SELECT last_id, last_hash FROM audit_chain_state WHERE id=1`).Scan(&lastID, &lastHash)
	if err == sql.ErrNoRows {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("store: audit chain head: %w", err)
	}
	return lastID, lastHash, nil
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
		if _, err := tx.Exec(`UPDATE audit_events SET prev_hash=?, hash=? WHERE id=?`, prevHash, hash, id); err != nil {
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
	lastID, lastHash, err := s.auditChainHead(tx)
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
	if _, err := tx.Exec(`INSERT INTO audit_chain_state(id, last_id, last_hash) VALUES(1, ?, ?)`, lastID, lastHash); err != nil {
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
	res, err := tx.Exec(`INSERT INTO audit_events(ts, kind, actor, agent_id, payload) VALUES(?,?,?,?,?)`,
		a.TS, a.Kind, a.Actor, a.AgentID, a.Payload)
	if err != nil {
		return fmt.Errorf("store: audit insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("store: audit insert id: %w", err)
	}
	hash := auditHash(lastHash, &a, id)
	if _, err := tx.Exec(`UPDATE audit_events SET prev_hash=?, hash=? WHERE id=?`, lastHash, hash, id); err != nil {
		return fmt.Errorf("store: audit chain update: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO audit_chain_state(id, last_id, last_hash) VALUES(1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id, last_hash=excluded.last_hash`, id, hash); err != nil {
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

// VerifyAuditChain walks the full chain in id order and reports whether every
// row's recorded hash matches its payload and every prev_hash links to the
// preceding row's hash. Legacy rows not yet chained (an upgraded database
// with no append since) are chained first, once.
func (s *Store) VerifyAuditChain() (AuditVerifyResult, error) {
	if err := s.ensureAuditChainCommitted(); err != nil {
		return AuditVerifyResult{}, err
	}
	rows, err := s.db.Query(`SELECT id, ts, kind, actor, agent_id, payload, prev_hash, hash FROM audit_events ORDER BY id ASC`)
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
		if err := rows.Scan(&id, &a.TS, &a.Kind, &a.Actor, &agent, &a.Payload, &a.PrevHash, &a.Hash); err != nil {
			return AuditVerifyResult{}, fmt.Errorf("store: audit verify row: %w", err)
		}
		a.AgentID = agent.String
		if a.PrevHash != prevHash {
			return AuditVerifyResult{OK: false, RowsChecked: checked, BrokenRowID: id, Reason: "prev_hash does not link to the previous row's hash"}, nil
		}
		if a.Hash != auditHash(prevHash, a, id) {
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
