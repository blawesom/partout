// doctor_db.go — read-only database health checks for `partout doctor`
// (server/embedded mode): fleet version skew (operations.md
// "version_mismatch" — previously documented but never implemented) and the
// production-evidence query pack (empty audit actors, stuck executions,
// expired pending approvals, the file-root fact wipe signature). Everything
// opens the DB mode=ro and creates nothing; a missing DB is a fresh
// install, not an error.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // read-only opens; no writes ever

	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/version"
)

// openDBRO opens the SQLite database read-only. The driver is shared with
// the store; mode=ro guarantees the doctor can never mutate state.
func openDBRO(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// checkFleetVersions compares every enrolled agent's reported version with
// this binary's: mixed versions are the precondition for every legacy/skew
// code path (file roots, fact shapes, self-update compatibility), and the
// operations.md troubleshooting table has always assumed this check exists.
func checkFleetVersions(cfg *config.Config, r *doctorResult) {
	db, err := openDBRO(cfg.DBPath)
	if err != nil {
		if os.IsNotExist(err) {
			r.add(dinfo, "fleet versions", "no database yet — nothing enrolled")
			return
		}
		r.add(dwarn, "fleet versions", "cannot open db: "+err.Error())
		return
	}
	defer db.Close()

	rows, err := db.Query(`SELECT version, COUNT(*) FROM agents GROUP BY version`)
	if err != nil {
		r.add(dwarn, "fleet versions", "query: "+err.Error())
		return
	}
	defer rows.Close()
	var skew, never []string
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			continue
		}
		switch {
		case v == "":
			never = append(never, fmt.Sprintf("%d agent(s) never connected", n))
		case !version.Equal(v, facts.Version):
			skew = append(skew, fmt.Sprintf("%s ×%d", v, n))
		}
	}
	switch {
	case len(skew) > 0:
		r.add(dwarn, "fleet versions",
			"agents not at server version "+facts.Version+": "+strings.Join(skew, ", ")+
				" — upgrade via the Updates page (rollouts); legacy/skew code paths apply until then")
	case len(never) > 0:
		r.add(dinfo, "fleet versions", "server "+facts.Version+" · "+strings.Join(never, ", "))
	default:
		r.add(dok, "fleet versions", "all agents at "+facts.Version)
	}
}

// checkDBHealth is the production-evidence pack: queries that found real
// bugs when run against a live database (the file-root fact wipe was
// confirmed this way). Every finding is a symptom class the UI cannot see.
func checkDBHealth(cfg *config.Config, r *doctorResult) {
	db, err := openDBRO(cfg.DBPath)
	if err != nil {
		if os.IsNotExist(err) {
			r.add(dinfo, "db health", "no database yet — fresh install")
			return
		}
		r.add(dwarn, "db health", "cannot open db: "+err.Error())
		return
	}
	defer db.Close()
	checkAuditActors(db, r)
	checkStuckExecutions(db, r)
	checkExpiredApprovals(db, r)
	checkFileRootFacts(db, r)
}

// checkAuditActors: audit rows without an actor break the C8 accountability
// story (who did this?) — the exec dispatch path produced these before the
// created_by stamping fix.
func checkAuditActors(db *sql.DB, r *doctorResult) {
	rows, err := db.Query(`SELECT kind, COUNT(*) FROM audit_events WHERE actor='' OR actor IS NULL GROUP BY kind ORDER BY 2 DESC`)
	if err != nil {
		r.add(dwarn, "db audit actors", "query: "+err.Error())
		return
	}
	defer rows.Close()
	var out []string
	total := 0
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err == nil {
			out = append(out, fmt.Sprintf("%s ×%d", k, n))
			total += n
		}
	}
	if total > 0 {
		r.add(dwarn, "db audit actors", fmt.Sprintf("%d audit row(s) without an actor: %s", total, strings.Join(out, ", ")))
		return
	}
	r.add(dok, "db audit actors", "every audit row names its actor")
}

// checkStuckExecutions: executions still in a non-terminal state long past
// the spool window will never finalize on their own — invisible stalls.
func checkStuckExecutions(db *sql.DB, r *doctorResult) {
	cutoff := time.Now().Add(-72 * time.Hour).Unix()
	rows, err := db.Query(`SELECT id, state FROM executions WHERE state IN ('dispatching','running','interrupted','queued') AND created < ?`, cutoff)
	if err != nil {
		r.add(dwarn, "db stuck execs", "query: "+err.Error())
		return
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err == nil {
			out = append(out, id+" ("+state+")")
		}
	}
	if len(out) > 0 {
		r.add(dwarn, "db stuck execs", fmt.Sprintf("%d execution(s) non-terminal for >72h: %s", len(out), strings.Join(out, ", ")))
		return
	}
	r.add(dok, "db stuck execs", "no executions stuck non-terminal >72h")
}

// checkExpiredApprovals: a pending request past its expiry should have been
// finalized expired by the approvals engine — still-pending rows are a
// sweeper defect, and they keep the nav badge count inflated.
func checkExpiredApprovals(db *sql.DB, r *doctorResult) {
	rows, err := db.Query(`SELECT id FROM approval_requests WHERE state='pending' AND expires_unix < ?`, time.Now().Unix())
	if err != nil {
		r.add(dwarn, "db approvals", "query: "+err.Error())
		return
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	if len(out) > 0 {
		r.add(dwarn, "db approvals", fmt.Sprintf("%d pending approval(s) past expiry (sweeper defect): %s", len(out), strings.Join(out, ", ")))
		return
	}
	r.add(dok, "db approvals", "no expired-but-pending approvals")
}

// checkFileRootFacts: the file-root wipe signature. An agent ≥0.9.5 that
// has been connected recently must report either partout.file_root or
// partout.file_root_error; neither means the pre-fix build (fact set at
// construction, wiped by the first facts batch) — the exact bug that made
// every agent look "legacy" on the Files page.
func checkFileRootFacts(db *sql.DB, r *doctorResult) {
	type agentRow struct {
		id       string
		version  string
		lastSeen int64
	}
	agents := map[string]agentRow{}
	rows, err := db.Query(`SELECT id, version, last_seen FROM agents`)
	if err != nil {
		r.add(dwarn, "db file roots", "query: "+err.Error())
		return
	}
	for rows.Next() {
		var a agentRow
		if err := rows.Scan(&a.id, &a.version, &a.lastSeen); err == nil {
			agents[a.id] = a
		}
	}
	rows.Close()

	// Latest facts row per agent (max ts).
	latest := map[string]string{}
	rows, err = db.Query(`SELECT agent_id, ts, data FROM host_facts`)
	if err != nil {
		r.add(dwarn, "db file roots", "query: "+err.Error())
		return
	}
	latestTS := map[string]int64{}
	for rows.Next() {
		var id string
		var ts int64
		var data string
		if err := rows.Scan(&id, &ts, &data); err == nil {
			if ts >= latestTS[id] {
				latestTS[id] = ts
				latest[id] = data
			}
		}
	}
	rows.Close()

	recent := time.Now().Add(-24 * time.Hour).Unix()
	var wiped []string
	for id, a := range agents {
		if a.version == "" || version.Compare(a.version, "0.9.5") < 0 {
			continue // pre-file-root agent (genuinely legacy) or never connected
		}
		if a.lastSeen < recent {
			continue // offline: facts may simply be stale
		}
		data := latest[id]
		if data == "" {
			continue // no facts row at all — enrollment issue, other checks cover
		}
		var m map[string]string
		_ = json.Unmarshal([]byte(data), &m)
		if m["partout.file_root"] == "" && m["partout.file_root_error"] == "" {
			wiped = append(wiped, id+" ("+a.version+")")
		}
	}
	if len(wiped) > 0 {
		r.add(dfail, "db file roots", "connected agent(s) ≥0.9.5 reporting NEITHER file root nor error — the fact-wipe bug (upgrade the agent): "+strings.Join(wiped, ", "))
		return
	}
	r.add(dok, "db file roots", "every connected ≥0.9.5 agent reports its file root state")
}
