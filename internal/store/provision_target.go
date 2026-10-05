package store

import (
	"database/sql"
	"fmt"
)

// ProvisionTargetForAgent returns the SSH target (user@host) of the most
// recent successful provision run for an agent — the natural rejoin target
// for the join-mode migration flow (v0.9.12 layout → join re-provision →
// rollout): the fleet's own provisioning history knows where each agent
// lives. Returns ("", nil) when the agent has no successful run.
func (s *Store) ProvisionTargetForAgent(agentID string) (string, error) {
	row := s.db.QueryRow(
		`SELECT host FROM provision_runs
		 WHERE agent_id=? AND state='connected'
		 ORDER BY updated DESC LIMIT 1`, agentID)
	var host string
	if err := row.Scan(&host); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("store: provision target for %s: %w", agentID, err)
	}
	return host, nil
}
