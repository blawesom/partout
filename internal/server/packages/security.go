package packages

// M5.1: the periodic security scan. For each connected agent it reuses the
// existing list-updates path (agent-side apt/dnf + OSV CVE correlation) and
// persists the security findings, which the alert engine reads. The scan is
// read-only on the hosts (list-updates performs no mutation) and never
// touches offline agents — they keep their last findings, which the UI
// marks stale.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/store"
)

// maxVulnIDs caps the CVE-id list persisted per finding.
const maxVulnIDs = 8

// SecurityScan runs one scan pass over all connected agents. Returns the
// number of hosts scanned. Per-host failures are logged and skipped (a
// wedged host must not stop the fleet scan).
func (c *Controller) SecurityScan(ctx context.Context) (int, error) {
	if c.extdata == nil {
		return 0, fmt.Errorf("security scan: CVE correlation not configured")
	}
	agents, err := c.st.Agents()
	if err != nil {
		return 0, err
	}
	scanned := 0
	for _, a := range agents {
		if a.State != "connected" {
			continue // offline hosts keep their last findings
		}
		if err := ctx.Err(); err != nil {
			return scanned, err
		}
		if err := c.scanAgent(ctx, a.ID); err != nil {
			if c.log != nil {
				c.log.Printf("security scan: %s: %v", a.ID, err)
			}
			continue
		}
		scanned++
	}
	return scanned, nil
}

func (c *Controller) scanAgent(ctx context.Context, agentID string) error {
	updates, err := c.ListUpdates(ctx, agentID, Actor{Principal: "security-scan", Role: "admin"})
	if err != nil {
		return err
	}
	var findings []store.SecurityFinding
	security := 0
	for _, u := range updates {
		if !u.IsSecurity {
			continue
		}
		security++
		f := store.SecurityFinding{
			AgentID:   agentID,
			Pkg:       u.Name,
			Installed: u.Installed,
			Available: u.Available,
			VulnCount: int(u.VulnCount),
			MaxCVSS:   cvssFromLabel(u.MaxSeverity),
			VulnIDs:   VulnIDsFromList(u.VulnIds),
		}
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].MaxCVSS != findings[j].MaxCVSS {
			return findings[i].MaxCVSS > findings[j].MaxCVSS
		}
		return findings[i].Pkg < findings[j].Pkg
	})
	return c.st.ReplaceSecurityFindings(agentID, findings, store.SecurityScanMeta{
		AgentID:         agentID,
		ScannedAt:       time.Now().Unix(),
		UpdatesTotal:    len(updates),
		SecurityUpdates: security,
	})
}

// RunSecurityLoop runs an initial pass shortly after boot, then scans on
// the given interval until the context is cancelled.
func (c *Controller) RunSecurityLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		delay := 30 * time.Second // let agents connect first
		if err := sleepCtx(ctx, delay); err != nil {
			return
		}
		if _, err := c.SecurityScan(ctx); err != nil && c.log != nil {
			c.log.Printf("security scan: initial pass: %v", err)
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := c.SecurityScan(ctx); err != nil && c.log != nil {
					c.log.Printf("security scan: %v", err)
				}
			}
		}
	}()
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// cvssFromLabel maps the maxCVSS severity label back to a representative
// CVSS score for storage (the alert engine buckets on the same thresholds).
func cvssFromLabel(label string) float64 {
	switch label {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.0
	default:
		return 0
	}
}

// VulnIDsFromList caps and joins a CVE/advisory id list for storage.
func VulnIDsFromList(ids []string) string {
	if len(ids) > maxVulnIDs {
		ids = ids[:maxVulnIDs]
	}
	return strings.Join(ids, ",")
}

// SecurityScanAgent runs one scan pass for a single agent (the CLI's
// `cve scan --agent` filter — it used to be accepted and silently ignored).
func (c *Controller) SecurityScanAgent(ctx context.Context, agentID string) error {
	if c.extdata == nil {
		return fmt.Errorf("security scan: CVE correlation not configured")
	}
	return c.scanAgent(ctx, agentID)
}
