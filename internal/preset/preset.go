// Package preset seeds sensible fleet-management defaults on first boot.
//
// A fresh server should not be a blank slate: customers immediately get a
// safety net — a few high-confidence deny rules (the things that are never
// right) and the standard observability alert rules. Every seeded row is
// named `default-*` and created by `partout-preset`, so it is recognizable
// in the UI and in the audit trail, and may be edited or deleted freely.
//
// Apply is idempotent and additive: it creates only what is missing (by
// name) and never modifies or deletes user rows — so re-applying after a
// restore or an accidental delete restores just the missing defaults
// without clobbering user edits to the rest.
package preset

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/policy"
	"github.com/blawesom/partout/internal/server/observe"
	"github.com/blawesom/partout/internal/store"
)

const createdBy = "partout-preset"

// DefaultPolicy is one seeded policy rule.
type DefaultPolicy struct {
	Name     string
	Match    policy.Match
	Effect   string
	Priority int
}

// DefaultAlert is one seeded alert rule.
type DefaultAlert struct {
	Name       string
	Kind       string
	Selector   string
	Thresholds string
	Severity   string
}

// Policies is the fleet safety net: high-confidence "never right" denies +
// one approval gate for host reboot. All scoped to every host, exec class.
var Policies = []DefaultPolicy{
	{
		Name: "default-deny-rm-rf-root",
		Match: policy.Match{
			Hosts: "all", Actions: []string{policy.ActionExec},
			// rm with any flags, targeting exactly / (or /*). `rm -rf /tmp`
			// does not match; `sudo rm -r -f /` and `--no-preserve-root` do.
			CommandRegex: `(^|\s)rm\s+(?:-[a-zA-Z]+\s+|--no-preserve-root\s+)+/(\*|\s|$)`,
		},
		Effect: policy.EffectDeny,
	},
	{
		Name: "default-deny-disk-wipe",
		Match: policy.Match{
			Hosts: "all", Actions: []string{policy.ActionExec},
			CommandRegex: `(^|[\s|;&])(dd\s+[^|;&]*\bof=/dev/|mkfs(\.[a-z0-9]+)?(\s|$)|wipefs\b|shred\s+[^|;&]*/dev/)`,
		},
		Effect: policy.EffectDeny,
	},
	{
		Name: "default-deny-auth-file-tamper",
		Match: policy.Match{
			Hosts: "all", Actions: []string{policy.ActionExec},
			// Shell-redirect writes to the account/auth files. Managed-editing
			// tools (visudo, chpasswd, useradd) are left to policy discretion.
			CommandRegex: `>>?\s*/etc/(passwd|shadow|sudoers)`,
		},
		Effect: policy.EffectDeny,
	},
	{
		Name: "default-require-approval-reboot",
		Match: policy.Match{
			Hosts: "all", Actions: []string{policy.ActionExec},
			// Word must sit in command position (start/whitespace/pipe
			// preceded) and must not be a path or filename fragment
			// (no dot/underscore/alnum/slash after): "reboot.log" and
			// "cat /reboot" do not match; "systemctl reboot" does.
			CommandRegex: `(^|[\s|;&])(reboot|shutdown|halt|poweroff)([^a-zA-Z0-9._/]|$)`,
		},
		Effect: policy.EffectRequireApproval,
	},
}

// Alerts is the standard observability net (thresholds = the engine's
// documented defaults, so rule behaviour matches the docs).
var Alerts = []DefaultAlert{
	{Name: "default-service-failed", Kind: observe.KindServiceFailed, Selector: "all",
		Thresholds: `{"service_failed_minutes":5}`, Severity: "critical"},
	{Name: "default-service-restarting", Kind: observe.KindServiceRestarting, Selector: "all",
		Thresholds: `{"service_restart_rate_per_hour":10}`, Severity: "warning"},
	{Name: "default-cert-expiring", Kind: observe.KindCertExpiring, Selector: "all",
		Thresholds: `{"cert_days_remaining":30}`, Severity: "warning"},
	{Name: "default-config-invalid", Kind: observe.KindConfigInvalid, Selector: "all",
		Thresholds: `{}`, Severity: "critical"},
	{Name: "default-config-drift", Kind: observe.KindConfigDrift, Selector: "all",
		Thresholds: `{"config_drift_tolerance":0}`, Severity: "info"},
	{Name: "default-update-run", Kind: observe.KindUpdateRun, Selector: "all",
		Thresholds: `{"status":"paused_failure,failed"}`, Severity: "warning"},
	{Name: "default-update-drift", Kind: observe.KindUpdateDrift, Selector: "all",
		Thresholds: `{"min_drifted":1}`, Severity: "warning"},
	{Name: "default-security-updates", Kind: observe.KindSecurityUpdates, Selector: "all",
		Thresholds: `{"min_severity":"high","min_count":1}`, Severity: "warning"},
}

// slug turns a default name into a deterministic row id
// ("default-deny-rm-rf-root" → "preset_deny_rm_rf_root").
func slug(name string) string {
	n := strings.TrimPrefix(name, "default-")
	return "preset_" + strings.ReplaceAll(n, "-", "_")
}

// validatePolicies compiles every preset regex so a bad pattern fails loudly
// at seed time (and in tests), not on the first denied command.
func validatePolicies() error {
	for _, p := range Policies {
		if p.Match.CommandRegex == "" {
			continue
		}
		if _, err := regexp.Compile(p.Match.CommandRegex); err != nil {
			return fmt.Errorf("preset: bad regex in %s: %w", p.Name, err)
		}
	}
	return nil
}

// Apply idempotently seeds every missing default. Returns the names it
// created. Existing rows (by name) are left untouched.
func Apply(st *store.Store) (policies, alerts []string, err error) {
	if err := validatePolicies(); err != nil {
		return nil, nil, err
	}

	existingP, err := existingPolicyNames(st)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range Policies {
		if existingP[p.Name] {
			continue
		}
		id := "pol_" + slug(p.Name)
		if err := st.CreatePolicy(id, p.Name, p.Match, p.Effect, p.Priority); err != nil {
			return nil, nil, fmt.Errorf("preset: create policy %s: %w", p.Name, err)
		}
		policies = append(policies, p.Name)
	}

	existingA, err := existingAlertNames(st)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Unix()
	for _, a := range Alerts {
		if existingA[a.Name] {
			continue
		}
		if err := st.CreateAlertRule(&store.AlertRule{
			ID: "alr_" + slug(a.Name), Name: a.Name, Kind: a.Kind,
			Selector: a.Selector, Thresholds: a.Thresholds, Severity: a.Severity,
			Enabled: true, CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return nil, nil, fmt.Errorf("preset: create alert rule %s: %w", a.Name, err)
		}
		alerts = append(alerts, a.Name)
	}
	return policies, alerts, nil
}

type rowStatus struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	ID      string `json:"id,omitempty"`
	Effect  string `json:"effect,omitempty"` // policies
	Kind    string `json:"kind,omitempty"`   // alert rules
}

// Status reports, for every preset row, whether it exists on this server.
func Status(st *store.Store) (out map[string][]rowStatus, err error) {
	out = map[string][]rowStatus{}

	pr, err := st.ListPolicies()
	if err != nil {
		return nil, err
	}
	byName := map[string]store.PolicyRule{}
	for _, p := range pr {
		byName[p.Name] = p
	}
	for _, p := range Policies {
		rs := rowStatus{Name: p.Name, Effect: p.Effect}
		if row, ok := byName[p.Name]; ok {
			rs.Present, rs.ID = true, row.ID
		}
		out["policies"] = append(out["policies"], rs)
	}

	ar, err := st.ListAlertRules()
	if err != nil {
		return nil, err
	}
	byNameA := map[string]*store.AlertRule{}
	for _, a := range ar {
		byNameA[a.Name] = a
	}
	for _, a := range Alerts {
		rs := rowStatus{Name: a.Name, Kind: a.Kind}
		if row, ok := byNameA[a.Name]; ok {
			rs.Present, rs.ID = true, row.ID
		}
		out["alert_rules"] = append(out["alert_rules"], rs)
	}
	return out, nil
}

func existingPolicyNames(st *store.Store) (map[string]bool, error) {
	pr, err := st.ListPolicies()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, p := range pr {
		out[p.Name] = true
	}
	return out, nil
}

func existingAlertNames(st *store.Store) (map[string]bool, error) {
	ar, err := st.ListAlertRules()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, a := range ar {
		out[a.Name] = true
	}
	return out, nil
}
