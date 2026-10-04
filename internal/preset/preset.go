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

	"github.com/blawesom/partout/internal/agent/elevate"
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
// Result names everything a single Apply created.
type Result struct {
	Policies          []string // deny/approval policy rules
	Alerts            []string // alert rules
	ElevationPolicies []string // elevation policy documents (server store)
	Tasks             []string // task templates
	Jobs              []string // scheduled jobs (seeded paused)
}

// ElevationPolicyDef is one seeded elevation policy document.
type ElevationPolicyDef struct {
	Name        string
	Description string
	RulesJSON   string // canonical rules array
}

// Tasks is the seeded ready-to-run library: the task templates a first-day
// fleet needs (the daily package update is THE fleet job).
var Tasks = []struct {
	Name        string
	Description string
	StepsJSON   string
}{
	{
		Name:        "default-daily-updates",
		Description: "Apply all available package updates (apt/dnf aware, elevated per the host's elevation policy)",
		StepsJSON:   `[{"kind":"upgrade","name":"apply all package updates"}]`,
	},
}

// Jobs are seeded PAUSED (ready to apply — the operator flips them on; a
// job that auto-updates a fleet must be a deliberate act).
var Jobs = []struct {
	Name        string
	TaskName    string
	Cron        string
	Selector    string
	Description string
}{
	{
		Name:        "default-daily-package-updates",
		TaskName:    "default-daily-updates",
		Cron:        "30 4 * * *",
		Selector:    "all",
		Description: "Daily package updates across the fleet (seeded paused — enable when ready)",
	},
}

// ElevationPolicies are the seeded ready-to-apply privilege profiles. The
// baseline grants exactly what a first-day fleet needs — package updates
// (both the task step and the packages-apply command forms, apt and dnf),
// service control for the standard fleet units, hostname changes and a
// bare reboot — nothing more. Validated in the field (FIELD-REPORT
// 2026-10-04).
var ElevationPolicies = []ElevationPolicyDef{
	{
		Name: "default-baseline",
		Description: "Day-1 fleet baseline: package updates and installs (apt + dnf, task steps and packages-apply forms), " +
			"systemctl on standard fleet units, hostnamectl set-hostname, bare reboot. " +
			"Apply at provisioning (provision new --elevate) or with your config management; " +
			"edit or clone for tighter scopes.",
		RulesJSON: `[
  {"allow":"apt-get|dnf","args":["-y","upgrade"]},
  {"allow":"apt-get|dnf","args":["-y","install","*"]},
  {"allow":"apt-get|dnf","args":["-q","makecache"]},
  {"allow":"apt-get","args":["-qq","update"]},
  {"allow":"apt-get","args":["-o","Dpkg::Progress-Focus=full","-y","-o","Dpkg::Options::=--force-confdef","-o","Dpkg::Options::=--force-confold","upgrade"]},
  {"allow":"dnf","args":["check-update"]},
  {"allow":"hostnamectl","args":["set-hostname","*"]},
  {"allow":"systemctl","verbs":["status","show","start","stop","restart","reload","try-restart","enable","disable","is-active","is-enabled"],"units":["partout-*","fail2ban*","sshd*","nginx*","haproxy*","caddy*"]},
  {"allow":"reboot"}
]`,
	},
}

func Apply(st *store.Store) (res Result, rerr error) {
	if err := validatePolicies(); err != nil {
		return res, err
	}

	existingP, err := existingPolicyNames(st)
	if err != nil {
		return res, err
	}
	for _, p := range Policies {
		if existingP[p.Name] {
			continue
		}
		id := "pol_" + slug(p.Name)
		if err := st.CreatePolicy(id, p.Name, p.Match, p.Effect, p.Priority); err != nil {
			return res, fmt.Errorf("preset: create policy %s: %w", p.Name, err)
		}
		res.Policies = append(res.Policies, p.Name)
	}

	existingA, err := existingAlertNames(st)
	if err != nil {
		return res, err
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
			return res, fmt.Errorf("preset: create alert rule %s: %w", a.Name, err)
		}
		res.Alerts = append(res.Alerts, a.Name)
	}

	// Elevation policies (the ready-to-apply privilege profiles the
	// provisioner and wizard offer). Validated before insert.
	for _, ep := range ElevationPolicies {
		if existing, _ := st.ElevationPolicy(ep.Name); existing != nil {
			continue
		}
		pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + ep.RulesJSON + `}`))
		if err != nil {
			return res, fmt.Errorf("preset: elevation policy %s invalid: %w", ep.Name, err)
		}
		if err := st.CreateElevationPolicy(&store.ElevationPolicy{
			Name: ep.Name, Description: ep.Description,
			RulesJSON: ep.RulesJSON, PolicySHA: pol.PolicyHash(),
		}); err != nil {
			return res, fmt.Errorf("preset: create elevation policy %s: %w", ep.Name, err)
		}
		res.ElevationPolicies = append(res.ElevationPolicies, ep.Name)
	}

	// Tasks (seeded library). Skips by name.
	for _, td := range Tasks {
		if existing, _ := st.TaskByName(td.Name); existing != nil {
			continue
		}
		taskID := "task_" + slug(td.Name)
		if err := st.CreateTask(&store.Task{ID: taskID, Name: td.Name, Description: td.Description}); err != nil {
			return res, fmt.Errorf("preset: create task %s: %w", td.Name, err)
		}
		if err := st.UpsertTaskVersion(&store.TaskVersion{TaskID: taskID, Version: 1, StepsJSON: td.StepsJSON}); err != nil {
			return res, fmt.Errorf("preset: create task version %s: %w", td.Name, err)
		}
		res.Tasks = append(res.Tasks, td.Name)
	}

	// Jobs (seeded PAUSED: ready to apply, running nothing until the
	// operator enables them). Assignments are pushed by the jobs
	// controller's reconcile loop once enabled.
	for _, jd := range Jobs {
		if existing, _ := st.GetJobByName(jd.Name); existing != nil {
			continue
		}
		task, err := st.TaskByName(jd.TaskName)
		if err != nil || task == nil {
			return res, fmt.Errorf("preset: job %s: task %s missing", jd.Name, jd.TaskName)
		}
		if err := st.CreateJob(&store.Job{
			ID: "job_" + slug(jd.Name), Name: jd.Name,
			TaskID: task.ID, TaskVersion: 1, Cron: jd.Cron,
			Selector: jd.Selector, Enabled: false,
		}); err != nil {
			return res, fmt.Errorf("preset: create job %s: %w", jd.Name, err)
		}
		res.Jobs = append(res.Jobs, jd.Name)
	}
	return res, nil
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
