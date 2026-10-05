// Package factscollect implements structured fact collectors for the observe
// layer (M5, R18–R20). Collectors run on the agent and upload JSON blobs
// via the OBSERVE_FACTS gRPC envelope to the server, which upserts them into
// host_facts (architecture §7.2).
package factscollect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/agent/elevate"
)

// Kind identifies the observation domain.
type Kind string

const (
	KindServices Kind = "services"
	KindConfigs  Kind = "configs"
	KindCerts    Kind = "certs"
)

// Subprocess timeouts. Every collector shells out; without a bound a wedged
// systemctl/openssl/haproxy blocks the agent's single collection slot and the
// observe cadence stalls indefinitely (subsequent ticks are skipped).
const (
	systemctlTimeout  = 20 * time.Second
	configExecTimeout = 20 * time.Second
)

// Facts is the top-level facts blob the server stores as a key in host_facts.
type Facts struct {
	ServicesDetailed *ServiceFacts `json:"services_detailed,omitempty"` // R18
	Configs          *ConfigFacts  `json:"configs,omitempty"`           // R19
	Certificates     *CertFacts    `json:"certificates,omitempty"`      // R20
}

// Collect runs all collectors and returns the merged Facts blob, or nil if
// all collectors return empty (no structured facts to upload).
func Collect(cfg *Config) *Facts {
	if cfg == nil {
		cfg = &Config{}
	}
	f := &Facts{}
	if sf := collectServices(cfg); sf != nil {
		f.ServicesDetailed = sf
	}
	if cf := collectConfigs(cfg); cf != nil {
		f.Configs = cf
	}
	if ce := collectCerts(cfg); ce != nil {
		f.Certificates = ce
	}
	if f.ServicesDetailed == nil && f.Configs == nil && f.Certificates == nil {
		return nil
	}
	return f
}

// Config controls collector behaviour.
type Config struct {
	// ServiceLabels: comma-separated operator labels for custom unit
	// identification (PARTOUT_SERVICE_LABELS). Empty = units from
	// /etc/systemd/system/* are auto-marked as custom.
	ServiceLabels string
	// CertPaths: comma-separated paths for cert discovery, in addition to
	// defaults (/etc/ssl/, /etc/pki/tls/).
	CertPaths string
	// CAPath: trust bundle used for `openssl verify` (PARTOUT_CERT_CA). Empty
	// = resolve from the standard system locations; when none is found, chain
	// verification is skipped and reported as unchecked rather than invalid.
	CAPath string
	// NginxConf / HaproxyConf / CaddyConf: service config locations whose
	// referenced certificate files are collected and labeled (M5, R20).
	// Empty = standard locations (/etc/nginx/nginx.conf, /etc/haproxy/
	// haproxy.cfg, /etc/caddy/Caddyfile [+ caddy.json]).
	NginxConf   string
	HaproxyConf string
	CaddyConf   string
	// ObserveFactsInterval: seconds between uploads (PARTOUT_OBSERVE_FACTS_INTERVAL).
	ObserveFactsInterval int
	// Elevate: host-level elevation mode (PRD Decision 3). In sudo mode,
	// config-file reads that fail with a permission error retry via
	// `sudo -n cat` (scoped by the host's sudoers file, or by the loaded
	// policy when one is set) so root-owned configs (e.g. haproxy.cfg)
	// still produce facts.
	Elevate elevate.Mode
	// Elevation: the loaded elevation policy (PARTOUT_ELEVATION_POLICY).
	// nil = legacy behavior (the hand-installed drop-in decides). When set
	// and the mode is sudo, agent-internal privileged commands (config
	// validation, elevated reads) run only when a rule matches.
	Elevation *elevate.Policy
}

// Fill returns a config with defaults filled in.
func (c *Config) Fill() *Config {
	if c == nil {
		c = &Config{}
	}
	if c.ObserveFactsInterval <= 0 {
		c.ObserveFactsInterval = 300
	}
	return c
}

// ---- Service facts (R18) ------------------------------------------------

// ServiceFacts carries systemd unit facts for the server to aggregate and
// alert on (PRD §5.1, arch §7.2).
type ServiceFacts struct {
	Units []UnitFact `json:"units"`
}

// UnitFact is one systemd unit's state, dependencies, enablement, and labels.
type UnitFact struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	State         string   `json:"state"`
	SubState      string   `json:"sub_state"`
	Enabled       bool     `json:"enabled"`
	WantedBy      []string `json:"wanted_by,omitempty"`
	RequiredBy    []string `json:"required_by,omitempty"`
	After         []string `json:"after,omitempty"`
	RestartPolicy string   `json:"restart_policy,omitempty"`
	MemoryCurrent uint64   `json:"memory_current,omitempty"`
	CPUUsageSec   string   `json:"cpu_usage_sec,omitempty"`
	NRestarts     int64    `json:"n_restarts,omitempty"`
	// NRestartsKnown distinguishes a genuine counter value (including 0) from
	// a failed `systemctl show` (where NRestarts is simply absent). Without
	// it the engine cannot tell "no datum" from "counter reset to 0" and
	// would treat a transient collector failure as a spike of restarts.
	NRestartsKnown bool   `json:"n_restarts_known,omitempty"`
	LastExitCode   int    `json:"last_exit_code,omitempty"`
	LastExitStatus string `json:"last_exit_status,omitempty"`
	// Description is the unit's human summary line from the [Service]/[Unit]
	// Description= field — the first thing an operator wants when scanning
	// a wall of unit names.
	Description string `json:"description,omitempty"`
	// MainPID is 0 when the unit is not running.
	MainPID int64 `json:"main_pid,omitempty"`
	// FragmentPath is where the unit file lives (distro package vs
	// /etc/systemd/system drop-in — hints at who owns the config).
	FragmentPath string `json:"fragment_path,omitempty"`
	// ExecMainStartTimestamp is systemd's formatted "last start" ("" when
	// the unit has never run).
	ExecMainStartTimestamp string `json:"exec_main_start_timestamp,omitempty"`
	// Result is systemd's last-run verdict (success|exit-code|signal|
	// core-dump|timeout|start-limit-hit|soft-restart|watchdog; "" when the
	// unit has never run).
	Result string   `json:"result,omitempty"`
	Labels []string `json:"labels,omitempty"`
}

// collectServices runs `systemctl list-units` + `systemctl show` to collect
// full unit state for custom units (PRD Decision 13: custom units only in
// output — units from /etc/systemd/system/* or labelled by operator).
//
// Refresh: 5 minutes (arch §7.2).
func collectServices(cfg *Config) *ServiceFacts {
	cfg = cfg.Fill()
	units, err := listUnits()
	if err != nil || len(units) == 0 {
		return nil
	}
	facts := &ServiceFacts{Units: make([]UnitFact, 0, len(units))}
	for _, u := range units {
		f := unitDetail(u)
		if isCustomUnit(u, cfg.ServiceLabels) {
			facts.Units = append(facts.Units, f)
		}
	}
	if len(facts.Units) == 0 {
		return nil
	}
	return facts
}

// listUnits runs systemctl list-units and returns unit names that are
// active, failed, stopped (inactive), or in a transitional state. Inactive
// is included because "enabled but not running, not failing" is a real
// triage case (stopped/masked/missed-start); the Enabled column makes those
// rows legible. Units that were never started are not loaded into the
// runtime, so they do not appear (they are unit-*files*, not units).
func listUnits() ([]string, error) {
	out, err := runOutput(systemctlTimeout, "systemctl", "list-units", "--no-pager", "--no-legend",
		"--type=service", "--state=active", "--state=failed", "--state=inactive",
		"--state=activating", "--state=deactivating", "--state=auto-restarting")
	if err != nil {
		return nil, err
	}
	return parseUnitList(out), nil
}

// parseUnitList extracts unit names from `systemctl list-units` output,
// stripping the .service suffix for consistency.
func parseUnitList(out string) []string {
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		// systemctl prints a status glyph (●, ○) as the first field on some
		// systemd versions; the unit name is the first field that carries a
		// known unit-type suffix. Summary lines ("N loaded units listed.")
		// and header rows carry none, so they are skipped.
		name := ""
		for _, f := range fields {
			if isUnitName(f) {
				name = f
				break
			}
		}
		if name == "" {
			continue
		}
		names = append(names, strings.TrimSuffix(name, ".service"))
	}
	return names
}

// isUnitName reports whether s looks like a systemd unit name (carries a
// known unit-type suffix).
func isUnitName(s string) bool {
	for _, ext := range []string{".service", ".target", ".timer", ".socket", ".path", ".mount"} {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

// unitDetail runs systemctl show for a unit and parses the key=value output.
func unitDetail(name string) UnitFact {
	out, err := runOutput(systemctlTimeout, "systemctl", "show", name,
		"--property=Type,State,SubState,ActiveState,UnitFileState,Requires,RequiredBy,Wants,WantedBy,After,Before,Restart,MemoryCurrent,CPUSec,NRestarts,ExecMainStatus,RestartForceExitStatus,Description,MainPID,FragmentPath,ExecMainStartTimestamp,Result")
	if err != nil {
		return UnitFact{Name: name}
	}
	return parseUnitShow(name, out)
}

// parseUnitShow parses `systemctl show` key=value output into a UnitFact.
// Split out from unitDetail so the mapping is unit-testable without systemd.
func parseUnitShow(name, out string) UnitFact {
	f := UnitFact{Name: name}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "Type":
			f.Type = v
		case "ActiveState":
			// ActiveState is the active/inactive/failed/activating state that
			// alert rules match on (`state == "failed"`). `State` is the *load*
			// state (loaded/not-found) and is not emitted by `systemctl show`
			// for these properties, so mapping it here left state empty.
			f.State = v
		case "SubState":
			f.SubState = v
		case "UnitFileState":
			f.Enabled = v == "enabled" || v == "enabled-runtime" || v == "static"
		case "WantedBy":
			f.WantedBy = splitSpaceList(v)
		case "RequiredBy":
			f.RequiredBy = splitSpaceList(v)
		case "After":
			f.After = splitSpaceList(v)
		case "Restart":
			f.RestartPolicy = v
		case "MemoryCurrent":
			if n, err := parseUint64(v); err == nil {
				f.MemoryCurrent = n
			}
		case "CPUSec":
			f.CPUUsageSec = v
		case "NRestarts":
			// systemd's restart counter for the unit's main process since the
			// unit was (re)started; feeds the service_restarting alert rule
			// (M6.1) as a rate computed server-side across ticks.
			if n, err := parseUint64(v); err == nil {
				f.NRestarts = int64(n)
				f.NRestartsKnown = true
			}
		case "ExecMainStatus":
			// The unit's last exit status. Empty for units that have never
			// run; "[not set]" is not emitted for this property, but guard
			// anyway. Do not use RestartForceExitStatus here: that is the
			// configured restart trigger list, not the observed status.
			f.LastExitStatus = v
			f.LastExitCode = parseExitCode(v)
		case "Result":
			// systemd's one-word verdict for the last run: success,
			// exit-code, signal, core-dump, timeout, start-limit-hit,
			// soft-restart, watchdog. This is the operator-facing "why did
			// it fail" (ExecMainStatus is just a raw number).
			f.Result = v
		case "Description":
			f.Description = v
		case "MainPID":
			if n, err := parseUint64(v); err == nil {
				f.MainPID = int64(n)
			}
		case "FragmentPath":
			f.FragmentPath = v
		case "ExecMainStartTimestamp":
			if v != "Mon 1970-01-01 00:00:00 UTC" { // never-run sentinel
				f.ExecMainStartTimestamp = v
			}
		}
	}
	return f
}

// unitFileDirs are the search paths consulted for an operator-managed unit
// file. /etc/systemd/system is the admin-owned tree (PRD Decision 13: custom
// units only); the XDG user tree covers rootless deployments.
func unitFileDirs() []string {
	dirs := []string{"/etc/systemd/system", "/run/systemd/system"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", "systemd", "user"))
	}
	return dirs
}

// isCustomUnit reports whether a unit is operator-managed (include in the
// custom unit set, PRD Decision 13):
//
//   - the unit name matches an operator-supplied label, or
//   - a unit file exists under a unitFileDirs() path, or
//   - a drop-in directory for the unit exists there (<unit>.d/override.conf).
//
// labelList is the raw PARTOUT_SERVICE_LABELS value (comma-separated).
// Search dirs are injectable so the logic is unit-testable off-systemd.
func isCustomUnit(name, labelList string) bool {
	return isCustomUnitIn(name, labelList, unitFileDirs())
}

func isCustomUnitIn(name, labelList string, dirs []string) bool {
	for _, l := range splitList(labelList) {
		if l == name {
			return true
		}
	}
	// Strip any unit-type suffix: `systemctl show` takes the bare name for
	// .service units, and the file on disk may be any unit type.
	bare := name
	for _, ext := range []string{".service", ".timer", ".socket", ".target", ".mount", ".path"} {
		bare = strings.TrimSuffix(bare, ext)
	}
	for _, dir := range dirs {
		// A direct unit file of any type, and the drop-in directory.
		if matches, _ := filepath.Glob(filepath.Join(dir, bare+".*")); len(matches) > 0 {
			return true
		}
		if st, err := os.Stat(filepath.Join(dir, bare+".d")); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

// ---- Config facts (R19) --------------------------------------------------

// ConfigFacts carries webservice config facts (haproxy, nginx).
type ConfigFacts struct {
	HAProxy *HAProxyConfig `json:"haproxy,omitempty"`
	Nginx   *NginxConfig   `json:"nginx,omitempty"`
}

// HAProxyConfig is haproxy's config fact set.
type HAProxyConfig struct {
	Present      bool   `json:"present"`
	Version      string `json:"version"`
	ConfigFile   string `json:"config_file"`
	ConfigSHA256 string `json:"config_sha256"`
	ConfigValid  bool   `json:"config_valid"`
	// ConfigValidated distinguishes "the validator ran and said invalid"
	// from "validation was blocked" (root-only config or includes, no
	// authorized elevation). nil = older agent (pre-0.9.14); false = blocked
	// (ConfigValid is NOT evidence — the alert engine must not fire); true =
	// the validator ran to a definitive answer (ConfigValid is meaningful).
	ConfigValidated *bool `json:"config_validated,omitempty"`
	// ConfigError carries the validator's (haproxy -c) output when
	// ConfigValid is false, so the UI can explain *why* instead of just
	// showing a red badge. Bounded by capConfigError. Empty when the
	// validator never ran (ConfigReadable == false, not authorized).
	ConfigError string `json:"config_error,omitempty"`
	// ConfigReadable: the agent user can open the config file directly.
	// nil = unknown (older agent, or file absent); false = root-only file —
	// the config is NOT necessarily invalid, the agent just cannot see it
	// (the UI must say so instead of mislabeling it invalid); true = readable
	// (validation ran as the agent user or via an authorized elevation).
	ConfigReadable *bool          `json:"config_readable,omitempty"`
	Backends       []BackendFact  `json:"backends"`
	Listeners      []ListenerFact `json:"listeners"`
}

// NginxConfig is nginx's config fact set.
type NginxConfig struct {
	Present      bool   `json:"present"`
	Version      string `json:"version"`
	ConfigFile   string `json:"config_file"`
	ConfigSHA256 string `json:"config_sha256"`
	ConfigValid  bool   `json:"config_valid"`
	// ConfigValidated: see HAProxyConfig.ConfigValidated.
	ConfigValidated *bool `json:"config_validated,omitempty"`
	// ConfigError: nginx -t output on failure (see HAProxyConfig).
	ConfigError string `json:"config_error,omitempty"`
	// ConfigReadable: see HAProxyConfig.ConfigReadable.
	ConfigReadable *bool       `json:"config_readable,omitempty"`
	Vhosts         []VHostFact `json:"vhosts"`
}

// BackendFact is one haproxy backend's server state.
type BackendFact struct {
	Name    string `json:"name"`
	Servers int64  `json:"servers"`
	Active  int64  `json:"active"`
}

// ListenerFact is one haproxy frontend/listener.
type ListenerFact struct {
	Port int    `json:"port"`
	Mode string `json:"mode"` // http or https
	TLS  string `json:"tls"`  // cert path if TLS
}

// VHostFact is one nginx virtual host.
type VHostFact struct {
	ServerName string `json:"server_name"`
	Port       int    `json:"port"`
	TLS        bool   `json:"tls"`
	TLSCert    string `json:"tls_cert"`
	Root       string `json:"root"`
	Upstream   string `json:"upstream"`
}

// collectConfigs runs haproxy -c and nginx -t for validation, and extracts
// topology from the config files (lightweight regex/line parsing).
// Refresh: 15 min or on file mtime change (arch §7.2).
func collectConfigs(cfg *Config) *ConfigFacts {
	cfg = cfg.Fill()
	f := &ConfigFacts{}
	if hf := collectHAProxy(cfg); hf != nil {
		f.HAProxy = hf
	}
	if nf := collectNginx(cfg); nf != nil {
		f.Nginx = nf
	}
	if f.HAProxy == nil && f.Nginx == nil {
		return nil
	}
	return f
}

// probeReadable reports whether the agent user can open path. A var so
// tests can stub EACCES without chmod acrobatics.
var probeReadable = func(path string) error {
	f, err := os.Open(path)
	if err == nil {
		f.Close()
	}
	return err
}

// collectHAProxy runs haproxy -c for validation and parses topology.
func collectHAProxy(cfg *Config) *HAProxyConfig {
	cfg = cfg.Fill()
	if _, err := exec.LookPath("haproxy"); err != nil {
		return nil
	}
	cfgPath := orDefault(cfg.HaproxyConf, "/etc/haproxy/haproxy.cfg")
	if _, err := os.Stat(cfgPath); err != nil {
		return nil
	}
	h := &HAProxyConfig{
		Present:    true,
		ConfigFile: cfgPath,
	}
	// Readability first: a root-only cfg is not evidence of an invalid
	// config — running the validator as the agent user would just report
	// "Permission denied" and the UI would mislabel a healthy service.
	readable := probeReadable(cfgPath) == nil
	h.ConfigReadable = &readable

	// Validate: haproxy -c (bounded: a wedged binary must not stall
	// collection) — capture the output on failure so the UI can explain
	// the invalid state.
	validateArgs := []string{"-c", "-f", cfgPath}
	// validated starts false (blocked): it flips to true only when the
	// validator runs to a definitive answer — as the agent user, or via
	// an authorized elevation. A root-only config (or root-only includes)
	// without an authorized elevation leaves it false: ConfigValid=false is
	// then NOT evidence of an invalid config, and the alert engine must not
	// fire (field report: ccc.laplane.net — 12 false config_invalid alerts).
	validated := false
	defer func() { h.ConfigValidated = &validated }()
	runValidator := func(elevated bool) (string, error) {
		if !elevated {
			return runOutput(configExecTimeout, "haproxy", validateArgs...)
		}
		n, a := cfg.Elevate.Run("haproxy", validateArgs...)
		return runOutput(configExecTimeout, n, a...)
	}
	switch {
	case readable:
		out, err := runValidator(false)
		switch {
		case err == nil:
			h.ConfigValid, validated = true, true
		case isPermissionFailure(out) && authorizedElevated(cfg, "haproxy", validateArgs):
			// The agent user couldn't read the config (or an include) —
			// retry elevated. A permission failure is not evidence of an
			// invalid config (field report: root-only conf.d includes).
			if eout, eerr := runValidator(true); eerr == nil {
				h.ConfigValid, validated = true, true
			} else {
				h.ConfigError, validated = capConfigError(eout), true
			}
		case isPermissionFailure(out):
			// Permission failure, no authorized elevation: blocked, not
			// invalid. ConfigError stays empty — the alert engine treats
			// an empty error as "never validated" and must not fire.
		default:
			h.ConfigError, validated = capConfigError(out), true
		}
	case cfg.Elevation != nil && authorizedElevated(cfg, "haproxy", validateArgs):
		// Not directly readable, but the policy authorizes elevated
		// validation: the validator runs as root and the config can still
		// be proven (in)valid. ConfigReadable stays false — the file
		// itself is root-only.
		if out, err := runValidator(true); err == nil {
			h.ConfigValid, validated = true, true
		} else {
			h.ConfigError, validated = capConfigError(out), true
		}
	default:
		// Unreadable and not authorized: skip validation entirely and let
		// the UI say "not readable" instead of "invalid".
	}
	// Version: haproxy -v
	if out, err := runOutput(configExecTimeout, "haproxy", "-v"); err == nil {
		h.Version = extractVersion(out)
	}
	// Config SHA256
	if sha, err := fileSHA256(cfgPath, cfg.Elevate, cfg.Elevation); err == nil {
		h.ConfigSHA256 = sha
	}
	// Topology: lightweight parsing
	h.Backends, h.Listeners = parseHAProxyTopology(cfgPath, cfg.Elevate, cfg.Elevation)
	return h
}

// isPermissionFailure reports whether a validator's combined output
// indicates a file-access failure (root-only config or includes) rather
// than a config error. nginx prints `open() "…" failed (13: Permission
// denied)`; haproxy prints `Could not open configuration file … :
// Permission denied`. Both use strerror(EACCES) — stable across versions.
// A permission failure is NOT evidence of an invalid config: the service
// runs as root at startup and reads those files fine (field report:
// ccc.laplane.net — nginx -t exits 1 on root-only conf.d includes while
// nginx itself is active and healthy).
func isPermissionFailure(out string) bool {
	return strings.Contains(out, "Permission denied")
}

// authorizedElevated reports whether the loaded policy authorizes (name,
// args) to run elevated in Sudo mode. A nil policy is never authorized
// here — the legacy drop-in is not derived from anything the agent knows.
func authorizedElevated(cfg *Config, name string, args []string) bool {
	return cfg.Elevate == elevate.Sudo &&
		cfg.Elevation != nil &&
		cfg.Elevation.Check(name, args) == elevate.Elevated
}

// collectNginx runs nginx -t for validation and extracts vhost topology.
func collectNginx(cfg *Config) *NginxConfig {
	cfg = cfg.Fill()
	if _, err := exec.LookPath("nginx"); err != nil {
		return nil
	}
	cfgPath := orDefault(cfg.NginxConf, "/etc/nginx/nginx.conf")
	if _, err := os.Stat(cfgPath); err != nil {
		return nil
	}
	n := &NginxConfig{
		Present:    true,
		ConfigFile: cfgPath,
	}
	// Readability first (see collectHAProxy): a root-only nginx.conf is not
	// evidence of an invalid config.
	readable := probeReadable(cfgPath) == nil
	n.ConfigReadable = &readable

	// Validate: nginx -t — capture output on failure (see HAProxyConfig).
	// validated starts false (blocked) — see collectHAProxy.
	validated := false
	defer func() { n.ConfigValidated = &validated }()
	switch {
	case readable:
		out, err := runOutput(configExecTimeout, "nginx", "-t")
		switch {
		case err == nil:
			n.ConfigValid, validated = true, true
		case isPermissionFailure(out) && authorizedElevated(cfg, "nginx", []string{"-t"}):
			// Root-only includes (the top-level file is readable, but conf.d
			// entries may be root-only): retry elevated — not evidence of an
			// invalid config (field report: ccc.laplane.net).
			if eout, eerr := runOutputElevated(cfg, configExecTimeout, "nginx", "-t"); eerr == nil {
				n.ConfigValid, validated = true, true
			} else {
				n.ConfigError, validated = capConfigError(eout), true
			}
		case isPermissionFailure(out):
			// Permission failure, no authorized elevation: blocked, not
			// invalid. ConfigError stays empty — the alert engine must not
			// fire on a validation that never completed.
		default:
			n.ConfigError, validated = capConfigError(out), true
		}
	case authorizedElevated(cfg, "nginx", []string{"-t"}):
		if out, err := runOutputElevated(cfg, configExecTimeout, "nginx", "-t"); err == nil {
			n.ConfigValid, validated = true, true
		} else {
			n.ConfigError, validated = capConfigError(out), true
		}
	default:
		// Unreadable and not authorized: skip, UI says "not readable".
	}
	// Version: nginx -v (writes to stderr)
	if out, err := runOutput(configExecTimeout, "nginx", "-v"); err == nil {
		n.Version = extractVersion(out)
	}
	// Config SHA256
	if sha, err := fileSHA256(cfgPath, cfg.Elevate, cfg.Elevation); err == nil {
		n.ConfigSHA256 = sha
	}
	// Topology: lightweight parsing
	n.Vhosts = parseNginxVhosts(cfgPath, cfg.Elevate, cfg.Elevation)
	return n
}

// runOutputElevated runs name+args through the agent's elevation prefix
// (sudo -n in Sudo mode) and captures combined output.
func runOutputElevated(cfg *Config, timeout time.Duration, name string, args ...string) (string, error) {
	n, a := cfg.Elevate.Run(name, args...)
	return runOutput(timeout, n, a...)
}

// ---- Cert facts (R20) ----------------------------------------------------

// CertFacts carries TLS certificate facts.
type CertFacts struct {
	Items []CertFact `json:"items"`
}

// CertFact is one certificate's details (arch §7.2).
type CertFact struct {
	Path          string   `json:"path"`
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	Serial        string   `json:"serial"`
	NotBefore     int64    `json:"not_before"` // epoch; 0 = unknown
	NotAfter      int64    `json:"not_after"`  // epoch; 0 = unknown
	DaysRemaining int64    `json:"days_remaining"`
	KeyType       string   `json:"key_type"`
	SANs          []string `json:"san"`
	ChainChecked  bool     `json:"chain_checked"` // true when `openssl verify` ran
	ChainValid    bool     `json:"chain_valid"`
	ChainLength   int      `json:"chain_length"`
	SelfSigned    bool     `json:"self_signed"`
	OCSPStapling  bool     `json:"ocsp_stapling"`
	OCSPStatus    string   `json:"ocsp_status"`
	Labels        []string `json:"labels,omitempty"`
}

// Cert collection bounds (M5). Scanning /etc/ssl on a distribution with a
// large CA bundle otherwise spawns thousands of openssl processes per
// interval and stalls the agent's collection slot for minutes.
const (
	maxCertFiles    = 512              // hard cap on files examined per collection
	maxCertFileSize = 1 << 20          // skip files >1 MiB (not a leaf cert)
	certExecTimeout = 10 * time.Second // per subprocess (openssl, sha256sum)
)

// collectCerts walks cert directories and runs openssl x509 on each file.
// Discovery: paths from config facts (TLS bindings) + defaults
// (/etc/ssl/, /etc/pki/tls/) + PARTOUT_CERT_PATHS.
// Refresh: 1 hour (arch §7.2).
func collectCerts(cfg *Config) *CertFacts {
	cfg = cfg.Fill()
	certPaths := defaultCertPaths()
	certPaths = append(certPaths, splitList(cfg.CertPaths)...)

	var items []CertFact
	seen := make(map[string]bool)
	caPath := resolveCABundle(cfg.CAPath)

	// Service-config references first: these are the certificates actually
	// serving traffic and must be captured even when the directory walk
	// exhausts its file budget. A referenced file may also fall inside a
	// scan root — the seen-set dedupes, and the label is attached below
	// regardless of which pass found the file.
	svcRefs := discoverServiceCerts(cfg)
	svcLabels := make(map[string][]string, len(svcRefs))
	for _, r := range svcRefs {
		svcLabels[r.Path] = append(svcLabels[r.Path], r.Service)
	}
	for _, r := range svcRefs {
		if len(items) >= maxCertFiles || seen[r.Path] {
			continue
		}
		if st, err := os.Stat(r.Path); err != nil || st.Size() > maxCertFileSize {
			continue // referenced but absent (or not a cert file)
		}
		seen[r.Path] = true
		if cf := parseCert(r.Path, caPath); cf != nil {
			items = append(items, *cf)
		}
	}

	// When caPath is empty (no trust bundle on this host) chain verification is
	// skipped for every cert and reported as unchecked, not as a broken chain.
	for _, dir := range certPaths {
		for _, f := range findCertFiles(dir) {
			if len(items) >= maxCertFiles {
				break
			}
			if seen[f] {
				continue // same file reachable from two scan roots
			}
			seen[f] = true
			if cf := parseCert(f, caPath); cf != nil {
				items = append(items, *cf)
			}
		}
	}
	for i := range items {
		if ls, ok := svcLabels[items[i].Path]; ok {
			items[i].Labels = append(items[i].Labels, ls...)
		}
	}
	if len(items) == 0 {
		return nil
	}
	return &CertFacts{Items: items}
}

// defaultCertPaths returns the standard certificate directories to scan.
func defaultCertPaths() []string {
	return []string{
		"/etc/ssl/",
		"/etc/pki/tls/",
	}
}

// defaultCABundles are the well-known system trust-bundle locations, in
// preference order. Debian/Ubuntu ships ca-certificates.crt; RHEL/Fedora
// ships tls/cert.pem; Alpine ships certs/ca-certificates.crt.
func defaultCABundles() []string {
	return []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/pki/tls/cert.pem",
		"/etc/ssl/cert.pem",
	}
}

// resolveCABundle returns the first existing CA bundle, or "" when none is
// found (then chain verification is skipped rather than reported as invalid).
func resolveCABundle(explicit string) string {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit
		}
	}
	for _, p := range defaultCABundles() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// findCertFiles walks a directory and returns .pem, .crt, .cert files, up to
// maxCertFiles. Symlinks are not followed (avoids cycles), oversized files
// are skipped, and the walk stops early once the cap is reached.
func findCertFiles(dir string) []string {
	return findCertFilesBounded(dir, maxCertFiles)
}

func findCertFilesBounded(dir string, budget int) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if len(files) >= budget {
			return files
		}
		if e.IsDir() {
			continue // subdirectories are walked explicitly by the caller's roots
		}
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".cert") {
			continue
		}
		full := filepath.Join(dir, name)
		if st, err := os.Stat(full); err != nil || st.Size() > maxCertFileSize {
			continue
		}
		files = append(files, full)
	}
	// Recurse into subdirectories after the files in this one, still bounded.
	for _, e := range entries {
		if len(files) >= budget {
			break
		}
		if !e.IsDir() {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			continue // e.g. /etc/ssl/certs symlinks into the CA store
		}
		files = append(files, findCertFilesBounded(filepath.Join(dir, e.Name()), budget-len(files))...)
	}
	return files
}

// parseCert runs openssl x509 to extract certificate details. caPath is the
// trust bundle used for chain verification; empty means verification is
// skipped (ChainValid stays false and ChainChecked false, so the caller can
// distinguish "not verified" from "verified and broken").
func parseCert(path, caPath string) *CertFact {
	cf := &CertFact{Path: path}

	// The certificate must be readable and parseable. Each field call below
	// fails soft (returning ""), so without this probe an unreadable file
	// would yield a phantom all-empty cert entry.
	if _, err := runOutput(certExecTimeout, "openssl", "x509", "-in", path, "-noout", "-subject"); err != nil {
		return nil
	}

	// One openssl call per single-valued field. Each of these prints exactly
	// one line, so no cross-field parsing heuristics are needed (an earlier
	// version parsed one combined blob and routinely swallowed the rest of
	// the output into subject/issuer).
	cf.Subject = opensslField(certExecTimeout, path, "-subject")
	cf.Issuer = opensslField(certExecTimeout, path, "-issuer")
	cf.Serial = opensslField(certExecTimeout, path, "-serial")

	// Dates. A parse failure leaves the timestamp zero: callers must treat
	// NotAfter==0 as "unknown", not as "expired" (DaysRemaining would
	// otherwise be a large negative number).
	if notBefore := opensslField(certExecTimeout, path, "-startdate"); notBefore != "" {
		if t, err := parseCertTime(notBefore); err == nil {
			cf.NotBefore = t.Unix()
		}
	}
	notAfter := opensslField(certExecTimeout, path, "-enddate")
	if notAfter != "" {
		if t, err := parseCertTime(notAfter); err == nil {
			cf.NotAfter = t.Unix()
			cf.DaysRemaining = int64(t.Sub(time.Now()).Hours() / 24)
		}
	}

	// SANs from the extension only (multi-value, so its own parse).
	cf.SANs = extractSANs(opensslSANSection(certExecTimeout, path))

	// Public-key algorithm and size come from -text.
	if text, err := runOutput(certExecTimeout, "openssl", "x509", "-in", path, "-noout", "-text"); err == nil {
		cf.KeyType = parseKeyType(text)
	}

	// Chain validation: openssl verify against the resolved trust bundle.
	// Only attempted when a bundle exists.
	if caPath != "" {
		cf.ChainChecked = true
		if _, err := runOutput(certExecTimeout, "openssl", "verify", "-CAfile", caPath, path); err == nil {
			cf.ChainValid = true
		}
	}

	// Chain length: number of PEM certs in the file.
	if data, err := os.ReadFile(path); err == nil {
		cf.ChainLength = bytes.Count(data, []byte("-----BEGIN CERTIFICATE-----"))
	}

	// Self-signed: the certificate is signed by its own key. Comparing the
	// subject and issuer names is a useful cheap pre-filter, but the
	// authoritative check is that the signature verifies against the cert's
	// own public key. `openssl verify -CAfile <cert> <cert>` is not reliable
	// here: it fails for a self-issued leaf that lacks the CA basic
	// constraint (the common `openssl req -x509` output).
	if cf.Subject != "" && cf.Subject == cf.Issuer {
		cf.SelfSigned = isSelfSigned(path)
	}

	// OCSP: the extension's presence says nothing about whether the serving
	// host staples a response, which is a server property. Report unknown
	// rather than guessing from the certificate text.
	cf.OCSPStatus = "unknown"

	return cf
}

// opensslField runs `openssl x509 -in <path> -noout <flags...>` and returns
// the printed value with the given prefix stripped. These invocations print
// exactly one line, so the result is unambiguous.
func opensslField(timeout time.Duration, path string, flags ...string) string {
	args := append([]string{"x509", "-in", path, "-noout"}, flags...)
	out, err := runOutput(timeout, "openssl", args...)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(out)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	// Strip a known "key=" prefix when the caller passed flags that produce
	// one (subject=, issuer=, serial=). Date fields print the value bare.
	for _, prefix := range []string{"subject=", "issuer=", "serial=", "notBefore=", "notAfter="} {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return line
}

// isSelfSigned reports whether the certificate is signed by its own key.
//
// Verified in-process with crypto/x509: CheckSignatureFrom(cert) succeeds iff
// the certificate's signature validates against its own public key. This is
// the authoritative test, and it is cheap (no subprocess) and portable.
func isSelfSigned(path string) bool {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// runOutput runs a command with a timeout and returns its combined output.
// capConfigError bounds a validator's output for the facts channel: keep the
// head (systemd/haproxy/nginx print the decisive error first) and mark the
// truncation so the operator knows there is more in the log.
func capConfigError(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 2048 {
		return s
	}
	return s[:2048] + " …(truncated)"
}

func runOutput(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// parseKeyType reports the certificate's public-key algorithm and size, e.g.
// "RSA-4096" or "ECDSA-P256". openssl x509 -text prints a public key block
// such as "Public Key Algorithm: rsaEncryption" / "RSA Public-Key: (4096
// bit)". The size is read from that block rather than hardcoded.
func parseKeyType(text string) string {
	switch {
	case strings.Contains(text, "RSA Public-Key"), strings.Contains(text, "Public Key Algorithm: rsaEncryption"):
		if n := extractBitSize(text); n != "" {
			return "RSA-" + n
		}
		return "RSA"
	case strings.Contains(text, "EC Public-Key"), strings.Contains(text, "id-ecPublicKey"):
		// ECDSA keys are reported by curve name (P-256/P-384/P-521); the
		// bit size does not identify the curve, so map from the curve text.
		for _, curve := range []string{"P-521", "P-384", "P-256", "P-224"} {
			if strings.Contains(text, curve) {
				return "ECDSA-" + curve
			}
		}
		return "ECDSA"
	case strings.Contains(text, "ED25519 Public-Key"):
		return "Ed25519"
	}
	return "unknown"
}

// extractBitSize pulls the bit count out of a "... : (4096 bit)" line.
func extractBitSize(text string) string {
	idx := strings.Index(text, " bit)")
	if idx < 0 {
		return ""
	}
	open := strings.LastIndex(text[:idx], "(")
	if open < 0 || open >= idx {
		return ""
	}
	n := strings.TrimSpace(text[open+1 : idx])
	if _, err := strconv.Atoi(n); err != nil {
		return ""
	}
	return n
}

// ---- Helpers -------------------------------------------------------------

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// splitSpaceList splits a whitespace-separated list. `systemctl show` renders
// dependency properties (After=, WantedBy=, RequiredBy=) as space-separated
// values, not comma-separated ones, so splitList would return them whole.
func splitSpaceList(s string) []string {
	return strings.Fields(s)
}

func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return strconv.ParseUint(strings.TrimSpace(s), 10, 64)
}

func parseExitCode(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// opensslSANSection returns the raw subjectAltName extension text, or ""
// when the certificate has no SAN extension.
func opensslSANSection(timeout time.Duration, path string) string {
	out, err := runOutput(timeout, "openssl", "x509", "-in", path, "-noout", "-ext", "subjectAltName")
	if err != nil {
		return ""
	}
	return out
}

func extractSANs(s string) []string {
	var sans []string
	// Look for DNS: patterns in the SANs section.
	sansSection := extractAfter(s, "X509v3 Subject Alternative Name:")
	if sansSection == "" {
		return nil
	}
	// The section runs until the next "X509v3 ..." extension header; without
	// this bound the last entry swallows the following extension text.
	if idx := strings.Index(sansSection, "X509v3 "); idx >= 0 {
		sansSection = sansSection[:idx]
	}
	// Entries are comma-separated; split before matching so an entry does not
	// carry a trailing comma ("app.example.com,").
	for _, entry := range strings.Split(sansSection, ",") {
		entry = strings.TrimSpace(entry)
		if strings.HasPrefix(entry, "DNS:") {
			if host := strings.TrimSpace(strings.TrimPrefix(entry, "DNS:")); host != "" {
				sans = append(sans, host)
			}
		}
	}
	return sans
}

func extractAfter(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(s[idx+len(prefix):])
}

// parseCertTime parses the `openssl x509 -dates` format, e.g.
// "Apr  5 00:00:00 2024 GMT" and "Apr 15 12:34:56 2024 GMT". The day field
// is space-padded, which time.Parse's reference layout tolerates for the
// day component, but the extra space after a short month name is not, so
// collapse runs of spaces first. ASN.1 UTCTime may also use a two-digit
// year; OpenSSL renders four, but accept both defensively.
func parseCertTime(s string) (time.Time, error) {
	s = strings.Join(strings.Fields(s), " ")
	for _, layout := range []string{
		"Jan 2 15:04:05 2006 MST",
		"Jan 2 15:04:05 2006",
		"2 Jan 2006 15:04:05 MST",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized certificate time %q", s)
}

// extractVersion pulls the version out of `haproxy -v` / `nginx -v` output.
//
// Real formats:
//
//	"HAProxy version 2.8.5 2023/04/13 - https://haproxy.org/"
//	"nginx version: nginx/1.24.0"
//	"nginx version: openresty/1.21.4.1"
//
// The version is the first dot-separated numeric token after a "version"
// marker and any "name/" prefix. Returns "" when nothing matches.
func extractVersion(s string) string {
	for _, field := range strings.Fields(s) {
		// Skip the marker words themselves.
		if field == "version" || field == "version:" {
			continue
		}
		// Strip a leading "nginx/"-style product prefix.
		if i := strings.LastIndex(field, "/"); i >= 0 {
			field = field[i+1:]
		}
		// Candidate must look like a dotted numeric version: leading digit,
		// containing a dot, and stopping at the first non [0-9.] rune.
		if field == "" || field[0] < '0' || field[0] > '9' {
			continue
		}
		end := len(field)
		for i, c := range field {
			if (c < '0' || c > '9') && c != '.' {
				end = i
				break
			}
		}
		candidate := field[:end]
		if strings.Contains(candidate, ".") {
			return candidate
		}
	}
	return ""
}

// fileSHA256 returns the SHA-256 of path. Under the given elevation policy,
// a permission error on the direct read retries via `sudo -n cat` so
// root-owned configs still get a hash.
func fileSHA256(path string, m elevate.Mode, p *elevate.Policy) (string, error) {
	data, err := elevate.ReadFile(m, p, path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:]), nil
}

// parseHAProxyTopology does lightweight regex/line-based parsing of the
// haproxy config to extract backends, servers, frontends, TLS bindings.
// No full YAML parsing dependency — just line scanning.
func parseHAProxyTopology(path string, m elevate.Mode, p *elevate.Policy) ([]BackendFact, []ListenerFact) {
	var backends []BackendFact
	var listeners []ListenerFact
	data, err := elevate.ReadFile(m, p, path)
	if err != nil {
		return backends, listeners
	}
	lines := strings.Split(string(data), "\n")
	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "backend ") {
			currentSection = "backend"
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				backends = append(backends, BackendFact{Name: fields[1]})
			}
		} else if strings.HasPrefix(line, "frontend ") || strings.HasPrefix(line, "listen ") {
			currentSection = "frontend"
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mode := "http"
				port := 0
				tls := ""
				for _, field := range fields[1:] {
					if field == ":443" || field == ":8443" {
						mode = "https"
						port, _ = strconv.Atoi(field[1:])
						tls = "enabled"
					} else if n, err := strconv.Atoi(field[1:]); err == nil {
						port = n
					}
				}
				listeners = append(listeners, ListenerFact{
					Port: port, Mode: mode, TLS: tls,
				})
			}
		} else if currentSection == "backend" && strings.HasPrefix(line, "server ") {
			if len(backends) > 0 {
				backends[len(backends)-1].Servers++
			}
		}
	}
	return backends, listeners
}

// parseNginxVhosts does lightweight parsing of nginx config to extract
// server blocks (vhosts) with their TLS and upstream info.
// parseNginxVhosts extracts server { ... } blocks from an nginx config and
// parses each one. The scan is line-based with brace-depth tracking so that a
// nested block (location, if) does not terminate the server block early.
// `include`d files are not followed (best-effort topology, arch §7.2).
func parseNginxVhosts(path string, m elevate.Mode, p *elevate.Policy) []VHostFact {
	data, err := elevate.ReadFile(m, p, path)
	if err != nil {
		return nil
	}

	var vhosts []VHostFact
	var block []string
	depth := 0
	inServer := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := stripNginxComment(raw)
		trimmed := strings.TrimSpace(line)
		if !inServer {
			if isNginxServerOpen(trimmed) {
				inServer = true
				depth = strings.Count(line, "{") - strings.Count(line, "}")
				block = block[:0]
				block = append(block, line)
				if depth <= 0 {
					// Single-line block.
					vhosts = append(vhosts, parseNginxServerBlock(strings.Join(block, "\n")))
					inServer = false
				}
			}
			continue
		}
		block = append(block, line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			vhosts = append(vhosts, parseNginxServerBlock(strings.Join(block, "\n")))
			inServer = false
		}
	}
	return vhosts
}

// isNginxServerOpen reports whether a line opens a `server {` block.
func isNginxServerOpen(trimmed string) bool {
	if !strings.Contains(trimmed, "{") {
		return false
	}
	fields := strings.Fields(trimmed)
	return len(fields) >= 2 && fields[0] == "server" && strings.HasPrefix(fields[1], "{")
}

// stripNginxComment removes a trailing `# ...` comment (nginx has no string
// literals that could contain an unescaped # in a directive line).
func stripNginxComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// parseNginxServerBlock extracts vhost details from a server { ... } block.
// Directive values are terminated by ';', which is stripped before use.
func parseNginxServerBlock(block string) VHostFact {
	var vhost VHostFact
	for _, raw := range strings.Split(block, "\n") {
		fields := strings.Fields(strings.TrimSpace(stripNginxComment(raw)))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "server_name":
			// First name; "_" is the catch-all placeholder and is kept as-is.
			vhost.ServerName = nginxValue(fields[1])
		case "listen":
			for _, p := range fields[1:] {
				p = nginxValue(p)
				if p == "ssl" {
					vhost.TLS = true
					continue
				}
				// Accept "443", "8443", "[::]:443", "127.0.0.1:8080".
				if i := strings.LastIndexByte(p, ':'); i >= 0 {
					p = p[i+1:]
				}
				if n, err := strconv.Atoi(p); err == nil {
					vhost.Port = n
				}
			}
		case "ssl_certificate":
			vhost.TLSCert = nginxValue(fields[1])
		case "root":
			vhost.Root = nginxValue(fields[1])
		case "proxy_pass":
			vhost.Upstream = nginxValue(fields[1])
		}
	}
	return vhost
}

// nginxValue trims a trailing directive terminator.
func nginxValue(v string) string { return strings.TrimSuffix(v, ";") }
