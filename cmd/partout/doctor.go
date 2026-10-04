// Command partout — `doctor` subcommand.
//
// `partout doctor` is a pre-flight readiness check: it inspects the *current*
// host against the *effective* server config (env + flag overrides) and
// reports pass/fail for the things that would otherwise surface as a confusing
// startup failure — most importantly, a listener port that is already taken.
// It makes no changes and starts no server.
//
// Exit code: 0 when nothing hard-fails, 1 when at least one check fails.
// Warnings (degraded but runnable) do not change the exit code.
//
// Intended as the "check before you start" step:
//
//	partout doctor && ./partout
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/agent/facts"
	agentfs "github.com/blawesom/partout/internal/agent/fs"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/sshutil"
)

type doctorLevel int

const (
	dok doctorLevel = iota
	dinfo
	dwarn
	dfail
)

func (l doctorLevel) tag() string {
	switch l {
	case dok:
		return "ok  "
	case dinfo:
		return "info"
	case dwarn:
		return "WARN"
	case dfail:
		return "FAIL"
	}
	return "??"
}

type doctorCheck struct {
	level  doctorLevel
	name   string
	detail string
}

type doctorResult struct {
	checks []doctorCheck
	fails  int
	warns  int
}

func (r *doctorResult) add(lv doctorLevel, name, detail string) {
	switch lv {
	case dfail:
		r.fails++
	case dwarn:
		r.warns++
	}
	r.checks = append(r.checks, doctorCheck{lv, name, detail})
}

func (r *doctorResult) print() {
	for _, c := range r.checks {
		if c.detail == "" {
			fmt.Printf("  %s %s\n", c.level.tag(), c.name)
		} else {
			fmt.Printf("  %s %-22s %s\n", c.level.tag(), c.name, c.detail)
		}
	}
}

// runDoctor loads the effective config, runs the pre-flight checks, prints a
// report, and returns an error when a hard check fails (main maps that to a
// non-zero exit).
func runDoctor() error {
	// Parse the server-relevant flags exactly the way the server does, so the
	// checks reflect what `partout` would actually do.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	fs := newDoctorFlagSet(cfg)
	if err := fs.fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *fs.vers {
		fmt.Println("partout " + facts.Version)
		return nil
	}
	applyDoctorFlags(cfg, fs)

	r := &doctorResult{}
	fmt.Printf("partout doctor (%s)\n", facts.Version)
	fmt.Printf("  mode=%s addr=%s port=%d db=%s tls=%v\n\n",
		cfg.Mode, orAll(cfg.Addr), cfg.Port, cfg.DBPath, cfg.TLS)

	checkPortFree(cfg, r)
	checkDBWritable(cfg, r)
	checkTLS(cfg, r)
	checkAdmin(cfg, r)
	checkOutboundOSV(cfg, r)
	checkOutboundEOL(cfg, r)
	checkSSHKey(cfg, r)
	checkReleaseKey(cfg, r)
	checkProvisioning(cfg, r)
	if cfg.Mode == "agent" || cfg.Mode == "embedded" {
		checkFileRoot(cfg, r)
		checkElevation(cfg, r)
	}
	if cfg.Mode == "server" || cfg.Mode == "embedded" {
		checkFleetVersions(cfg, r)
		checkDBHealth(cfg, r)
	}

	fmt.Println()
	if r.fails > 0 {
		fmt.Printf("doctor: %d failure(s), %d warning(s) — NOT ready\n", r.fails, r.warns)
		r.print()
		return fmt.Errorf("doctor: %d check(s) failed", r.fails)
	}
	fmt.Printf("doctor: %d warning(s), no failures — ready\n", r.warns)
	r.print()
	return nil
}

// checkFileRoot verifies the agent file-surface root (docs/spec-file-root.md)
// read-only: an unusable root disables the file surface (fail closed) — the
// most common cause of a "no file root reported" banner on an upgraded
// fleet (the agent runs unprivileged and cannot create /home/partout
// itself on hosts provisioned before v0.9.5, whose /home is root-owned).
// Deliberately creates nothing: report what the agent would find.
func checkFileRoot(cfg *config.Config, r *doctorResult) {
	root := strings.TrimSpace(cfg.FileRoot)
	if root == "" {
		root = agentfs.DefaultFileRoot
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		r.add(dfail, "file root", err.Error())
		return
	}
	info, err := os.Lstat(abs)
	if os.IsNotExist(err) {
		// The agent creates the root (0750) at startup when the parent is
		// writable by the agent user; doctor runs as the operator, who may
		// or may not be that user — so this is a warning with the remedy,
		// not a failure.
		r.add(dwarn, "file root",
			abs+" does not exist — the agent creates it at startup when the parent is writable; if it is not: sudo mkdir -p "+abs+" && sudo chown partout:partout "+abs+" && sudo chmod 0750 "+abs)
		return
	}
	if err != nil {
		r.add(dfail, "file root", err.Error())
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		r.add(dfail, "file root", abs+" is a symlink — not allowed (the root must be a real directory)")
		return
	}
	if !info.IsDir() {
		r.add(dfail, "file root", abs+" is not a directory")
		return
	}
	if info.Mode().Perm()&0o200 == 0 {
		r.add(dfail, "file root", abs+" is not writable by this user — the file surface would be disabled (fail closed); chown it to the agent user")
		return
	}
	r.add(dok, "file root", abs+" (file surface confined to this directory)")
}

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------

func checkPortFree(cfg *config.Config, r *doctorResult) {
	addr := cfg.Addr
	if addr == "" {
		addr = "0.0.0.0"
	}
	la, err := net.Listen("tcp", net.JoinHostPort(addr, formatPort(cfg.Port)))
	if err != nil {
		r.add(dfail, "port free", err.Error())
		return
	}
	la.Close()
	r.add(dok, "port free", fmt.Sprintf("%s:%d", orAll(addr), cfg.Port))
}

func checkDBWritable(cfg *config.Config, r *doctorResult) {
	dir := filepath.Dir(cfg.DBPath)
	if dir == "" {
		dir = "."
	}
	fi, err := os.Stat(dir)
	if err != nil {
		r.add(dfail, "db dir", fmt.Sprintf("%s not found (%v)", dir, err))
		return
	}
	if !fi.IsDir() {
		r.add(dfail, "db dir", dir+" is not a directory")
		return
	}
	// Probe writability without touching the real DB.
	probe, perr := os.CreateTemp(dir, ".partout-doctor-*")
	if perr != nil {
		r.add(dfail, "db writable", perr.Error())
		return
	}
	pname := probe.Name()
	probe.Close()
	defer os.Remove(pname)
	if os.Remove(pname) != nil {
		r.add(dfail, "db writable", "cannot write/remove in "+dir)
		return
	}
	r.add(dok, "db writable", dir)
}

func checkTLS(cfg *config.Config, r *doctorResult) {
	if !cfg.TLS {
		// Plain HTTP is fine on loopback (local dev) but a silent credential
		// exposure on a reachable interface: the login password and every
		// session token would cross the network in cleartext. The default bind
		// is all interfaces, so this is the state a first-run operator is most
		// likely to be in — warn loudly instead of noting it in passing.
		if loopbackOnly(cfg.Addr) {
			r.add(dinfo, "tls", "off (plain HTTP on loopback; set PARTOUT_TLS=on for a local root CA)")
		} else {
			r.add(dwarn, "tls", "off — plain HTTP on "+orAll(cfg.Addr)+": the admin password and session tokens cross the network in cleartext (set PARTOUT_TLS=on, or PARTOUT_ADDR=127.0.0.1 behind a TLS proxy)")
		}
		return
	}
	if strings.TrimSpace(cfg.TLSNames) == "" {
		r.add(dwarn, "tls SAN names", "empty — server will use defaults (localhost,127.0.0.1,hostname)")
		return
	}
	for _, n := range strings.Split(cfg.TLSNames, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if strings.Contains(n, ":") && net.ParseIP(strings.SplitN(n, ":", 2)[0]) == nil {
			r.add(dwarn, "tls SAN names", "looks like a host:port — a bare IP/port SAN is unusual")
			return
		}
	}
	r.add(dok, "tls", "on (local root CA bootstrap)")
}

func checkAdmin(cfg *config.Config, r *doctorResult) {
	if cfg.AdminPassword != "" {
		r.add(dok, "admin auth", "admin password set via PARTOUT_ADMIN_PASSWORD")
		return
	}
	if cfg.AdminToken != "" {
		r.add(dok, "admin auth", "static RBAC admin token set")
		return
	}
	// First-run path: a random password is generated into <dbdir>/admin_password.txt.
	pwd := filepath.Join(filepath.Dir(cfg.DBPath), "admin_password.txt")
	r.add(dwarn, "admin auth", "no admin password set — a random one will be written to "+pwd+" on first run; rotate it")
}

func checkOutboundOSV(cfg *config.Config, r *doctorResult) {
	if ok, detail := probeOutbound("https://api.osv.dev/v1/", 3*time.Second); ok {
		r.add(dok, "outbound OSV.dev", detail)
	} else {
		r.add(dwarn, "outbound OSV.dev", "unreachable — the security scan will have no CVE data until it is ("+detail+")")
	}
}

func checkOutboundEOL(cfg *config.Config, r *doctorResult) {
	if ok, detail := probeOutbound("https://endoflife.date/api/debian", 3*time.Second); ok {
		r.add(dok, "outbound EOL", detail)
	} else {
		r.add(dwarn, "outbound EOL", "unreachable — distro end-of-life data will not refresh ("+detail+")")
	}
}

// checkSSHKey reports which identity key the server's host-provisioning path
// would use (conventional names in the SSH dir, in OpenSSH's order), plus
// any IdentityFile the ssh config declares that exists on disk, or notes
// the absence so the operator knows provisioning needs a key first.
func checkSSHKey(cfg *config.Config, r *doctorResult) {
	sshDir := os.Getenv("PARTOUT_SSH_DIR")
	if sshDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			sshDir = filepath.Join(home, ".ssh")
		}
	}
	if sshDir == "" {
		r.add(dwarn, "ssh key", "cannot determine SSH dir (HOME unset?)")
		return
	}
	// Same source of truth the provisioner uses (sshutil.IdentityStatusFor),
	// so doctor reports exactly what a run would offer. The probe is
	// host-agnostic: defaults + "Host *" config sections (the wizard passes
	// the real target host for host-specific IdentityFile blocks).
	st := sshutil.Default(sshDir).IdentityStatusFor(context.Background(), "")
	switch {
	case len(st.FileKeys) > 0:
		r.add(dok, "ssh key", filepath.Join(sshDir, st.FileKeys[0])+" (host provisioning)")
	case len(st.ConfigKeys) > 0:
		r.add(dok, "ssh key", st.ConfigKeys[0]+" (from ssh config, host provisioning)")
	case st.Agent:
		r.add(dok, "ssh key", "ssh-agent holds a key (no conventional file in "+sshDir+")")
	default:
		r.add(dwarn, "ssh key", "no identity key found for host provisioning (looked for id_ed25519/ecdsa/rsa in "+sshDir+", the ssh config's IdentityFile entries, or the ssh-agent)")
	}
}

func checkReleaseKey(cfg *config.Config, r *doctorResult) {
	if cfg.ReleaseKey != "" {
		r.add(dok, "release key", "set (fleet updates verify signatures)")
		return
	}
	r.add(dinfo, "release key", "unset — fleet updates run unsigned-beta (set PARTOUT_RELEASE_KEY to require signatures)")
}

// checkProvisioning reports whether host provisioning from this server can
// work: the listener bind must be reachable from remote hosts (a loopback
// bind never is), the server host written into agents' PARTOUT_SERVER must
// resolve to something other targets can use (not just loopback), and with
// TLS on, that host must be covered by the leaf's SANs or provisioned agents
// fail certificate verification.
func checkProvisioning(cfg *config.Config, r *doctorResult) {
	if config.LoopbackBind(cfg.Addr) {
		r.add(dwarn, "provision bind", "PARTOUT_ADDR="+cfg.Addr+" is loopback-only — hosts provisioned from this server can never reach it; use a routable bind (or same-host agents only)")
	}

	sh := cfg.ServerHost
	if sh == "" {
		sh = config.DefaultServerHost()
	}
	if cfg.ServerHost == "" {
		if ips, err := net.LookupHost(sh); err == nil && allLoopbackIPs(ips) {
			r.add(dwarn, "provision server host", "PARTOUT_SERVER_HOST unset and the local hostname resolves only to loopback ("+strings.Join(ips, ",")+") — remote targets cannot reach it; set PARTOUT_SERVER_HOST to a routable IP/FQDN")
		} else {
			r.add(dinfo, "provision server host", sh+" (PARTOUT_SERVER_HOST unset — hostname fallback; it must resolve on every target)")
		}
	} else {
		if ips, err := net.LookupHost(hostOnly(sh)); err != nil {
			r.add(dwarn, "provision server host", sh+" does not resolve — provisioned agents cannot find the server")
		} else if allLoopbackIPs(ips) {
			r.add(dwarn, "provision server host", sh+" resolves only to loopback — remote targets cannot reach it")
		} else {
			r.add(dok, "provision server host", sh)
		}
	}

	// TLS + provisioning: the leaf must cover the host agents dial, and the
	// CA gets distributed by the installer automatically.
	if cfg.TLS {
		names := serverCertNames(cfg.TLSNames)
		if !nameCovered(names, hostOnly(sh)) {
			r.add(dwarn, "provision tls", "server host "+hostOnly(sh)+" is not in the leaf SANs "+strings.Join(names, ",")+" — provisioned agents will fail cert verification (add it to PARTOUT_TLS_SERVER_NAMES or point PARTOUT_SERVER_HOST at a covered name)")
		}
	}
}

// hostOnly strips a :port suffix (best-effort; IPv6 literals keep their
// brackets so net.ParseIP still works on the result).
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// allLoopbackIPs reports whether a resolved address list is non-empty and
// loopback-only (e.g. the typical /etc/hosts 127.0.1.1 hostname entry).
func allLoopbackIPs(ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// serverCertNames (shared with the server bootstrap) lives in main.go; it
// resolves the configured list or the documented default
// (localhost,127.0.0.1,hostname).

// nameCovered reports whether the SAN list covers host (exact, case-
// insensitive — the same check Go's x509 verifier effectively applies).
func nameCovered(names []string, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, n := range names {
		if strings.ToLower(strings.TrimSpace(n)) == host {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// probeOutbound does a bounded GET and reports whether any HTTP status came
// back (a 4xx still proves the network path). The returned detail is the
// status line on success, or the network error on failure.
func probeOutbound(url string, timeout time.Duration) (bool, string) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return false, err.Error()
	}
	res, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	res.Body.Close()
	return true, res.Status
}

func orAll(s string) string {
	if s == "" {
		return "* (all interfaces)"
	}
	return s
}

// loopbackOnly is a thin alias over the shared config helper (canonical
// implementation + tests live in internal/config, so the provisioner and
// doctor agree on what counts as loopback).
func loopbackOnly(addr string) bool { return config.LoopbackBind(addr) }

func formatPort(p int) string { return fmt.Sprintf("%d", p) }

// doctorFlagSet bundles the server-relevant flags the doctor needs, seeded
// from the loaded config so flag > env > default holds (same as the server).
type doctorFlagSet struct {
	fs    *flag.FlagSet
	port  *int
	addr  *string
	db    *string
	tls   *string
	names *string
	vers  *bool
}

func newDoctorFlagSet(cfg *config.Config) *doctorFlagSet {
	fs := flag.NewFlagSet("partout doctor", flag.ContinueOnError)
	return &doctorFlagSet{
		fs:    fs,
		port:  fs.Int("port", cfg.Port, "server: single listener port"),
		addr:  fs.String("addr", cfg.Addr, "server: bind address (empty = all interfaces)"),
		db:    fs.String("db", cfg.DBPath, "server: SQLite path"),
		tls:   fs.String("tls", tlsDefault(cfg.TLS), "server: TLS mode on|off"),
		names: fs.String("tls-names", cfg.TLSNames, "server: comma-separated SAN names"),
		vers:  fs.Bool("version", false, "print the version and exit"),
	}
}

// applyDoctorFlags folds the parsed flags back into the effective config.
func applyDoctorFlags(cfg *config.Config, d *doctorFlagSet) {
	cfg.Port = *d.port
	cfg.Addr = *d.addr
	cfg.DBPath = *d.db
	cfg.TLSNames = *d.names
	switch strings.ToLower(*d.tls) {
	case "on", "true":
		cfg.TLS = true
	case "off", "false", "":
		cfg.TLS = false
	default:
		// Unknown value: keep the config as-is (doctor only reports; it never
		// starts a server, so an unrecognized --tls does not need to be fatal).
	}
}

func (d *doctorFlagSet) parse(args []string) error { return d.fs.Parse(args) }

// sudoProbe runs `sudo -n true` — injectable in tests.
var sudoProbe = func() error {
	return exec.Command("sudo", "-n", "true").Run()
}

// checkElevation verifies the host-level elevation mode (PRD Decision 3):
// with PARTOUT_ELEVATE off, package applies and every other root-requiring
// action fail with raw permission errors (the most common "applying system
// updates fails" report on provisioned hosts — provisioning deliberately
// does not enable elevation). With sudo on, the sudoers scope must
// actually answer non-interactively.
func checkElevation(cfg *config.Config, r *doctorResult) {
	if cfg.Elevate != "sudo" {
		r.add(dwarn, "elevation",
			"off (PARTOUT_ELEVATE unset/none) — package applies and other root-requiring actions fail with permission errors as the unprivileged agent user; to enable: install the sudoers scope (deploy/sudoers/partout-agent, or an elevation policy via `partout ctl elevation install-sudoers`), set PARTOUT_ELEVATE=sudo in the agent env, restart the agent")
		return
	}
	if err := sudoProbe(); err != nil {
		r.add(dwarn, "elevation",
			"PARTOUT_ELEVATE=sudo but `sudo -n true` failed — the sudoers scope is missing or wrong (run as the agent user for the exact error); see deploy/sudoers/partout-agent")
		return
	}
	if os.Geteuid() == 0 {
		r.add(dok, "elevation", "sudo -n works — trivially: doctor runs as root; probe again as the agent user for a real check")
		return
	}
	r.add(dok, "elevation", "sudo -n works (privileged actions elevated per the sudoers scope)")
}
