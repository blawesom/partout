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
	"github.com/blawesom/partout/internal/config"
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
		r.add(dinfo, "tls", "off (plain HTTP; set PARTOUT_TLS=on for a local root CA)")
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
// would use (conventional names in the SSH dir, in OpenSSH's order), or notes
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
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		p := filepath.Join(sshDir, name)
		if _, err := os.Stat(p); err == nil {
			r.add(dok, "ssh key", p+" (host provisioning)")
			return
		}
	}
	// No conventional file key: the ssh-agent may still have keys.
	if agentOK() {
		r.add(dok, "ssh key", "ssh-agent holds a key (no conventional file in "+sshDir+")")
		return
	}
	r.add(dwarn, "ssh key", "no identity key found for host provisioning (looked for id_ed25519/ecdsa/rsa in "+sshDir+" or the ssh-agent)")
}

func checkReleaseKey(cfg *config.Config, r *doctorResult) {
	if cfg.ReleaseKey != "" {
		r.add(dok, "release key", "set (fleet updates verify signatures)")
		return
	}
	r.add(dinfo, "release key", "unset — fleet updates run unsigned-beta (set PARTOUT_RELEASE_KEY to require signatures)")
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

// agentOK reports whether the ssh-agent holds at least one key.
func agentOK() bool {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return false
	}
	cmd := exec.Command("ssh-add", "-l")
	cmd.Env = os.Environ()
	err := cmd.Run()
	return err == nil
}

func orAll(s string) string {
	if s == "" {
		return "* (all interfaces)"
	}
	return s
}

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
		cfg.TLS = cfg.TLS // unknown value keeps config; doctor will not start a server
	}
}

func (d *doctorFlagSet) parse(args []string) error { return d.fs.Parse(args) }
