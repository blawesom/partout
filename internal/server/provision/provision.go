// Package provision implements the host provisioning run state machine and
// step executor (architecture §3.5, PRD R17/C10).
//
// States: queued → connecting → key_confirm → preflight → transferring
// → installing → enrolling → connected
// Terminal: failed | cancelled | handoff
//
// Steps:
//  1. connect      — fingerprint gate (no silent TOFU)
//  2. preflight    — read-only checks (os, arch, systemd, sudo, disk)
//  3. transfer     — scp of the server binary
//  4. install      — one sudo bash script: install, user, env, unit, start
//  5. wait-enroll  — wait for the agent to enroll + connect
//
// Each step is streamed as an SSE event (provision.step) and persisted for
// audit, with a bounded output excerpt. SSH is the bootstrap channel only —
// it never carries commands, files, or observation data (PRD invariant 1).
// Partout never creates, copies, or persists operator credentials.
package provision

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blawesom/partout/internal/agent/elevate"
	agentfacts "github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/server/provision/embedded"
	"github.com/blawesom/partout/internal/sshutil"
	"github.com/blawesom/partout/internal/store"
)

// Emitter is the SSE broadcast hook the provisioner uses to publish
// per-step and terminal events.
type Emitter interface {
	Emit(kind string, payload any)
}

// activeRun holds the in-memory control channel for a running provision.
type activeRun struct {
	id      string
	confirm chan struct{} // closed when ConfirmKey is called
	cancel  context.CancelFunc

	// confirmOnce guarantees the confirm channel is closed at most once, so a
	// duplicate POST /key (double-click, retry) cannot panic with
	// "close of closed channel".
	confirmOnce sync.Once
}

// Provisioner orchestrates host provisioning runs.
type Provisioner struct {
	store        *store.Store
	ssh          sshutil.Config
	emitter      Emitter
	log          *log.Logger
	serverHost   string // address the new agent connects to (PARTOUT_SERVER)
	bindAddr     string // server listener bind ("" = all interfaces); diagnostics only
	caPath       string // server root CA to distribute ("" = TLS off, plaintext h2c)
	binaryPath   string // path to the partout binary on the server
	localVersion string // the server's own version (for the version-diff check)
	tokenTTL     int    // enrollment token TTL seconds (short, arch §3.5)

	mu   sync.Mutex
	runs map[string]*activeRun
}

// Options builds a Provisioner. SSH controls the ssh child processes (use
// sshutil.Default(sshDir) for the operator's ~/.ssh; inject a custom Config
// in tests). ServerHost is the address written into the agent's
// PARTOUT_SERVER. BindAddr is the server's own listener bind ("" = all
// interfaces), used only for diagnostics: a loopback-only bind can never be
// reached from a remote host, so the preflight failure can say that instead
// of blaming the network. BinaryPath is the server's own binary that gets
// transferred. CAPath is the server root CA (PEM) distributed to
// /etc/partout/ca.crt on targets so a provisioned agent trusts the server
// from its first connection; "" (TLS off) keeps the agent stream plaintext h2c.
type Options struct {
	Store      *store.Store
	SSH        sshutil.Config
	ServerHost string
	BindAddr   string
	CAPath     string
	BinaryPath string
	Emitter    Emitter
	Logger     *log.Logger
}

// New builds a Provisioner from opts.
func New(opts Options) *Provisioner {
	lg := opts.Logger
	if lg == nil {
		lg = log.Default()
	}
	return &Provisioner{
		store:        opts.Store,
		ssh:          opts.SSH,
		emitter:      opts.Emitter,
		log:          lg,
		serverHost:   opts.ServerHost,
		bindAddr:     opts.BindAddr,
		caPath:       opts.CAPath,
		binaryPath:   opts.BinaryPath,
		localVersion: agentfacts.Version,
		tokenTTL:     300, // 5 min — short TTL for the one-time token
		runs:         make(map[string]*activeRun),
	}
}

// SSHStatus reports the identity keys this provisioner would offer to a
// target host (conventional files in SSHDir + the ssh-agent). The wizard's
// confirm screen surfaces this BEFORE start so the operator sees exactly
// which key will be used — and that none was found — before a run can fail
// on a missing key.
func (p *Provisioner) SSHStatus() sshutil.IdentityStatus {
	return p.ssh.IdentityStatus()
}

// SSHStatusFor is the host-aware variant of SSHStatus: it also resolves the
// ssh config for that specific host (aliases, host-specific IdentityFile
// blocks) via ssh -G, so a config like "Host ai / IdentityFile marvin_ops"
// is reported as an offered key instead of silently missing from the
// conventional-name scan.
func (p *Provisioner) SSHStatusFor(host string) sshutil.IdentityStatus {
	return p.ssh.IdentityStatusFor(context.Background(), host)
}

// stepNames are the five provisioning steps in order.
var stepNames = []string{"connect", "preflight", "transfer", "install", "wait-enroll"}

// ErrHostBusy reports a rejected start: another non-terminal run for the
// same host is already in flight (concurrent runs race on known_hosts
// entries, the install script, and the target's systemd units).
var ErrHostBusy = errors.New("provision: an active run for this host already exists")

// Start creates a provisioning run in queued state, generates a one-time
// enrollment token, and kicks off the async state machine.
// ElevationPolicySpec is one elevation policy to install on the target:
// either resolved from the server-side store (Name + content) or supplied
// inline by the caller (CLI local file). SHA is the canonical rules-only
// hash (elevate.PolicyHash), verified on the target before install.
type ElevationPolicySpec struct {
	Name      string `json:"name"`
	RulesJSON string `json:"rules_json"`
	SHA       string `json:"sha256"`
}

// StartOptions are the provision-time knobs (field feedback D1): the
// elevation bootstrap (policy + sudoers + PARTOUT_ELEVATE wired through
// the run's root install) and the agent.env extras that need root to set
// post-provision (service labels, cert paths).
type StartOptions struct {
	// Elevate enables elevation on the target: policies are installed to
	// /etc/partout/elevation.d/, the sudoers drop-in is rendered +
	// visudo-checked + installed, and agent.env gets PARTOUT_ELEVATE=sudo.
	Elevate bool
	// ElevationPolicies are installed in order as numbered drop-ins.
	ElevationPolicies []ElevationPolicySpec
	// ServiceLabels / CertPaths are written into agent.env verbatim
	// (PARTOUT_SERVICE_LABELS / PARTOUT_CERT_PATHS).
	ServiceLabels string
	CertPaths     string
}

// extrasJSON is the persisted display/audit form of the options.
type extrasJSON struct {
	Elevate           bool                  `json:"elevate"`
	ElevationPolicies []ElevationPolicySpec `json:"elevation_policies,omitempty"`
	ServiceLabels     string                `json:"service_labels,omitempty"`
	CertPaths         string                `json:"cert_paths,omitempty"`
}

func (o StartOptions) extras() string {
	b, _ := json.Marshal(extrasJSON(o))
	return string(b)
}

func (p *Provisioner) Start(host, mode string, opts StartOptions) (*store.ProvisionRun, error) {
	// One active run per host: a second run would race the first on
	// known_hosts, the install script, and the target's units.
	if runs, err := p.store.ProvisionRuns(500); err == nil {
		for _, r := range runs {
			if !isTerminal(r.State) && r.Host == host {
				return nil, fmt.Errorf("%w: run %s (state %s); cancel it or wait for it to finish", ErrHostBusy, r.ID, r.State)
			}
		}
	}

	// Fail fast on inconsistent elevation options — a policy that does not
	// parse must never reach the target (the sudoers render happens there,
	// but the JSON is validated here, server-side).
	if opts.Elevate && len(opts.ElevationPolicies) == 0 {
		return nil, fmt.Errorf("provision: --elevate requires at least one --elevation-policy (a store name or a local file)")
	}
	for i, ep := range opts.ElevationPolicies {
		if ep.RulesJSON == "" {
			return nil, fmt.Errorf("provision: elevation policy %d (%s): empty rules", i, ep.Name)
		}
		pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + ep.RulesJSON + `}`))
		if err != nil {
			return nil, fmt.Errorf("provision: elevation policy %s invalid: %w", ep.Name, err)
		}
		// Canonicalize (defense in depth): the transferred file is written
		// as {"rules":<RulesJSON>} and verified against PolicyHash, which is
		// the sha256 of the CANONICAL compact marshal — a hand-formatted
		// input (indented JSON from a local file or a preset literal) must
		// be normalized or the on-host verification (correctly) rejects it.
		canonical, err := json.Marshal(pol.Rules)
		if err != nil {
			return nil, fmt.Errorf("provision: elevation policy %s: canonicalize: %w", ep.Name, err)
		}
		opts.ElevationPolicies[i].RulesJSON = string(canonical)
		opts.ElevationPolicies[i].SHA = pol.PolicyHash()
	}

	runID := id.New("prv")
	run := &store.ProvisionRun{
		ID:         runID,
		Host:       host,
		Mode:       mode,
		ExtrasJSON: opts.extras(),
		State:      "queued",
		Created:    time.Now().Unix(),
		Updated:    time.Now().Unix(),
	}

	// Create the run first so a failure here cannot leave an orphaned
	// enrollment token behind. The token is generated and attached next.
	if err := p.store.CreateProvisionRun(*run); err != nil {
		return nil, fmt.Errorf("provision: create run: %w", err)
	}

	// One-time short-TTL enrollment token for the new agent.
	token, err := p.store.NewEnrollmentToken(p.tokenTTL)
	if err != nil {
		return nil, fmt.Errorf("provision: create token: %w", err)
	}
	run.TokenHash = sha256Hex(token)
	if err := p.store.SetProvisionRunToken(runID, run.TokenHash); err != nil {
		return nil, fmt.Errorf("provision: link token: %w", err)
	}
	for i := 1; i <= len(stepNames); i++ {
		if err := p.store.CreateProvisionStep(runID, i, stepNames[i-1]); err != nil {
			p.log.Printf("provision: create step %d: %v", i, err)
		}
	}

	p.audit("provision.requested", fmt.Sprintf(`{"host":%q,"mode":%q}`, host, mode))
	if p.emitter != nil {
		p.emitter.Emit("provision.start", map[string]string{"run_id": runID, "host": host, "mode": mode})
	}

	ctx, cancel := context.WithCancel(context.Background())
	ar := &activeRun{id: runID, confirm: make(chan struct{}), cancel: cancel}
	p.mu.Lock()
	p.runs[runID] = ar
	p.mu.Unlock()

	go p.run(ctx, ar, run, token, opts)
	return run, nil
}

// ConfirmKey approves the captured host key: appends it to known_hosts
// (hashed) and resumes the paused state machine.
func (p *Provisioner) ConfirmKey(runID string) error {
	run, err := p.store.ProvisionRun(runID)
	if err != nil {
		return fmt.Errorf("provision: confirm key: %w", err)
	}
	if run.State != "key_confirm" {
		return fmt.Errorf("provision: run %s is not awaiting key confirmation (state=%s)", runID, run.State)
	}
	if run.KeyLine == "" {
		return fmt.Errorf("provision: run %s has no captured key", runID)
	}

	p.mu.Lock()
	ar := p.runs[runID]
	p.mu.Unlock()
	if ar == nil {
		// The run is paused but this process has no live state machine for it:
		// the server restarted after capturing the key. Resume is not possible
		// (the goroutine is gone and the one-time token is still valid only
		// until its TTL), so fail the run explicitly instead of reporting a
		// success that resumes nothing and leaves a permanent key_confirm
		// zombie.
		const msg = "server restarted while awaiting key confirmation; re-run provisioning"
		p.emitStep(run, 1, stepNames[0], "failed")
		p.setTerminal(run, "failed", msg)
		return fmt.Errorf("provision: run %s lost its state machine (server restart); re-run provisioning", runID)
	}

	// Transition out of key_confirm BEFORE closing the channel so a concurrent
	// or duplicate confirm sees a non-key_confirm state and is rejected.
	if err := p.store.SetProvisionRunState(runID, "confirming", "connect", ""); err != nil {
		return fmt.Errorf("provision: mark confirming: %w", err)
	}

	// Append the public key to known_hosts and hash it. No private material
	// is ever read, copied, or logged.
	if err := p.ssh.AddKey(context.Background(), run.KeyLine); err != nil {
		// Roll back so the operator can retry without a stuck run.
		_ = p.store.SetProvisionRunState(runID, "key_confirm", "connect", "")
		return fmt.Errorf("provision: add to known_hosts: %w", err)
	}
	p.audit("provision.key.confirmed", fmt.Sprintf(`{"run_id":%q,"fingerprint":%q}`, runID, run.Fingerprint))

	// Close at most once: safe under duplicate/racing confirms.
	ar.confirmOnce.Do(func() { close(ar.confirm) })
	return nil
}

// DenyKey cancels a run awaiting key confirmation; nothing changed on the host.
func (p *Provisioner) DenyKey(runID string) error {
	run, err := p.store.ProvisionRun(runID)
	if err != nil {
		return err
	}
	if run.State != "key_confirm" {
		return fmt.Errorf("provision: run %s is not awaiting key confirmation (state=%s)", runID, run.State)
	}
	p.audit("provision.key.denied", fmt.Sprintf(`{"run_id":%q,"fingerprint":%q}`, runID, run.Fingerprint))
	if err := p.store.SetProvisionRunState(runID, "cancelled", "connect", "key confirmation denied"); err != nil {
		return err
	}
	if p.emitter != nil {
		p.emitter.Emit("provision.cancelled", map[string]string{"run_id": runID, "host": run.Host, "state": "cancelled", "error": "key confirmation denied"})
	}
	p.emitStep(run, 1, stepNames[0], "cancelled")
	p.mu.Lock()
	ar := p.runs[runID]
	p.mu.Unlock()
	if ar != nil {
		ar.cancel()
	}
	return nil
}

// Cancel cancels a non-terminal run.
func (p *Provisioner) Cancel(runID string) error {
	run, err := p.store.ProvisionRun(runID)
	if err != nil {
		return err
	}
	if isTerminal(run.State) {
		return nil
	}
	if err := p.store.SetProvisionRunState(runID, "cancelled", run.Step, "cancelled by operator"); err != nil {
		return err
	}
	if p.emitter != nil {
		p.emitter.Emit("provision.cancelled", map[string]string{"run_id": runID, "host": run.Host, "state": "cancelled", "error": "cancelled by operator"})
	}
	p.audit("provision.cancelled", fmt.Sprintf(`{"run_id":%q,"error":"cancelled by operator"}`, runID))
	p.mu.Lock()
	ar := p.runs[runID]
	p.mu.Unlock()
	if ar != nil {
		ar.cancel()
	}
	return nil
}

// ReapStale fails every non-terminal run left behind by a previous process.
// The state machine lives in a goroutine, so a server restart strands
// queued, in-flight, and key_confirm runs forever (nothing drives their
// steps and the one-time enrollment token is not worth salvaging). Marking
// them failed at boot keeps the UI truthful: the operator sees a reason
// instead of a run that can never make progress. Called once from main at
// server startup.
func (p *Provisioner) ReapStale() {
	runs, err := p.store.ProvisionRuns(100)
	if err != nil {
		p.log.Printf("provision: reap stale: %v", err)
		return
	}
	for _, r := range runs {
		if !isTerminal(r.State) {
			p.log.Printf("provision: reaping %s (host=%s state=%s) — server restarted mid-run", r.ID, r.Host, r.State)
			p.setTerminal(r, "failed", "server restarted while the run was in flight; start a new provision run")
		}
	}
}

// run executes the state machine. It blocks on the confirm channel while the
// run is paused at key_confirm.
func (p *Provisioner) run(ctx context.Context, ar *activeRun, run *store.ProvisionRun, token string, opts StartOptions) {
	defer func() {
		p.mu.Lock()
		delete(p.runs, run.ID)
		p.mu.Unlock()
		if r := recover(); r != nil {
			p.log.Printf("provision: %s PANIC: %v", run.ID, r)
			_ = p.store.SetProvisionRunState(run.ID, "failed", run.Step, fmt.Sprint(r))
		}
	}()

	// Step 1: connect (fingerprint gate).
	if !p.stepConnect(ctx, run) {
		// Paused at key_confirm: block until confirmed or cancelled.
		select {
		case <-ar.confirm:
			p.finishStep(run, 1) // step complete now that the key is trusted
		case <-ctx.Done():
			// Only cancel if we are still waiting for a decision. If the
			// operator already confirmed (state=confirming) we must not
			// overwrite that with "cancelled".
			if r, err := p.store.ProvisionRun(run.ID); err == nil && r.State == "key_confirm" {
				p.setTerminal(r, "cancelled", "key confirmation cancelled")
			}
			return
		}
	}

	// Step 2: preflight.
	if !p.stepPreflight(ctx, run) {
		return
	}
	// Step 3: transfer.
	if !p.stepTransfer(ctx, run, opts) {
		return
	}
	// Step 4: install.
	installStarted := time.Now()
	if !p.stepInstall(ctx, run, token, opts) {
		return
	}
	// Step 5: wait-enroll (terminal: connected or failed).
	p.stepWaitEnroll(ctx, run, installStarted)
}

// stepConnect performs the fingerprint gate. Returns true to continue (host
// already trusted), false if it paused at key_confirm.
func (p *Provisioner) stepConnect(ctx context.Context, run *store.ProvisionRun) bool {
	p.setState(run, "connecting", "connect", "")
	p.beginStep(run, 1)

	trusted, err := p.ssh.HasHost(ctx, run.Host)
	if err != nil {
		return p.failStep(run, 1, fmt.Sprintf("known_hosts check failed: %v", err))
	}
	if trusted {
		p.log.Printf("provision: %s host %s already trusted", run.ID, run.Host)
		p.finishStep(run, 1)
		return true
	}

	ft, fp, line, err := p.ssh.HostKey(ctx, run.Host)
	if err != nil {
		return p.failStep(run, 1, fmt.Sprintf("keyscan failed: %v", err))
	}
	if err := p.store.SetProvisionRunKey(run.ID, ft, fp, line); err != nil {
		p.log.Printf("provision: %s store key: %v", run.ID, err)
	}
	// The keyscan line is keyed under the ssh-config-resolved target
	// ("[host]:port" for non-default ports) — surface it on the run so the
	// operator sees what an ssh-config alias actually points at before
	// confirming the fingerprint.
	resolved := ""
	if f := strings.Fields(line); len(f) > 0 {
		resolved = f[0]
	}
	if resolved != "" && resolved != run.Host {
		if err := p.store.SetProvisionRunResolved(run.ID, resolved); err != nil {
			p.log.Printf("provision: %s store resolved: %v", run.ID, err)
		}
		run.ResolvedHost = resolved
	}
	p.setState(run, "key_confirm", "connect", "")
	if err := p.store.FinishProvisionStep(run.ID, 1, "key_confirm", "", ""); err != nil {
		p.log.Printf("provision: %s finish step 1: %v", run.ID, err)
	}
	p.log.Printf("provision: %s key_confirm: %s %s %s", run.ID, run.Host, ft, fp)
	if p.emitter != nil {
		p.emitter.Emit("provision.key_confirm", map[string]string{
			"run_id": run.ID, "host": run.Host, "key_type": ft, "fingerprint": fp, "resolved": resolved,
		})
	}
	return false
}

// stepPreflight runs read-only checks on the remote host. Returns true to
// continue.
func (p *Provisioner) stepPreflight(ctx context.Context, run *store.ProvisionRun) bool {
	p.setState(run, "preflight", "preflight", "")
	p.beginStep(run, 2)

	// The reachability probe is the cheap way to catch the most common
	// real-world failure (a firewall/NAT between the host and the server)
	// before installing anything and burning the wait-enroll window.
	// curl/wget are best-effort: if neither exists we do not fail the run.
	script := fmt.Sprintf(`set +e
echo "os=$(cat /etc/os-release 2>/dev/null | grep -m1 PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "arch=$(uname -m)"
if command -v systemctl >/dev/null 2>&1; then echo "init=systemd"; else echo "init=none"; fi
echo "user=$(whoami)"
if sudo -n true 2>/dev/null; then echo "sudo=yes"; else echo "sudo=no"; fi
# Currently-installed partout version (version-diff check). none = not present.
if [ -x /usr/local/bin/partout ]; then echo "remote_version=$(/usr/local/bin/partout --version 2>/dev/null | awk '{print $2}')"; else echo "remote_version=none"; fi
# Existing agent identity (join mode: the run links to this agent instead of
# waiting for a fresh enrollment — the agent keeps its identity and never
# consumes the new token).
# identity.json is pretty-printed ("uuid": "…" — whitespace after the
# colon), so the extraction tolerates it (field-caught: the rigid pattern
# matched only compact JSON and the join link silently never happened).
echo "agent_uuid=$(sudo -n cat /var/lib/partout/agent/identity.json 2>/dev/null | grep -o '"uuid": *[[:space:]]*"[^"]*"' | cut -d'"' -f4)"
echo "disk=$(df -B1 / 2>/dev/null | awk 'NR==2{print $4}')"
# Host -> server reachability on the control-plane port. The https attempt
# is deliberately unverified (curl -k): preflight only proves the network
# path exists — trust is established later, when the install step places the
# server's CA at /etc/partout/ca.crt. A DNS failure is reported separately
# from a refused/filtered port: curl exit 6 means the address itself is bad
# (typically PARTOUT_SERVER_HOST defaulting to a bare hostname the target
# cannot resolve), which no firewall change can fix.
SRV=%s
if command -v curl >/dev/null 2>&1; then
  if curl -kfsS --max-time 5 "https://$SRV/healthz" >/dev/null 2>&1; then echo "reach=yes-tls"
  elif curl -fsS --max-time 5 "http://$SRV/healthz" >/dev/null 2>&1; then echo "reach=yes-plain"
  elif [ "$?" = "6" ]; then echo "reach=dns"
  else echo "reach=no"; fi
elif command -v wget >/dev/null 2>&1; then
  if wget -q -T 5 --no-check-certificate -O /dev/null "https://$SRV/healthz" 2>/dev/null; then echo "reach=yes-tls"
  elif wget -q -T 5 -O /dev/null "http://$SRV/healthz" 2>/dev/null; then echo "reach=yes-plain"
  else echo "reach=no"; fi
else
  echo "reach=unknown"
fi
`, shellQuote(p.serverHost))

	out, stderr, exit, err := p.ssh.Run(ctx, run.Host, script)
	if err != nil {
		return p.failStep(run, 2, fmt.Sprintf("ssh failed: %v", err))
	}
	if exit != 0 {
		return p.failStep(run, 2, p.keyHint(p.authHint(fmt.Sprintf("preflight exit %d: %s", exit, strings.TrimSpace(stderr)))))
	}

	facts := parseKeyValues(out)
	p.log.Printf("provision: %s preflight: %v", run.ID, facts)

	// Version-diff check (read-only): report the currently-installed agent
	// version vs the version about to be installed, so the operator sees an
	// install vs upgrade (and in which direction) before anything changes.
	remoteVer := facts["remote_version"]
	facts["update"] = versionNote(remoteVer, p.localVersion)
	p.log.Printf("provision: %s version: remote=%s local=%s (%s)", run.ID, remoteVer, p.localVersion, facts["update"])

	// Join mode + an existing agent: link the run to it NOW (field friction:
	// the run used to wait for a fresh enrollment that never happens — the
	// agent keeps its identity and does not consume the token, so wait-enroll
	// always timed out with "agent did not connect within 60s" even though
	// the update had fully succeeded).
	if run.Mode == "join" && facts["agent_uuid"] != "" {
		if agent, err := p.store.AgentByUUID(facts["agent_uuid"]); err == nil && agent != nil {
			if err := p.store.LinkProvisionRunAgent(run.ID, agent.ID); err == nil {
				run.AgentID = agent.ID
				p.log.Printf("provision: %s join: existing agent %s will be updated in place", run.ID, agent.ID)
			} else {
				p.log.Printf("provision: %s join: link agent: %v", run.ID, err)
			}
		}
	}

	if facts["init"] != "systemd" {
		_ = p.store.FinishProvisionStep(run.ID, 2, "handoff", out, "")
		p.setTerminal(run, "handoff", "non-systemd init; manual install required")
		return false
	}
	if facts["sudo"] != "yes" {
		return p.failStep(run, 2, "install needs root or NOPASSWD sudo; grant the ssh user passwordless sudo")
	}
	// reach=unknown means neither curl nor wget is present: warn but continue,
	// since the agent itself (Go) does not need them.
	if facts["reach"] == "dns" {
		return p.failStep(run, 2, fmt.Sprintf(
			"host cannot resolve the server address %s — set PARTOUT_SERVER_HOST to an IP or a name every target host can resolve",
			p.serverHost))
	}
	if facts["reach"] == "no" {
		// A loopback-only server bind can never be reached from a remote host —
		// no firewall change fixes that, so say so instead of sending the
		// operator to debug their network.
		if config.LoopbackBind(p.bindAddr) {
			return p.failStep(run, 2, fmt.Sprintf(
				"host cannot reach the server at %s: the server binds %s (loopback-only), which no remote host can ever reach — set PARTOUT_ADDR to a routable address (e.g. the LAN IP) and restart the server, or provision same-host agents only",
				p.serverHost, p.bindAddr))
		}
		return p.failStep(run, 2, fmt.Sprintf(
			"host cannot reach the server at %s on the control-plane port; open the firewall/NAT path before provisioning",
			p.serverHost))
	}

	// Record the version-diff note in the step output so it is visible in the
	// step detail + SSE (preflight is the read-only step where the diff is known).
	verNote := fmt.Sprintf("remote_version=%s local_version=%s update=%s", remoteVer, p.localVersion, facts["update"])
	if err := p.store.FinishProvisionStep(run.ID, 2, "done", verNote, ""); err != nil {
		p.log.Printf("provision: %s finish preflight: %v", run.ID, err)
	}
	p.emitStep(run, 2, stepNames[1], "done")
	return true
}

// stepTransfer scp's the server binary (and, when TLS is on, the root CA)
// to the host. Returns true to continue.
func (p *Provisioner) stepTransfer(ctx context.Context, run *store.ProvisionRun, opts StartOptions) bool {
	p.setState(run, "transferring", "transfer", "")
	p.beginStep(run, 3)

	sha, err := sha256Of(p.binaryPath)
	if err != nil {
		return p.failStep(run, 3, fmt.Sprintf("read binary %s: %v", p.binaryPath, err))
	}
	remote := "/tmp/partout-" + hex.EncodeToString(sha[:])[:12]
	if _, err := p.ssh.Copy(ctx, p.binaryPath, run.Host, remote); err != nil {
		return p.failStep(run, 3, p.keyHint(p.authHint(fmt.Sprintf("scp failed: %v", err))))
	}
	// The server's root CA rides along when TLS is on, so the provisioned
	// agent trusts the server from its very first connection (HTTPS
	// enrollment + mTLS stream). Without it the agent could not verify the
	// locally-bootstrapped CA at all.
	if p.caPath != "" {
		caSHA, err := sha256Of(p.caPath)
		if err != nil {
			return p.failStep(run, 3, fmt.Sprintf("read CA %s: %v", p.caPath, err))
		}
		remoteCA := "/tmp/partout-ca-" + hex.EncodeToString(caSHA[:])[:12]
		if _, err := p.ssh.Copy(ctx, p.caPath, run.Host, remoteCA); err != nil {
			return p.failStep(run, 3, p.authHint(fmt.Sprintf("scp CA failed: %v", err)))
		}
	}
	// The M8.1 update guard rides along too (installed to
	// /usr/local/sbin/partout-update-guard by the install script).
	guardLocal, gerr := os.CreateTemp("", "partout-guard-*")
	if gerr != nil {
		return p.failStep(run, 3, fmt.Sprintf("stage update guard: %v", gerr))
	}
	if _, err := guardLocal.WriteString(embedded.UpdateGuard); err != nil {
		guardLocal.Close()
		os.Remove(guardLocal.Name())
		return p.failStep(run, 3, fmt.Sprintf("stage update guard: %v", err))
	}
	guardLocal.Close()
	defer os.Remove(guardLocal.Name())
	if _, err := p.ssh.Copy(ctx, guardLocal.Name(), run.Host, "/tmp/partout-update-guard"); err != nil {
		return p.failStep(run, 3, p.authHint(fmt.Sprintf("scp update guard failed: %v", err)))
	}
	// Elevation policies ride along the same way (D1 bootstrap): the
	// operator's canonical privilege documents, sha-verified on the target
	// before anything trusts them.
	for _, ep := range opts.ElevationPolicies {
		local := p.writeTempPolicy(ep)
		if local == "" {
			return p.failStep(run, 3, fmt.Sprintf("elevation policy %s: cannot stage content", ep.Name))
		}
		defer os.Remove(local)
		remote := "/tmp/partout-elev-" + ep.SHA[:12]
		if _, err := p.ssh.Copy(ctx, local, run.Host, remote); err != nil {
			return p.failStep(run, 3, p.authHint(fmt.Sprintf("scp elevation policy %s failed: %v", ep.Name, err)))
		}
	}
	p.finishStep(run, 3)
	return true
}

// writeTempPolicy stages one policy's canonical JSON in a temp file for
// scp ("" on failure).
func (p *Provisioner) writeTempPolicy(ep ElevationPolicySpec) string {
	f, err := os.CreateTemp("", "partout-elev-*.json")
	if err != nil {
		return ""
	}
	// The drop-in must be a full {"rules":[...]} document (the store keeps
	// the canonical bare array; the on-disk format is the document form).
	if _, err := f.WriteString(`{"rules":` + ep.RulesJSON + `}`); err != nil {
		f.Close()
		os.Remove(f.Name())
		return ""
	}
	f.Close()
	return f.Name()
}

// stepInstall runs the install script as root on the host. Returns true to
// continue.
func (p *Provisioner) stepInstall(ctx context.Context, run *store.ProvisionRun, token string, opts StartOptions) bool {
	p.setState(run, "installing", "install", "")
	p.beginStep(run, 4)

	sha, err := sha256Of(p.binaryPath)
	if err != nil {
		return p.failStep(run, 4, fmt.Sprintf("read binary %s: %v", p.binaryPath, err))
	}
	sha12 := hex.EncodeToString(sha[:])[:12]
	fullSHA := hex.EncodeToString(sha[:])

	spec := installSpec{
		binSHA12:   sha12,
		binSHA:     fullSHA,
		wipe:       wipeScript(run.Mode),
		serverHost: p.serverHost,
		token:      token,
		elevation:  elevationScript(opts),
		envExtras:  agentEnvExtras(opts),
	}
	// The CA fingerprint is part of the install contract when TLS is on:
	// the script verifies it before trusting /etc/partout/ca.crt.
	if p.caPath != "" {
		caSHA, err := sha256Of(p.caPath)
		if err != nil {
			return p.failStep(run, 4, fmt.Sprintf("read CA %s: %v", p.caPath, err))
		}
		spec.caSHA12 = hex.EncodeToString(caSHA[:])[:12]
		spec.caSHA = hex.EncodeToString(caSHA[:])
	}

	script := buildInstallScript(spec)

	// Pipe the script as base64 through sudo bash -s (avoids stdin plumbing
	// and shell-quoting issues). The token is one-time + short-TTL and is
	// never logged.
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	cmd := fmt.Sprintf("echo %s | base64 -d | sudo -n bash -s", b64)
	out, stderr, exit, err := p.ssh.Run(ctx, run.Host, cmd)
	if err != nil {
		return p.failStep(run, 4, fmt.Sprintf("ssh failed: %v", err))
	}
	if exit != 0 || !strings.Contains(out, "INSTALL_OK") {
		return p.failStep(run, 4, p.keyHint(p.authHint(fmt.Sprintf("install exit %d: %s", exit, strings.TrimSpace(stderr)))))
	}
	p.finishStep(run, 4)
	return true
}

// wipeScript returns the destructive-wipe prelude for fresh mode (stop +
// disable the existing agent unit, remove its identity + env so the reinstall
// enrolls as a brand-new agent), or "" for join mode (non-destructive in-place
// update that preserves existing state).
func wipeScript(mode string) string {
	if mode != "fresh" {
		return ""
	}
	return `# fresh mode: destructive wipe of existing agent state
systemctl stop partout-agent 2>/dev/null || true
systemctl disable partout-agent 2>/dev/null || true
rm -rf /var/lib/partout/agent
rm -f /etc/partout/agent.env
`
}

// versionNote summarizes the version-diff for the preflight step: whether the
// host gets a fresh install, is already at the target version, or an upgrade
// (with direction). remoteVer is "none"/"" when no agent is installed yet.
func versionNote(remoteVer, localVer string) string {
	switch {
	case remoteVer == "" || remoteVer == "none":
		return "install"
	case remoteVer == localVer:
		return "same (" + localVer + ")"
	default:
		return remoteVer + " -> " + localVer
	}
}

// installSpec renders the one-shot root install script. The ca fields are
// empty when the server runs without TLS — the script then carries no CA
// block and no PARTOUT_TLS_CA line (byte-compatible with the pre-TLS
// installer). serverHost and token are inserted raw into the quoted
// (<<'EOF') heredoc — they must NOT be shell-quoted there or the env file
// would contain literal quotes (token is prefix+hex and serverHost is
// host:port, both quote-safe).
type installSpec struct {
	binSHA12, binSHA  string // agent binary fingerprint (transfer verification)
	caSHA12, caSHA    string // root-CA fingerprint; both empty = TLS off
	wipe              string // mode-specific prelude ("" for join)
	serverHost, token string
	// elevation is the D1 bootstrap block ("" = no elevation): installs
	// the transferred policies to /etc/partout/elevation.d/, renders +
	// visudo-checks + installs the sudoers drop-in (as root, on the
	// target), and wires PARTOUT_ELEVATE in agent.env.
	elevation string
	// envExtras are extra agent.env lines (service labels, cert paths).
	envExtras string
}

// slugPolicyName makes a policy name filesystem-safe for its drop-in.
func slugPolicyName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "policy"
	}
	return out
}

// elevationScript renders the root-side elevation bootstrap for the
// install script. Policies were transferred as /tmp/partout-elev-<sha12>
// and are verified against the full sha before install (the same contract
// as the binary and the CA).
func elevationScript(opts StartOptions) string {
	if !opts.Elevate || len(opts.ElevationPolicies) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Elevation bootstrap (PRD Decision 3, onboarding): install the\n")
	b.WriteString("# operator's elevation policies, then render + visudo-check + install\n")
	b.WriteString("# the sudoers drop-in FROM them (single source of truth). Runs as root;\n")
	b.WriteString("# a bad policy aborts the install here, at the earliest possible moment.\n")
	// install -d with an EXPLICIT mode: the install script runs under
	// `umask 077`, so a bare mkdir -p would create the dir 0700 root-only
	// and the agent could never read its own policy (field-caught on the
	// v0.9.11 run: the agent degraded to legacy elevation mode).
	b.WriteString("install -d -m 0755 /etc/partout/elevation.d\n")
	for i, ep := range opts.ElevationPolicies {
		fmt.Fprintf(&b, "ELEV=/tmp/partout-elev-%s\n", ep.SHA[:12])
		fmt.Fprintf(&b, "ELEVACT=$(sha256sum \"$ELEV\" | cut -d' ' -f1)\n")
		fmt.Fprintf(&b, "if [ \"$ELEVACT\" != %s ]; then echo \"elevation policy %s sha256 mismatch: $ELEVACT\" >&2; exit 1; fi\n",
			shellQuote(ep.SHA), ep.Name)
		fmt.Fprintf(&b, "install -m 0644 -o root -g root \"$ELEV\" /etc/partout/elevation.d/%02d-%s.json\n", (i+1)*10, slugPolicyName(ep.Name))
		b.WriteString("rm -f \"$ELEV\"\n")
	}
	// Render + install sudoers from the same policy (visudo-checked before
	// anything is touched). Full path: sudo's secure_path may not include
	// /usr/local/bin on the target.
	b.WriteString("PARTOUT_ELEVATION_POLICY=/etc/partout/elevation.d /usr/local/bin/partout ctl elevation install-sudoers || { echo \"elevation: install-sudoers failed (bad policy?)\" >&2; exit 1; }\n")
	return b.String()
}

// agentEnvExtras renders the additional agent.env lines from the options.
func agentEnvExtras(opts StartOptions) string {
	var b strings.Builder
	if opts.Elevate {
		b.WriteString("PARTOUT_ELEVATE=sudo\n")
		b.WriteString("PARTOUT_ELEVATION_POLICY=/etc/partout/elevation.d\n")
	}
	if opts.ServiceLabels != "" {
		fmt.Fprintf(&b, "PARTOUT_SERVICE_LABELS=%s\n", opts.ServiceLabels)
	}
	if opts.CertPaths != "" {
		fmt.Fprintf(&b, "PARTOUT_CERT_PATHS=%s\n", opts.CertPaths)
	}
	return b.String()
}

// JoinScriptInput is everything the one-line join script (E1) needs.
// The script it renders is a curl prelude that materializes the exact
// /tmp files the field-proven installer expects, followed by that
// installer verbatim — the join path and the SSH-provisioning path share
// one install body, so they cannot drift.
type JoinScriptInput struct {
	// BaseURL is scheme://host:port the target host can reach (it fetched
	// the loader from there, so by construction it can reach it again).
	BaseURL string
	// Token is the one-time enrollment token (embedded in download URLs).
	Token string
	// Arch is the target arch (amd64|arm64) — the arch-specific script is
	// rendered per request.
	Arch string
	// BinSHA / BinVersion fingerprint the binary the prelude downloads.
	BinSHA     string
	BinVersion string
	// CAPEM is the root CA (TLS servers); empty = plaintext server.
	CAPEM string
	// Policies are the elevation documents to install (nil = no
	// elevation).
	Policies []ElevationPolicySpec
	// ServiceLabels / CertPaths are agent.env extras (same as StartOptions).
	ServiceLabels string
	CertPaths     string
}

// BuildJoinScript renders the arch-specific one-line join installer.
// Everything except the binary is staged inline as base64 (policy JSON,
// the CA, the update guard); the binary is fetched from the control plane
// and verified by the installer's sha256 gate like any provision transfer.
// Base64 (not heredocs) because the transferred bytes must match their
// sha256 EXACTLY — a heredoc always appends a trailing newline, which
// would break the CA/policy verification the install body performs.
func BuildJoinScript(in JoinScriptInput) (string, error) {
	if in.BaseURL == "" || in.Token == "" || in.Arch == "" || in.BinSHA == "" || len(in.BinSHA) < 12 {
		return "", fmt.Errorf("provision: join script requires base URL, token, arch, and binary sha")
	}
	var b strings.Builder
	b.WriteString("# partout join — one-line bootstrap (E1). Generated for arch " + in.Arch)
	if in.BinVersion != "" {
		b.WriteString(" (binary " + in.BinVersion + ")")
	}
	b.WriteString(".\n")
	b.WriteString("# Runs as root (curl … | sudo bash). Idempotent; safe to re-run.\n")
	b.WriteString("# The install body below is the SAME script SSH provisioning runs —\n")
	b.WriteString("# only the fetch prelude differs (curl from the control plane vs scp).\n")
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "ARCH=%s\n", in.Arch)
	fmt.Fprintf(&b, "BIN=/tmp/partout-%s\n", in.BinSHA[:12])
	fmt.Fprintf(&b, "curl -fsSL -o \"$BIN\" %s/api/v1/join/%s/binary?arch=%s || { echo \"join: no agent binary for arch %s on this server (upload a release for it on the Updates page, or install from GitHub releases)\" >&2; exit 1; }\n",
		shellQuote(in.BaseURL), in.Token, in.Arch, in.Arch)
	caSHA := ""
	if in.CAPEM != "" {
		caSHA = sha256Hex(in.CAPEM)
		fmt.Fprintf(&b, "CA=/tmp/partout-ca-%s\n", caSHA[:12])
		fmt.Fprintf(&b, "printf '%%s' %s | base64 -d > \"$CA\"\n", shellQuote(base64.StdEncoding.EncodeToString([]byte(in.CAPEM))))
	}
	for _, ep := range in.Policies {
		fmt.Fprintf(&b, "ELEV=/tmp/partout-elev-%s\n", ep.SHA[:12])
		fmt.Fprintf(&b, "printf '%%s' %s | base64 -d > \"$ELEV\"\n",
			shellQuote(base64.StdEncoding.EncodeToString([]byte(`{"rules":`+ep.RulesJSON+`}`))))
	}
	// The update guard: same embedded copy the provisioner ships.
	b.WriteString("GUARD=/tmp/partout-update-guard\n")
	fmt.Fprintf(&b, "printf '%%s' %s | base64 -d > \"$GUARD\"\n",
		shellQuote(base64.StdEncoding.EncodeToString([]byte(embedded.UpdateGuard))))

	// The install body: byte-identical to the SSH-provisioning install.
	b.WriteString(buildInstallScript(installSpec{
		binSHA12:   in.BinSHA[:12],
		binSHA:     in.BinSHA,
		caSHA:      caSHA,
		serverHost: hostOf(in.BaseURL),
		token:      in.Token,
		elevation:  elevationScript(StartOptions{Elevate: len(in.Policies) > 0, ElevationPolicies: in.Policies}),
		envExtras:  agentEnvExtras(StartOptions{Elevate: len(in.Policies) > 0, ServiceLabels: in.ServiceLabels, CertPaths: in.CertPaths}),
	}))
	return b.String(), nil
}

// BuildJoinLoader renders the arch-detecting first-stage script: fetch the
// arch-specific installer from the control plane and run it. The elevate
// and labels values are server-validated before they are embedded (the
// caller guarantees: policy name resolved from the store, labels matching
// ^[A-Za-z0-9,_.-]*$).
func BuildJoinLoader(baseURL, token, elevate, labels string) string {
	var b strings.Builder
	b.WriteString("# partout join — stage 1/2: detect the arch, fetch the arch-specific installer.\n")
	b.WriteString("# Stage 2 carries the sha256-verified install (same body as SSH provisioning).\n")
	b.WriteString("set -eu\n")
	b.WriteString("ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')\n")
	fmt.Fprintf(&b, "URL=%s\n", shellQuote(baseURL+"/api/v1/join/"+token+"?arch=")+"\"$ARCH\"")
	if elevate != "" {
		fmt.Fprintf(&b, "URL=\"$URL\"%s\n", shellQuote("&elevate="+elevate))
	}
	if labels != "" {
		fmt.Fprintf(&b, "URL=\"$URL\"%s\n", shellQuote("&labels="+labels))
	}
	b.WriteString("SCRIPT=$(mktemp /tmp/partout-join.XXXXXX)\n")
	b.WriteString("trap 'rm -f \"$SCRIPT\"' EXIT\n")
	b.WriteString("curl -fsSL -o \"$SCRIPT\" \"$URL\"\n")
	b.WriteString("sh \"$SCRIPT\"\n")
	return b.String()
}

// hostOf strips the scheme from a base URL (https://h: p → h: p).
func hostOf(baseURL string) string {
	s := strings.TrimPrefix(baseURL, "https://")
	return strings.TrimPrefix(s, "http://")
}

// ElevationBootstrapInput is the one-line elevation enablement for an
// already-enrolled host (P1): the operator pastes ONE root command on the
// host instead of the six-step manual dance (policy file, install-sudoers
// with the secure_path full-path trap, agent.env, NoNewPrivileges,
// daemon-reload, restart).
type ElevationBootstrapInput struct {
	// Hostname is the agent's reported hostname (the paste guard); empty
	// skips the guard (pre-reporting agents).
	Hostname string
	// PolicyName / RulesJSON / SHA are the canonical stored policy.
	PolicyName string
	RulesJSON  string
	SHA        string
}

// BuildElevationBootstrapScript renders the root script the host runs. It
// is deliberately boring: stage the policy, render + visudo-check the
// sudoers drop-in via the binary ALREADY on the host, wire the env, drop
// NoNewPrivileges, restart, verify. Fail-closed throughout (set -eu).
func BuildElevationBootstrapScript(in ElevationBootstrapInput) (string, error) {
	if in.RulesJSON == "" || in.PolicyName == "" {
		return "", fmt.Errorf("provision: elevation bootstrap requires a policy")
	}
	var b strings.Builder
	b.WriteString("# partout elevation bootstrap — generated for host " + in.Hostname)
	b.WriteString(" (policy " + in.PolicyName + ").\n")
	b.WriteString("# Runs as root ON the host (curl … | sudo bash). One command instead of the\n")
	b.WriteString("# six-step manual dance; the sudoers wall itself is rendered from the\n")
	b.WriteString("# policy ON the host (visudo-checked before anything is touched).\n")
	b.WriteString("set -eu\n")
	if in.Hostname != "" {
		b.WriteString("# Paste guard: this bootstrap was minted for one specific host.\n")
		fmt.Fprintf(&b, "EXPECT_HOST=%s\n", shellQuote(strings.ToLower(strings.SplitN(in.Hostname, ".", 2)[0])))
		b.WriteString("ACTUAL_HOST=$(hostname 2>/dev/null || true); ACTUAL_HOST=${ACTUAL_HOST%%.*}; ACTUAL_HOST=$(printf '%s' \"$ACTUAL_HOST\" | tr '[:upper:]' '[:lower:]')\n")
		b.WriteString("[ \"$ACTUAL_HOST\" = \"$EXPECT_HOST\" ] || { echo \"wrong host: this elevation bootstrap was minted for \"$EXPECT_HOST\" but this is \"$ACTUAL_HOST\"\" >&2; exit 1; }\n")
	}
	b.WriteString("BIN=/usr/local/bin/partout\n")
	b.WriteString("[ -x \"$BIN\" ] || { echo \"partout binary not found at $BIN — is this host enrolled with the M8.1 layout?\" >&2; exit 1; }\n")
	b.WriteString("command -v visudo >/dev/null 2>&1 || { echo \"visudo not found — install the sudo package first\" >&2; exit 1; }\n")
	b.WriteString("install -d -m 0755 /etc/partout/elevation.d\n")
	fmt.Fprintf(&b, "ELEV=/etc/partout/elevation.d/10-%s.json\n", slugPolicyName(in.PolicyName))
	fmt.Fprintf(&b, "printf '%%s' %s | base64 -d > \"$ELEV\"\n", shellQuote(base64.StdEncoding.EncodeToString([]byte(`{"rules":`+in.RulesJSON+`}`))))
	b.WriteString("chmod 0644 \"$ELEV\"\n")
	b.WriteString("# Render + install the sudoers drop-in FROM the policy (single source of\n")
	b.WriteString("# truth; visudo-checked before anything is touched).\n")
	b.WriteString("PARTOUT_ELEVATION_POLICY=/etc/partout/elevation.d \"$BIN\" ctl elevation install-sudoers\n")
	b.WriteString("# Wire the agent env (idempotent: replace the two elevation keys).\n")
	b.WriteString("ENVF=/etc/partout/agent.env\n")
	b.WriteString("[ -f \"$ENVF\" ] || { echo \"agent.env missing at $ENVF\" >&2; exit 1; }\n")
	b.WriteString("sed -i '/^PARTOUT_ELEVATE=/d; /^PARTOUT_ELEVATION_POLICY=/d' \"$ENVF\"\n")
	b.WriteString("printf 'PARTOUT_ELEVATE=sudo\\nPARTOUT_ELEVATION_POLICY=/etc/partout/elevation.d\\n' >> \"$ENVF\"\n")
	b.WriteString("# sudo needs setuid: drop a NoNewPrivileges line from the unit if present.\n")
	b.WriteString("UNIT=/etc/systemd/system/partout-agent.service\n")
	b.WriteString("if [ -f \"$UNIT\" ] && grep -q '^NoNewPrivileges' \"$UNIT\"; then\n")
	b.WriteString("  sed -i '/^NoNewPrivileges/d' \"$UNIT\"\n")
	b.WriteString("  systemctl daemon-reload\n")
	b.WriteString("fi\n")
	b.WriteString("systemctl restart partout-agent\n")
	b.WriteString("sleep 1\n")
	b.WriteString("\"$BIN\" ctl elevation check || true\n")
	b.WriteString("echo ELEVATION_OK — the agent restarted with elevation enabled; posture shows in the UI within a facts cycle (~5 min).\n")
	return b.String(), nil
}

func buildInstallScript(s installSpec) string {
	// CA install + env line only when TLS is on: verify the transferred CA
	// against its expected sha256, then place it where the agent expects it
	// (PARTOUT_TLS_CA). The CA is public material (0644); the private key
	// never leaves the server.
	caBlock, envCA := "", ""
	if s.caSHA != "" {
		caBlock = fmt.Sprintf(`CA=/tmp/partout-ca-%s
CAACT=$(sha256sum "$CA" | cut -d' ' -f1)
if [ "$CAACT" != %s ]; then echo "ca sha256 mismatch: $CAACT" >&2; exit 1; fi
install -m 0644 "$CA" /etc/partout/ca.crt
rm -f "$CA"
`, s.caSHA12, shellQuote(s.caSHA))
		envCA = "PARTOUT_TLS_CA=/etc/partout/ca.crt\n"
	}
	return fmt.Sprintf(`set -eu
BIN=/tmp/partout-%s
EXPECT=%s
ACTUAL=$(sha256sum "$BIN" | cut -d' ' -f1)
if [ "$ACTUAL" != "$EXPECT" ]; then echo "sha256 mismatch: $ACTUAL" >&2; exit 1; fi
%s# M8.1 layout: the agent's binary lives in an AGENT-WRITABLE dir
# (/var/lib/partout/bin) with a symlink from /usr/local/bin for operators —
# the self-swap writes <dir>/partout.old + .new next to the real binary,
# which a root-owned /usr/local/bin forbids (field-caught on the v0.9.12
# rollout: "write N-1 retention copy: permission denied").
id partout >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin partout
install -d -m 0750 -o partout -g partout /var/lib/partout/bin
install -m 0755 -o partout -g partout "$BIN" /var/lib/partout/bin/partout
# /usr/local/bin/partout becomes a symlink (replace a legacy real file).
rm -f /usr/local/bin/partout
ln -s /var/lib/partout/bin/partout /usr/local/bin/partout
# M8.1 boot guard: supervises the self-swap and rolls a failed update back
# to N-1 (same script as deploy/systemd/partout-update-guard.sh).
install -m 0755 -o root -g root /tmp/partout-update-guard /usr/local/sbin/partout-update-guard
mkdir -p /var/lib/partout/agent
chown partout:partout /var/lib/partout/agent
chmod 0750 /var/lib/partout/agent
# File root (docs/spec-file-root.md): the file surface is confined to this
# directory; no role or parameter can reach outside it through the file API.
mkdir -p /home/partout
chown partout:partout /home/partout
chmod 0750 /home/partout
mkdir -p /etc/partout
umask 077
%s%s# agent identity material lives under DATA_DIR (0700); the CA is a public cert
cat > /etc/partout/agent.env <<'EOF'
PARTOUT_MODE=agent
PARTOUT_SERVER=%s
PARTOUT_TOKEN=%s
PARTOUT_DATA_DIR=/var/lib/partout/agent
# Elevation (opt-in, PRD Decision 3): package applies and other
# root-requiring actions need it — the sudoers scope is an elevation
# policy installed by the provisioner (--elevate) or by hand
# ("partout ctl elevation install-sudoers").
%sEOF
chmod 0640 /etc/partout/agent.env
cat > /etc/systemd/system/partout-agent.service <<'EOF'
[Unit]
Description=Partout host agent
After=network-online.target
Wants=network-online.target
# M8.1: a crashlooping post-update binary must keep restarting until the
# boot guard rolls it back; systemd's default start limit would park the
# unit in failed first.
StartLimitIntervalSec=0

[Service]
Type=simple
User=partout
EnvironmentFile=/etc/partout/agent.env
# M8.1: the guard supervises the self-swap (N-1 rollback), then execs the
# real binary from the agent-writable dir.
Environment=PARTOUT_AGENT_DATA_DIR=/var/lib/partout/agent
Environment=PARTOUT_GUARD_BIN=/var/lib/partout/bin/partout
ExecStart=/usr/local/sbin/partout-update-guard
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable partout-agent
systemctl restart partout-agent
rm -f "$BIN"
echo INSTALL_OK
`, s.binSHA12, s.binSHA, s.wipe, caBlock, s.elevation, s.serverHost, s.token, s.envExtras+envCA)
}

// stepWaitEnroll polls until the agent from this run has connected. Terminal:
// connected (success) or failed (timeout).
func (p *Provisioner) stepWaitEnroll(ctx context.Context, run *store.ProvisionRun, installStarted time.Time) {
	p.setState(run, "enrolling", stepNames[4], "")
	p.beginStep(run, 5)

	// Join mode with a linked existing agent (linked at preflight): the agent
	// keeps its identity and reconnects after the install restarts it — wait
	// for a fresh connection (last_seen after the install began), not for a
	// token enrollment that never happens.
	if run.AgentID != "" {
		agent, _ := p.store.Agent(run.AgentID)
		if agent != nil {
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				agent, err := p.store.Agent(run.AgentID)
				if err == nil && agent != nil && agent.State == "connected" && agent.LastSeen >= installStarted.Unix() {
					_ = p.store.FinishProvisionStep(run.ID, 5, "done", "", "")
					p.setTerminal(run, "connected", "")
					p.audit("provision.completed", fmt.Sprintf(`{"run_id":%q,"agent_id":%q,"mode":%q,"updated":true}`, run.ID, agent.ID, run.Mode))
					if p.emitter != nil {
						p.emitter.Emit("provision.connected", map[string]string{"run_id": run.ID, "agent_id": agent.ID})
					}
					return
				}
			}
			_ = p.store.FinishProvisionStep(run.ID, 5, "failed", "", "existing agent did not reconnect within 60s")
			p.setTerminal(run, "failed", "existing agent did not reconnect within 60s")
			return
		}
		// Agent row vanished (removed from the fleet mid-run): fall through
		// to the token path — the timeout below reports it.
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		cur, err := p.store.ProvisionRun(run.ID)
		if err != nil {
			break
		}
		if cur.AgentID == "" {
			continue
		}
		agent, err := p.store.Agent(cur.AgentID)
		if err != nil || agent == nil {
			continue
		}
		if agent.State == "connected" {
			_ = p.store.FinishProvisionStep(run.ID, 5, "done", "", "")
			p.setTerminal(run, "connected", "")
			p.audit("provision.completed", fmt.Sprintf(`{"run_id":%q,"agent_id":%q,"mode":%q}`, run.ID, agent.ID, run.Mode))
			if p.emitter != nil {
				p.emitter.Emit("provision.connected", map[string]string{"run_id": run.ID, "agent_id": agent.ID})
			}
			return
		}
	}
	_ = p.store.FinishProvisionStep(run.ID, 5, "failed", "", "agent did not connect within 60s")
	p.setTerminal(run, "failed", "agent did not connect within 60s")
}

// ---- step bookkeeping ------------------------------------------------------

func (p *Provisioner) setState(run *store.ProvisionRun, state, step, errMsg string) {
	if err := p.store.SetProvisionRunState(run.ID, state, step, errMsg); err != nil {
		p.log.Printf("provision: %s set %s: %v", run.ID, state, err)
	}
}

func (p *Provisioner) beginStep(run *store.ProvisionRun, seq int) {
	if err := p.store.StartProvisionStep(run.ID, seq); err != nil {
		p.log.Printf("provision: %s begin step %d: %v", run.ID, seq, err)
	}
	p.emitStep(run, seq, stepNames[seq-1], "running")
}

// finishStep marks step seq done and emits + audits.
func (p *Provisioner) finishStep(run *store.ProvisionRun, seq int) {
	if err := p.store.FinishProvisionStep(run.ID, seq, "done", "", ""); err != nil {
		p.log.Printf("provision: %s finish step %d: %v", run.ID, seq, err)
	}
	p.emitStep(run, seq, stepNames[seq-1], "done")
}

// failStep marks step seq failed, transitions the run to failed, and returns
// false (stop the state machine).
// authHint augments ssh errors with an actionable hint for the most common
// first-run failure: the server process user's SSH dir presents no key the
// target accepts ("Permission denied (publickey)"). OpenSSH resolves ~/.ssh
// from the passwd database, so a service user's home (e.g. /var/lib/partout)
// is where the key must live — the operator's own ~/.ssh is not readable.
func (p *Provisioner) authHint(msg string) string {
	if !strings.Contains(msg, "Permission denied") {
		return msg
	}
	dir := p.ssh.SSHDir
	if dir == "" {
		dir = "the server user's ~/.ssh"
	}
	return msg + " — no usable SSH client key: " + dir + " offers no key this host accepts; " +
		"create one there as the server user (ssh-keygen -t ed25519) and add its public key " +
		"to the target's authorized_keys, then re-run"
}

// keyHint augments ssh errors that stem from a host-key mismatch (a
// reinstalled host presents a new key): instead of dead-ending at OpenSSH's
// raw banner, point at the re-confirm flow, which re-gates the new key
// through key_confirm.
func (p *Provisioner) keyHint(msg string) string {
	if !strings.Contains(msg, "REMOTE HOST IDENTIFICATION HAS CHANGED") &&
		!strings.Contains(msg, "Host key verification failed") {
		return msg
	}
	return msg + " — the host's key no longer matches the trusted entry (host reinstalled?); use Re-confirm key on the run to review and accept the new key"
}

// ReconfirmKey restarts the fingerprint gate for a failed run whose host
// key no longer matches the trusted entry (host reinstalled, key rotated):
// it removes the stale entry, re-captures the current key, and pauses the
// run at key_confirm again — rotation goes through the same deliberate
// operator gate as first contact instead of dead-ending at ssh's raw
// banner. The state machine is relaunched with a fresh one-time enrollment
// token (the original may have expired while the run sat failed).
func (p *Provisioner) ReconfirmKey(runID string) error {
	p.mu.Lock()
	if _, active := p.runs[runID]; active {
		p.mu.Unlock()
		return fmt.Errorf("provision: run %s already has a live state machine", runID)
	}
	p.mu.Unlock()

	run, err := p.store.ProvisionRun(runID)
	if err != nil {
		return fmt.Errorf("provision: reconfirm key: %w", err)
	}
	if run.State != "failed" {
		return fmt.Errorf("provision: run %s is not failed (state=%s); only a failed run can re-confirm its key", runID, run.State)
	}

	// Drop the stale entry (plain + hashed) under the resolved name.
	ctx := context.Background()
	res, err := p.ssh.ResolveHost(ctx, run.Host)
	if err != nil {
		return fmt.Errorf("provision: resolve %s: %w", run.Host, err)
	}
	if err := p.ssh.RemoveHost(ctx, res.Name()); err != nil {
		return fmt.Errorf("provision: remove stale key: %w", err)
	}

	// Re-capture the current key and pause at the gate again.
	ft, fp, line, err := p.ssh.HostKey(ctx, run.Host)
	if err != nil {
		return fmt.Errorf("provision: recapture key: %w", err)
	}
	if err := p.store.SetProvisionRunKey(runID, ft, fp, line); err != nil {
		return fmt.Errorf("provision: store key: %w", err)
	}
	resolved := ""
	if f := strings.Fields(line); len(f) > 0 {
		resolved = f[0]
	}
	if resolved != "" && resolved != run.Host {
		_ = p.store.SetProvisionRunResolved(runID, resolved)
	}

	// Fresh one-time token: the original likely expired while failed.
	token, err := p.store.NewEnrollmentToken(p.tokenTTL)
	if err != nil {
		return fmt.Errorf("provision: create token: %w", err)
	}
	if err := p.store.SetProvisionRunToken(runID, sha256Hex(token)); err != nil {
		return fmt.Errorf("provision: link token: %w", err)
	}

	if err := p.store.SetProvisionRunState(runID, "key_confirm", "connect", ""); err != nil {
		return fmt.Errorf("provision: pause at key_confirm: %w", err)
	}
	p.audit("provision.key.reconfirm", fmt.Sprintf(`{"run_id":%q,"fingerprint":%q}`, runID, fp))
	p.log.Printf("provision: %s re-confirm: stale key removed, new %s %s", runID, ft, fp)
	if p.emitter != nil {
		p.emitter.Emit("provision.key_confirm", map[string]string{
			"run_id": runID, "host": run.Host, "key_type": ft, "fingerprint": fp, "resolved": resolved,
		})
	}

	// Relaunch the state machine paused at the gate: on ConfirmKey the new
	// key enters known_hosts and p.run's stepConnect fast-paths (host now
	// trusted), continuing from preflight with the fresh token.
	cctx, cancel := context.WithCancel(context.Background())
	ar := &activeRun{id: runID, confirm: make(chan struct{}), cancel: cancel}
	p.mu.Lock()
	p.runs[runID] = ar
	p.mu.Unlock()
	go p.reconfirmWait(cctx, ar, runID, token)
	return nil
}

// reconfirmWait blocks at the re-opened key_confirm gate, then resumes the
// standard state machine on confirm (or terminates on cancel/deny).
func (p *Provisioner) reconfirmWait(ctx context.Context, ar *activeRun, runID, token string) {
	defer func() {
		p.mu.Lock()
		delete(p.runs, runID)
		p.mu.Unlock()
		if r := recover(); r != nil {
			p.log.Printf("provision: %s PANIC: %v", runID, r)
			_ = p.store.SetProvisionRunState(runID, "failed", "", fmt.Sprint(r))
		}
	}()
	select {
	case <-ar.confirm:
		run, err := p.store.ProvisionRun(runID)
		if err != nil || run == nil {
			p.log.Printf("provision: %s resume after re-confirm: %v", runID, err)
			return
		}
		// The provision-time options were persisted on the run row; a
		// re-confirmed key gate resumes with the same plan.
		var opts StartOptions
		if run.ExtrasJSON != "" {
			var ex extrasJSON
			if err := json.Unmarshal([]byte(run.ExtrasJSON), &ex); err == nil {
				opts = StartOptions(ex)
			}
		}
		p.run(ctx, ar, run, token, opts)
	case <-ctx.Done():
		if r, err := p.store.ProvisionRun(runID); err == nil && r.State == "key_confirm" {
			p.setTerminal(r, "cancelled", "key confirmation cancelled")
		}
	}
}

func (p *Provisioner) failStep(run *store.ProvisionRun, seq int, errMsg string) bool {
	_ = p.store.FinishProvisionStep(run.ID, seq, "failed", "", errMsg)
	p.emitStep(run, seq, stepNames[seq-1], "failed")
	p.setTerminal(run, "failed", errMsg)
	return false
}

// setTerminal transitions the run to a terminal state and emits + audits.
// It is a no-op (returns false, no event) when the run already reached a
// terminal state — e.g. an operator cancel racing a step failure — so a
// "cancelled" run is never silently overwritten by a late "failed".
func (p *Provisioner) setTerminal(run *store.ProvisionRun, state, errMsg string) bool {
	cur, err := p.store.ProvisionRun(run.ID)
	if err == nil && cur != nil && isTerminal(cur.State) {
		p.log.Printf("provision: %s already terminal (%s); skipping %s", run.ID, cur.State, state)
		return false
	}
	if err := p.store.SetProvisionRunState(run.ID, state, run.Step, errMsg); err != nil {
		p.log.Printf("provision: %s set %s: %v", run.ID, state, err)
	}
	kind := "provision." + state
	if p.emitter != nil {
		p.emitter.Emit(kind, map[string]string{"run_id": run.ID, "host": run.Host, "state": state, "error": errMsg})
	}
	p.audit(kind, fmt.Sprintf(`{"run_id":%q,"error":%q}`, run.ID, errMsg))
	return true
}

// emitStep emits an SSE provision.step event.
func (p *Provisioner) emitStep(run *store.ProvisionRun, seq int, name, state string) {
	if p.emitter != nil {
		p.emitter.Emit("provision.step", map[string]string{
			"run_id": run.ID, "seq": fmt.Sprint(seq), "name": name, "state": state,
		})
	}
	p.audit("provision.step", fmt.Sprintf(`{"run_id":%q,"name":%q,"state":%q}`, run.ID, name, state))
}

func (p *Provisioner) audit(kind, payload string) {
	if err := p.store.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: kind, Actor: "provision", Payload: payload,
	}); err != nil {
		p.log.Printf("provision: audit %s: %v", kind, err)
	}
}

// ---- helpers ----------------------------------------------------------------

func isTerminal(s string) bool {
	return s == "failed" || s == "cancelled" || s == "connected" || s == "handoff"
}

// parseKeyValues parses "key=value" lines into a map.
func parseKeyValues(out string) map[string]string {
	res := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			res[line[:i]] = line[i+1:]
		}
	}
	return res
}

// sha256Of returns the sha256 of a file.
func sha256Of(path string) ([32]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// shellQuote wraps s in single quotes, escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
