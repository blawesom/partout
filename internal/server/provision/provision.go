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
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	agentfacts "github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/id"
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
	binaryPath   string // path to the partout binary on the server
	localVersion string // the server's own version (for the version-diff check)
	tokenTTL     int    // enrollment token TTL seconds (short, arch §3.5)

	mu   sync.Mutex
	runs map[string]*activeRun
}

// New builds a Provisioner. ssh controls the ssh child processes (use
// sshutil.Default(sshDir) for the operator's ~/.ssh; inject a custom Config
// in tests). serverHost is the address written into the agent's
// PARTOUT_SERVER. binaryPath is the server's own binary that gets transferred.
func New(st *store.Store, ssh sshutil.Config, serverHost, binaryPath string, em Emitter, lg *log.Logger) *Provisioner {
	if lg == nil {
		lg = log.Default()
	}
	return &Provisioner{
		store:        st,
		ssh:          ssh,
		emitter:      em,
		log:          lg,
		serverHost:   serverHost,
		binaryPath:   binaryPath,
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

// stepNames are the five provisioning steps in order.
var stepNames = []string{"connect", "preflight", "transfer", "install", "wait-enroll"}

// Start creates a provisioning run in queued state, generates a one-time
// enrollment token, and kicks off the async state machine.
func (p *Provisioner) Start(host, mode string) (*store.ProvisionRun, error) {
	runID := id.New("prv")
	run := &store.ProvisionRun{
		ID:      runID,
		Host:    host,
		Mode:    mode,
		State:   "queued",
		Created: time.Now().Unix(),
		Updated: time.Now().Unix(),
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

	go p.run(ctx, ar, run, token)
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
func (p *Provisioner) run(ctx context.Context, ar *activeRun, run *store.ProvisionRun, token string) {
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
	if !p.stepTransfer(ctx, run) {
		return
	}
	// Step 4: install.
	if !p.stepInstall(ctx, run, token) {
		return
	}
	// Step 5: wait-enroll (terminal: connected or failed).
	p.stepWaitEnroll(ctx, run)
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
	p.setState(run, "key_confirm", "connect", "")
	if err := p.store.FinishProvisionStep(run.ID, 1, "key_confirm", "", ""); err != nil {
		p.log.Printf("provision: %s finish step 1: %v", run.ID, err)
	}
	p.log.Printf("provision: %s key_confirm: %s %s %s", run.ID, run.Host, ft, fp)
	if p.emitter != nil {
		p.emitter.Emit("provision.key_confirm", map[string]string{
			"run_id": run.ID, "host": run.Host, "key_type": ft, "fingerprint": fp,
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
echo "disk=$(df -B1 / 2>/dev/null | awk 'NR==2{print $4}')"
# Host -> server reachability on the control-plane port.
SRV=%s
if command -v curl >/dev/null 2>&1; then
  if curl -fsS --max-time 5 "https://$SRV/healthz" >/dev/null 2>&1; then echo "reach=yes-tls"
  elif curl -fsS --max-time 5 "http://$SRV/healthz" >/dev/null 2>&1; then echo "reach=yes-plain"
  else echo "reach=no"; fi
elif command -v wget >/dev/null 2>&1; then
  if wget -q -T 5 -O /dev/null "https://$SRV/healthz" 2>/dev/null; then echo "reach=yes-tls"
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
		return p.failStep(run, 2, p.authHint(fmt.Sprintf("preflight exit %d: %s", exit, strings.TrimSpace(stderr))))
	}

	facts := parseKeyValues(out)
	p.log.Printf("provision: %s preflight: %v", run.ID, facts)

	// Version-diff check (read-only): report the currently-installed agent
	// version vs the version about to be installed, so the operator sees an
	// install vs upgrade (and in which direction) before anything changes.
	remoteVer := facts["remote_version"]
	facts["update"] = versionNote(remoteVer, p.localVersion)
	p.log.Printf("provision: %s version: remote=%s local=%s (%s)", run.ID, remoteVer, p.localVersion, facts["update"])

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
	if facts["reach"] == "no" {
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

// stepTransfer scp's the server binary to the host. Returns true to continue.
func (p *Provisioner) stepTransfer(ctx context.Context, run *store.ProvisionRun) bool {
	p.setState(run, "transferring", "transfer", "")
	p.beginStep(run, 3)

	sha, err := sha256Of(p.binaryPath)
	if err != nil {
		return p.failStep(run, 3, fmt.Sprintf("read binary %s: %v", p.binaryPath, err))
	}
	remote := "/tmp/partout-" + hex.EncodeToString(sha[:])[:12]
	if _, err := p.ssh.Copy(ctx, p.binaryPath, run.Host, remote); err != nil {
		return p.failStep(run, 3, p.authHint(fmt.Sprintf("scp failed: %v", err)))
	}
	p.finishStep(run, 3)
	return true
}

// stepInstall runs the install script as root on the host. Returns true to
// continue.
func (p *Provisioner) stepInstall(ctx context.Context, run *store.ProvisionRun, token string) bool {
	p.setState(run, "installing", "install", "")
	p.beginStep(run, 4)

	sha, err := sha256Of(p.binaryPath)
	if err != nil {
		return p.failStep(run, 4, fmt.Sprintf("read binary %s: %v", p.binaryPath, err))
	}
	sha12 := hex.EncodeToString(sha[:])[:12]
	fullSHA := hex.EncodeToString(sha[:])

	script := buildInstallScript(sha12, fullSHA, wipeScript(run.Mode), p.serverHost, token)

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
		return p.failStep(run, 4, p.authHint(fmt.Sprintf("install exit %d: %s", exit, strings.TrimSpace(stderr))))
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

// buildInstallScript renders the one-shot root install script. wipe is the
// mode-specific prelude (empty for join). serverHost and token are inserted
// raw into the quoted (<<'EOF') heredoc — they must NOT be shell-quoted there
// or the env file would contain literal quotes (token is prefix+hex and
// serverHost is host:port, both quote-safe).
func buildInstallScript(sha12, fullSHA, wipe, serverHost, token string) string {
	return fmt.Sprintf(`set -eu
BIN=/tmp/partout-%s
EXPECT=%s
ACTUAL=$(sha256sum "$BIN" | cut -d' ' -f1)
if [ "$ACTUAL" != "$EXPECT" ]; then echo "sha256 mismatch: $ACTUAL" >&2; exit 1; fi
%sinstall -m 0755 "$BIN" /usr/local/bin/partout
id partout >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin partout
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
cat > /etc/partout/agent.env <<'EOF'
PARTOUT_MODE=agent
PARTOUT_SERVER=%s
PARTOUT_TOKEN=%s
PARTOUT_DATA_DIR=/var/lib/partout/agent
EOF
chmod 0640 /etc/partout/agent.env
cat > /etc/systemd/system/partout-agent.service <<'EOF'
[Unit]
Description=Partout host agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=partout
EnvironmentFile=/etc/partout/agent.env
ExecStart=/usr/local/bin/partout
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable partout-agent
systemctl restart partout-agent
rm -f "$BIN"
echo INSTALL_OK
`, sha12, fullSHA, wipe, serverHost, token)
}

// stepWaitEnroll polls until the agent from this run has connected. Terminal:
// connected (success) or failed (timeout).
func (p *Provisioner) stepWaitEnroll(ctx context.Context, run *store.ProvisionRun) {
	p.setState(run, "enrolling", stepNames[4], "")
	p.beginStep(run, 5)

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
