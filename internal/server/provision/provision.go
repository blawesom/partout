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
}

// Provisioner orchestrates host provisioning runs.
type Provisioner struct {
	store      *store.Store
	ssh        sshutil.Config
	emitter    Emitter
	log        *log.Logger
	serverHost string // address the new agent connects to (PARTOUT_SERVER)
	binaryPath string // path to the partout binary on the server
	tokenTTL   int    // enrollment token TTL seconds (short, arch §3.5)

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
		store:      st,
		ssh:        ssh,
		emitter:    em,
		log:        lg,
		serverHost: serverHost,
		binaryPath: binaryPath,
		tokenTTL:   300, // 5 min — short TTL for the one-time token
		runs:       make(map[string]*activeRun),
	}
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

	// One-time short-TTL enrollment token for the new agent.
	token, err := p.store.NewEnrollmentToken(p.tokenTTL)
	if err != nil {
		return nil, fmt.Errorf("provision: create token: %w", err)
	}
	run.TokenHash = sha256Hex(token)

	if err := p.store.CreateProvisionRun(*run); err != nil {
		return nil, fmt.Errorf("provision: create run: %w", err)
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
	// Append the public key to known_hosts and hash it. No private material
	// is ever read, copied, or logged.
	if err := p.ssh.AddKey(context.Background(), run.KeyLine); err != nil {
		return fmt.Errorf("provision: add to known_hosts: %w", err)
	}
	p.audit("provision.key.confirmed", fmt.Sprintf(`{"run_id":%q,"fingerprint":%q}`, runID, run.Fingerprint))
	p.mu.Lock()
	ar := p.runs[runID]
	p.mu.Unlock()
	if ar != nil {
		close(ar.confirm)
	}
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
	p.mu.Lock()
	ar := p.runs[runID]
	p.mu.Unlock()
	if ar != nil {
		ar.cancel()
	}
	return nil
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

	script := `set +e
echo "os=$(cat /etc/os-release 2>/dev/null | grep -m1 PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "arch=$(uname -m)"
if command -v systemctl >/dev/null 2>&1; then echo "init=systemd"; else echo "init=none"; fi
echo "user=$(whoami)"
if sudo -n true 2>/dev/null; then echo "sudo=yes"; else echo "sudo=no"; fi
echo "disk=$(df -B1 / 2>/dev/null | awk 'NR==2{print $4}')"
`
	out, stderr, exit, err := p.ssh.Run(ctx, run.Host, script)
	if err != nil {
		return p.failStep(run, 2, fmt.Sprintf("ssh failed: %v", err))
	}
	if exit != 0 {
		return p.failStep(run, 2, fmt.Sprintf("preflight exit %d: %s", exit, strings.TrimSpace(stderr)))
	}

	facts := parseKeyValues(out)
	p.log.Printf("provision: %s preflight: %v", run.ID, facts)

	if facts["init"] != "systemd" {
		_ = p.store.FinishProvisionStep(run.ID, 2, "handoff", out, "")
		p.setTerminal(run, "handoff", "non-systemd init; manual install required")
		return false
	}
	if facts["sudo"] != "yes" {
		return p.failStep(run, 2, "install needs root or NOPASSWD sudo; grant the ssh user passwordless sudo")
	}

	p.finishStep(run, 2)
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
		return p.failStep(run, 3, fmt.Sprintf("scp failed: %v", err))
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

	script := fmt.Sprintf(`set -eu
BIN=/tmp/partout-%s
EXPECT=%s
ACTUAL=$(sha256sum "$BIN" | cut -d' ' -f1)
if [ "$ACTUAL" != "$EXPECT" ]; then echo "sha256 mismatch: $ACTUAL" >&2; exit 1; fi
install -m 0755 "$BIN" /usr/local/bin/partout
id partout >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin partout
mkdir -p /var/lib/partout/agent
chown partout:partout /var/lib/partout/agent
chmod 0750 /var/lib/partout/agent
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
`, sha12, fullSHA, shellQuote(p.serverHost), shellQuote(token))

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
		return p.failStep(run, 4, fmt.Sprintf("install exit %d: %s", exit, strings.TrimSpace(stderr)))
	}
	p.finishStep(run, 4)
	return true
}

// stepWaitEnroll polls until the agent from this run has connected. Terminal:
// connected (success) or failed (timeout).
func (p *Provisioner) stepWaitEnroll(ctx context.Context, run *store.ProvisionRun) {
	p.setState(run, "enrolling", "enroll", "")
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
func (p *Provisioner) failStep(run *store.ProvisionRun, seq int, errMsg string) bool {
	_ = p.store.FinishProvisionStep(run.ID, seq, "failed", "", errMsg)
	p.emitStep(run, seq, stepNames[seq-1], "failed")
	p.setTerminal(run, "failed", errMsg)
	return false
}

// setTerminal transitions the run to a terminal state and emits + audits.
func (p *Provisioner) setTerminal(run *store.ProvisionRun, state, errMsg string) {
	if err := p.store.SetProvisionRunState(run.ID, state, run.Step, errMsg); err != nil {
		p.log.Printf("provision: %s set %s: %v", run.ID, state, err)
	}
	kind := "provision." + state
	if p.emitter != nil {
		p.emitter.Emit(kind, map[string]string{"run_id": run.ID, "state": state, "error": errMsg})
	}
	p.audit(kind, fmt.Sprintf(`{"run_id":%q,"error":%q}`, run.ID, errMsg))
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
