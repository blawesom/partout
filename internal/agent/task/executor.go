// executor.go — per-step execution logic (command, file, package, service,
// user, group, template, assert, reboot). Steps are intent-based and
// idempotent: each checks current state before changing.
package task

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
)

// Executor carries dependencies for all step kinds.
type Executor struct {
	mu    sync.RWMutex
	facts map[string]string
	// secrets resolves a secret ref to its plaintext value.
	secrets    func(ref string, version int64) (string, error)
	fileExists func(path string) bool
	// rebootFlush is the grace period before the reboot command fires, so
	// the "rebooting" report can flush up the stream (default 5 s).
	rebootFlush time.Duration
	// rebootCmd performs the reboot (default: systemctl reboot →
	// shutdown -r now → reboot). Injectable for tests.
	rebootCmd func() error
}

// NewExecutor builds an executor.
func NewExecutor(secrets func(ref string, version int64) (string, error)) *Executor {
	flush := 5 * time.Second
	if v := os.Getenv("PARTOUT_REBOOT_FLUSH_S"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			flush = time.Duration(n) * time.Second
		}
	}
	return &Executor{
		secrets: secrets,
		fileExists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		rebootFlush: flush,
		rebootCmd:   defaultReboot,
	}
}

// SetRebootFlush overrides the pre-reboot grace period (tests use 0).
func (e *Executor) SetRebootFlush(d time.Duration) {
	e.mu.Lock()
	e.rebootFlush = d
	e.mu.Unlock()
}

// SetRebootCmd overrides the reboot command (tests use a fake).
func (e *Executor) SetRebootCmd(fn func() error) {
	e.mu.Lock()
	e.rebootCmd = fn
	e.mu.Unlock()
}

// DoReboot performs the reboot half of the reboot-step handshake: a short
// grace period so the "rebooting" report flushes up the stream, then the
// reboot command. Returns (changed, detail) on success — the host goes
// down and the caller should stop the run as `rebooting` — or
// (failed, detail) if no reboot command could run (the host stays up; the
// caller reports the run failed and discards the resume marker).
func (e *Executor) DoReboot(ctx context.Context) (string, string) {
	e.mu.RLock()
	flush, cmd := e.rebootFlush, e.rebootCmd
	e.mu.RUnlock()
	if flush > 0 {
		select {
		case <-time.After(flush):
		case <-ctx.Done():
			return StateFailed, "reboot cancelled before command: " + ctx.Err().Error()
		}
	}
	if err := cmd(); err != nil {
		return StateFailed, err.Error()
	}
	return StateChanged, "reboot initiated; resuming after boot"
}

// defaultReboot tries the usual reboot entry points in order. The agent
// runs unprivileged (systemd unit), so this only works when the agent user
// has reboot permission (root, sudo, or polkit).
func defaultReboot() error {
	cmds := [][]string{
		{"systemctl", "reboot"},
		{"shutdown", "-r", "now"},
		{"reboot"},
	}
	var lastErr error
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err == nil {
			return nil
		} else {
			lastErr = fmt.Errorf("%s: %s", strings.Join(c, " "), truncate(string(out), 200))
		}
	}
	return fmt.Errorf("reboot command failed (agent needs reboot permission, e.g. run as root or grant sudo/polkit): %v", lastErr)
}

// SetFacts installs the live fact map (updated on each facts batch).
func (e *Executor) SetFacts(f map[string]string) {
	e.mu.Lock()
	e.facts = f
	e.mu.Unlock()
}
func (e *Executor) getFact(key string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.facts[key]
}

// Step executes one task step and returns a result.
func (e *Executor) Step(ctx context.Context, idx int, step *pb.TaskStep) StepResult {
	start := time.Now().Unix()
	sr := StepResult{Index: idx, Started: start}
	if step == nil {
		return srWith(sr, StateFailed, "nil step")
	}
	sr.Name = step.GetName()
	if sr.Name == "" {
		sr.Name = step.GetKind()
	}

	// 1. Evaluate the when-guard (constrained fact expression).
	w := NewWhenEvaluator(e.facts)
	w.SetFileExists(e.fileExists)
	if step.GetWhen() != "" {
		ok, err := w.Eval(step.GetWhen())
		if err != nil {
			return srWith(sr, StateFailed, fmt.Sprintf("guard error: %s", err.Error()))
		}
		if !ok {
			return srWith(sr, StateSkipped, "when guard false")
		}
	}

	// 2. Execute the step.
	state, detail := e.doStep(ctx, step)
	sr.State = state
	sr.Detail = detail
	sr.Finished = time.Now().Unix()
	return sr
}

// doStep dispatches to the right handler.
func (e *Executor) doStep(ctx context.Context, step *pb.TaskStep) (string, string) {
	switch step.GetKind() {
	case "command":
		return e.doCommand(ctx, step)
	case "file":
		return e.doFile(step)
	case "package":
		return e.doPackage(ctx, step)
	case "service":
		return e.doService(ctx, step)
	case "user":
		return e.doUser(step)
	case "group":
		return e.doGroup(step)
	case "template":
		return e.doTemplate(ctx, step)
	case "assert":
		return e.doAssert(step)
	case "reboot":
		// Reboot steps are orchestrated by the Runner (resume marker first,
		// then the reboot command). Reaching here means the runner wiring
		// is missing — fail closed rather than rebooting without a marker.
		return StateFailed, "reboot step must be run via the task Runner (marker hook missing)"
	default:
		return StateFailed, fmt.Sprintf("unknown kind: %s", step.GetKind())
	}
}

// doCommand runs a command (exit 0 = ok).
func (e *Executor) doCommand(ctx context.Context, step *pb.TaskStep) (string, string) {
	cmd := step.GetCommand()
	if cmd == "" {
		return StateFailed, "empty command"
	}
	c := exec.CommandContext(ctx, cmd, step.GetArgs()...)
	c.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	for k, v := range step.GetEnv() {
		c.Env = append(c.Env, k+"="+v)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return StateFailed, fmt.Sprintf("exit %v: %s", err, truncate(string(out), 500))
	}
	return StateOK, truncate(string(out), 500)
}

// doFile ensures content (idempotent).
func (e *Executor) doFile(step *pb.TaskStep) (string, string) {
	path := step.GetPath()
	if path == "" {
		return StateFailed, "empty path"
	}
	content := step.GetContent()
	if content == "" {
		return StateOK, "no content change"
	}
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return StateOK, "content matches"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return StateFailed, err.Error()
	}
	return StateChanged, fmt.Sprintf("wrote %d bytes", len(content))
}

// doPackage ensures package state via the distro package manager.
func (e *Executor) doPackage(ctx context.Context, step *pb.TaskStep) (string, string) {
	pkg := step.GetPackage()
	if pkg == "" {
		return StateFailed, "empty package name"
	}
	desired := step.GetState()
	if desired == "" {
		desired = "latest"
	}
	distro := e.getFact("host.distro")
	switch distro {
	case "ubuntu", "debian", "linuxmint", "pop":
		return e.doApt(ctx, pkg, desired)
	case "rhel", "centos", "rocky", "alma", "fedora", "ol":
		return e.doDnf(ctx, pkg, desired)
	default:
		return StateFailed, fmt.Sprintf("no pkg backend for %q", distro)
	}
}

func (e *Executor) doApt(ctx context.Context, pkg, desired string) (string, string) {
	switch desired {
	case "present", "installed", "latest":
		if _, err := exec.CommandContext(ctx, "dpkg-query", "-W", pkg).CombinedOutput(); err == nil {
			return StateOK, "already installed"
		}
		if out, err := exec.CommandContext(ctx, "apt-get", "-y", "install", pkg).CombinedOutput(); err != nil {
			return StateFailed, fmt.Sprintf("apt install failed: %s", truncate(string(out), 300))
		}
		return StateChanged, "installed package"
	case "absent", "removed":
		if _, err := exec.CommandContext(ctx, "dpkg-query", "-W", pkg).CombinedOutput(); err != nil {
			return StateOK, "already absent"
		}
		if out, err := exec.CommandContext(ctx, "apt-get", "-y", "remove", pkg).CombinedOutput(); err != nil {
			return StateFailed, fmt.Sprintf("apt remove failed: %s", truncate(string(out), 300))
		}
		return StateChanged, "removed package"
	default:
		return StateFailed, fmt.Sprintf("unsupported state: %s", desired)
	}
}

func (e *Executor) doDnf(ctx context.Context, pkg, desired string) (string, string) {
	switch desired {
	case "present", "installed", "latest":
		if _, err := exec.CommandContext(ctx, "rpm", "-q", pkg).CombinedOutput(); err == nil {
			return StateOK, "already installed"
		}
		if out, err := exec.CommandContext(ctx, "dnf", "-y", "install", pkg).CombinedOutput(); err != nil {
			return StateFailed, fmt.Sprintf("dnf install failed: %s", truncate(string(out), 300))
		}
		return StateChanged, "installed package"
	case "absent", "removed":
		if _, err := exec.CommandContext(ctx, "rpm", "-q", pkg).CombinedOutput(); err != nil {
			return StateOK, "already absent"
		}
		if out, err := exec.CommandContext(ctx, "dnf", "-y", "remove", pkg).CombinedOutput(); err != nil {
			return StateFailed, fmt.Sprintf("dnf remove failed: %s", truncate(string(out), 300))
		}
		return StateChanged, "removed package"
	default:
		return StateFailed, fmt.Sprintf("unsupported state: %s", desired)
	}
}

// doService ensures a systemd unit in the desired state.
func (e *Executor) doService(ctx context.Context, step *pb.TaskStep) (string, string) {
	svc := step.GetService()
	if svc == "" {
		return StateFailed, "empty service name"
	}
	desired := step.GetState()
	if desired == "" {
		desired = "started"
	}
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", svc).CombinedOutput()
	active := strings.TrimSpace(string(out)) == "active"
	switch desired {
	case "started", "running", "enabled":
		if active {
			return StateOK, "already active"
		}
		if out, err := exec.CommandContext(ctx, "systemctl", "start", svc).CombinedOutput(); err != nil {
			return StateFailed, fmt.Sprintf("start failed: %s", truncate(string(out), 300))
		}
		return StateChanged, "started service"
	case "stopped", "disabled":
		if !active {
			return StateOK, "already stopped"
		}
		if out, err := exec.CommandContext(ctx, "systemctl", "stop", svc).CombinedOutput(); err != nil {
			return StateFailed, fmt.Sprintf("stop failed: %s", truncate(string(out), 300))
		}
		return StateChanged, "stopped service"
	default:
		return StateFailed, fmt.Sprintf("unsupported state: %s", desired)
	}
}

// doUser ensures a user exists.
func (e *Executor) doUser(step *pb.TaskStep) (string, string) {
	name := step.GetUser()
	if name == "" {
		return StateFailed, "empty user name"
	}
	if _, err := exec.Command("id", name).CombinedOutput(); err == nil {
		return StateOK, "user exists"
	}
	if out, err := exec.Command("useradd", "--system", "--no-create-home", name).CombinedOutput(); err != nil {
		return StateFailed, fmt.Sprintf("useradd failed: %s", truncate(string(out), 300))
	}
	return StateChanged, "created user"
}

// doGroup ensures a group exists.
func (e *Executor) doGroup(step *pb.TaskStep) (string, string) {
	name := step.GetGroup()
	if name == "" {
		return StateFailed, "empty group name"
	}
	if _, err := exec.Command("getent", "group", name).CombinedOutput(); err == nil {
		return StateOK, "group exists"
	}
	if out, err := exec.Command("groupadd", name).CombinedOutput(); err != nil {
		return StateFailed, fmt.Sprintf("groupadd failed: %s", truncate(string(out), 300))
	}
	return StateChanged, "created group"
}

// doTemplate renders a Go template and writes to file (idempotent).
func (e *Executor) doTemplate(ctx context.Context, step *pb.TaskStep) (string, string) {
	path := step.GetPath()
	if path == "" {
		return StateFailed, "empty template path"
	}
	src := step.GetTemplate()
	if src == "" {
		return StateFailed, "empty template content"
	}
	// Build vars from facts + template vars.
	vars := map[string]any{"facts": e.facts}
	for k, v := range step.GetVars() {
		vars[k] = v
	}
	tmpl, err := template.New("tmpl").Option("missingkey=error").Parse(src)
	if err != nil {
		return StateFailed, fmt.Sprintf("template parse: %s", err.Error())
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, vars); err != nil {
		return StateFailed, fmt.Sprintf("template exec: %s", err.Error())
	}
	content := buf.String()
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return StateOK, "template output unchanged"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return StateFailed, err.Error()
	}
	return StateChanged, fmt.Sprintf("rendered (%d bytes)", len(content))
}

// doAssert evaluates an expression and fails if false.
func (e *Executor) doAssert(step *pb.TaskStep) (string, string) {
	expr := step.GetExpr()
	if expr == "" {
		return StateFailed, "empty expression"
	}
	w := NewWhenEvaluator(e.facts)
	ok, err := w.Eval(expr)
	if err != nil {
		return StateFailed, fmt.Sprintf("assert eval: %s", err.Error())
	}
	if !ok {
		return StateFailed, fmt.Sprintf("assert false: %s", expr)
	}
	return StateOK, "assert passed"
}

// ---- helpers ---------------------------------------------------------------

func srWith(sr StepResult, state, detail string) StepResult {
	sr.State = state
	sr.Detail = detail
	return sr
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
