// executor.go — per-step execution logic (command, file, package, service,
// user, group, template, assert, reboot). Steps are intent-based and
// idempotent: each checks current state before changing.
package task

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
}

// NewExecutor builds an executor.
func NewExecutor(secrets func(ref string, version int64) (string, error)) *Executor {
	return &Executor{
		secrets: secrets,
		fileExists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
	}
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
		return StateChanged, "reboot requested"
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
