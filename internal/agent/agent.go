// Package agent implements the agent-side run loop (architecture §3.1, §5):
// connect with backoff, Ed25519 handshake, heartbeat + facts cadence,
// command execution with streamed output, policy storage, and revocation.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blawesom/partout/internal/agent/exec"
	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/agent/fs"
	"github.com/blawesom/partout/internal/agent/guardrail"
	"github.com/blawesom/partout/internal/agent/jobs"
	pkg "github.com/blawesom/partout/internal/agent/pkg"
	agentsecrets "github.com/blawesom/partout/internal/agent/secrets"
	"github.com/blawesom/partout/internal/agent/session"
	"github.com/blawesom/partout/internal/agent/stream"
	"github.com/blawesom/partout/internal/agent/task"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/spool"

	pb "github.com/blawesom/partout/internal/proto"
)

// ErrRevoked is returned by Run when the server revokes the agent; the agent
// should stop and the operator must re-enroll.
var ErrRevoked = errors.New("agent: revoked by server")

// Constants (architecture §15 proposed defaults).
const (
	heartbeatInterval = 15 * time.Second
	backoffBase       = 1 * time.Second
	backoffCap        = 60 * time.Second
)

// Agent is the long-running agent process.
type Agent struct {
	id        *identity.Identity
	cfg       *config.Config
	log       *log.Logger
	streamC   *stream.Client
	start     time.Time
	factset   map[string]string
	policyDir string
	guard     *guardrail.Guard
	spool     *spool.Spool

	// rootCtx is the top-level agent context (from Run). In-flight runs are
	// derived from it — not from a per-stream session context — so a stream
	// drop does not kill the running process; its output spools instead and
	// replays on reconnect (architecture §3.4).
	rootCtx context.Context

	// secrets is the E2E secret materialization cache (M3, PRD §5.7). It may
	// be nil when the agent lacks an x25519 private key; then secret steps
	// fail closed.
	secrets *agentsecrets.Cache

	// taskRunner executes task runs (M3, PRD §5.5).
	taskRunner *task.Runner
	// taskExec carries facts/secrets for the task executor.
	taskExec *task.Executor

	// jobs runs scheduled jobs on the agent's own clock (M3, PRD §5.4).
	jobs *jobs.Scheduler

	// sendMu serializes all up-sends (direct + spool drain) on the stream.
	sendMu sync.Mutex

	// spooledMu guards spooled: runs whose output is currently in the spool.
	spooledMu sync.Mutex
	spooled   map[string]bool

	// spoolErr is set if the offline spool could not be opened at startup.
	// Run fails fast on it: silently running without a spool would drop every
	// result produced during a disconnect — the exact failure the spool exists
	// to prevent (architecture §3.4).
	spoolErr error

	// activeMu guards activeRunners.  Each entry is a context.CancelFunc for
	// a run in progress.  The server CANCEL envelope uses this map to kill
	// an in-flight process.
	activeMu      sync.Mutex
	activeRunners map[string]context.CancelFunc

	// sessions manages live PTY sessions (PRD §5.2.2). Killed on every
	// stream end (D2): a PTY without a stream cannot be meaningfully resumed.
	sessions *session.Manager

	// fsCfg bounds file operations (D3 defaults; env-configurable later).
	fsCfg fs.Config
}

// New builds an Agent. The identity must already be enrolled (server-side row
// exists with matching public keys).
func New(id *identity.Identity, cfg *config.Config, lg *log.Logger) *Agent {
	if lg == nil {
		lg = log.Default()
	}
	policyDir := filepath.Join(cfg.DataDir, "agent")
	g := guardrail.NewGuard(id.UUID, policyDir)
	if err := g.Load(); err != nil {
		lg.Printf("agent: load guardrail: %v", err)
	}
	// Open the offline spool (architecture §3.4). The spool dir lives directly
	// under the agent data dir (which is already the per-agent root, e.g.
	// /var/lib/partout/agent). A failure is not swallowed: it is surfaced from
	// Run so a broker data dir fails loudly at startup instead of silently
	// losing output during disconnects.
	sp, spoolErr := spool.Open(spool.Config{Dir: filepath.Join(cfg.DataDir, "spool")})
	if spoolErr != nil {
		lg.Printf("agent: open spool: %v", spoolErr)
	}
	// Secret cache (M3, PRD §5.7): holds materialized values in memory and,
	// for secrets with offline_ttl, the sealed form on disk (0600). A
	// failure to open it is logged but not fatal: secret-less runs work, and
	// declaring a secret then fails closed ("secret unavailable").
	var secCache *agentsecrets.Cache
	if id.X25519Priv != nil {
		var serr error
		secCache, serr = agentsecrets.New(filepath.Join(cfg.DataDir, "agent"), id.X25519Priv)
		if serr != nil {
			lg.Printf("agent: open secret cache: %v", serr)
			secCache = nil
		}
	}
	a := &Agent{
		id:            id,
		cfg:           cfg,
		log:           lg,
		streamC:       stream.New(id, stream.Config{ServerURL: cfg.ServerURL, CAFile: cfg.TLSCAFile, CertFile: cfg.TLSCertFile, KeyFile: cfg.TLSKeyFile}, lg),
		start:         time.Now(),
		factset:       facts.Collector(id, cfg.FactsInterval),
		policyDir:     policyDir,
		guard:         g,
		spool:         sp,
		spoolErr:      spoolErr,
		secrets:       secCache,
		spooled:       make(map[string]bool),
		activeRunners: make(map[string]context.CancelFunc),
		fsCfg:         fs.Config{},
	}
	// Task runner (M3, PRD §5.5): secrets lookup uses the E2E cache.
	var secLookup func(ref string, version int64) (string, error)
	if secCache != nil {
		secLookup = func(ref string, _ int64) (string, error) {
			v, ok := secCache.Get(ref)
			if !ok {
				return "", fmt.Errorf("secret %q unavailable", ref)
			}
			return v, nil
		}
	}
	a.taskExec = task.NewExecutor(secLookup)
	a.taskRunner = task.New(a.taskExec)
	a.jobs = jobs.New(filepath.Join(cfg.DataDir, "jobs"), a.taskExec, func(r *jobs.Report) {
		a.sendJobResult(r)
	}, a.log)
	// Session manager uses a closure that can reach the agent instance.
	a.sessions = session.NewManager(func(sid string, exitCode int32, state string, durationMs int64) {
		lg.Printf("agent: session %s finished: %s (exit=%d, %dms)", sid, state, exitCode, durationMs)
		a.sendUpEnvelopeNoSpool(&pb.Envelope{
			Kind: pb.EnvelopeKind_SESSION_RESULT,
			Payload: &pb.Envelope_SessionResult{SessionResult: &pb.SessionResult{
				SessionId: sid, ExitCode: exitCode, State: state, DurationMs: durationMs,
			}},
		})
	})
	return a
}

// GuardLoaded reports whether the agent has received (and cached) a policy
// bundle.  Exported so tests can wait for it deterministically.
func (a *Agent) GuardLoaded() bool {
	return a.guard.Loaded()
}

// Run blocks until ctx is canceled or the agent is revoked. It manages the
// connect → stream → reconnect loop with exponential backoff + jitter.
func (a *Agent) Run(ctx context.Context) error {
	a.rootCtx = ctx
	// Fail fast: without a spool, in-flight runs cannot be replayed after a
	// disconnect, so results would be silently lost (architecture §3.4).
	if a.spoolErr != nil {
		return fmt.Errorf("agent: offline spool unavailable: %w", a.spoolErr)
	}
	if a.spool != nil {
		defer a.spool.Close()
	}
	// M3 jobs: restore persisted schedules and start the agent-side clock
	// (PRD §5.4). Runs continue even while the stream is down.
	if a.jobs != nil {
		if err := a.jobs.Load(); err != nil {
			a.log.Printf("agent: jobs load: %v", err)
		}
		a.jobs.Start()
		defer a.jobs.Stop()
	}
	backoff := backoffBase
	for {
		err := a.connectAndStream(ctx)
		// D2: PTY sessions die with the stream (a dead terminal cannot be
		// resumed); the server marks them interrupted on disconnect.
		if n := a.sessions.KillAll(); n > 0 {
			a.log.Printf("agent: killed %d session(s) on stream end", n)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrRevoked) {
			return ErrRevoked
		}
		if err != nil {
			a.log.Printf("agent: stream ended: %v; reconnecting in %v", err, backoff)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff + jitter(backoff)):
		}
		if backoff *= 2; backoff > backoffCap {
			backoff = backoffCap
		}
	}
}

// connectAndStream opens one stream: connect, handshake, facts, then the
// envelope loop. Returns when the stream ends (error) or the agent is revoked.
func (a *Agent) connectAndStream(ctx context.Context) error {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := a.streamC.Connect(sessCtx); err != nil {
		return fmt.Errorf("agent: connect: %w", err)
	}
	defer a.streamC.Close()
	a.log.Printf("agent: connected to %s", a.cfg.ServerURL)

	if err := a.sendFacts(sessCtx, true); err != nil {
		return fmt.Errorf("agent: send facts: %w", err)
	}
	// Drain spooled output from any previous disconnection before processing
	// new down traffic (architecture §3.1.4). On the first connection this is
	// a fast no-op. A drain failure keeps the spool for the next attempt and
	// does not tear down the freshly established stream: the send error will
	// surface on the envelope loop itself if the connection is really down.
	if err := a.drainSpool(sessCtx); err != nil {
		a.log.Printf("agent: drain spool: %v (kept for retry)", err)
	}

	hbTimer := time.NewTicker(heartbeatInterval)
	defer hbTimer.Stop()
	factTimer := time.NewTicker(time.Duration(a.cfg.FactsInterval) * time.Second)
	defer factTimer.Stop()

	type downMsg struct {
		env *pb.Envelope
		err error
	}
	down := make(chan downMsg, 1)
	launchRecv := func() {
		go func() {
			env, err := a.streamC.Recv(sessCtx)
			down <- downMsg{env: env, err: err}
		}()
	}
	launchRecv()

	for {
		select {
		case <-sessCtx.Done():
			return sessCtx.Err()

		case <-hbTimer.C:
			hb := &pb.Heartbeat{
				AgentVersion: facts.Version,
				UptimeS:      int64(time.Since(a.start).Seconds()),
			}
			if a.spool != nil {
				m, d := a.spool.Usage()
				hb.SpoolMemBytes = m
				hb.SpoolDiskBytes = d
			}
			if err := a.streamC.Send(sessCtx, &pb.Envelope{
				Kind:    pb.EnvelopeKind_HEARTBEAT,
				Payload: &pb.Envelope_Heartbeat{Heartbeat: hb},
			}); err != nil {
				return fmt.Errorf("agent: send heartbeat: %w", err)
			}

		case <-factTimer.C:
			if err := a.sendFacts(sessCtx, false); err != nil {
				return fmt.Errorf("agent: send facts: %w", err)
			}

		case m := <-down:
			if m.err != nil {
				return m.err
			}
			if err := a.handleDown(sessCtx, m.env); err != nil {
				if errors.Is(err, ErrRevoked) {
					return ErrRevoked
				}
				return fmt.Errorf("agent: handle down: %w", err)
			}
			launchRecv()
		}
	}
}

// sendFacts sends a FactsBatch envelope (full snapshot; deltas are M1+).
func (a *Agent) sendFacts(ctx context.Context, full bool) error {
	a.factset = facts.Collector(a.id, a.cfg.FactsInterval)
	return a.streamC.Send(ctx, &pb.Envelope{
		Kind: pb.EnvelopeKind_FACTS_BATCH,
		Payload: &pb.Envelope_Facts{Facts: &pb.FactsBatch{
			Full:  full,
			Facts: a.factset,
		}},
	})
}

// handleDown processes one down envelope.
func (a *Agent) handleDown(ctx context.Context, env *pb.Envelope) error {
	switch {
	case env.GetCommand() != nil:
		cmd := env.GetCommand()
		a.log.Printf("agent: command %s (%s %v)", cmd.RunId, cmd.Cmd, cmd.Args)

		// Guardrail re-check (architecture §5.3).  Fails closed: no bundle,
		// no decision, bad signature, or local eval denies → ACK_DENIED_AGENT.
		if ok, reason := a.guard.Recheck(cmd); !ok {
			a.log.Printf("agent: guardrail DENIED %s: %s", cmd.RunId, reason)
			_ = a.streamC.Send(ctx, &pb.Envelope{
				Kind: pb.EnvelopeKind_ACK,
				Payload: &pb.Envelope_Ack{Ack: &pb.Ack{
					EnvelopeId: env.Id,
					Status:     pb.AckStatus_ACK_DENIED_AGENT,
					Detail:     reason,
				}},
			})
			return nil
		}

		// ACK delivery.
		_ = a.streamC.Send(ctx, &pb.Envelope{
			Kind: pb.EnvelopeKind_ACK,
			Payload: &pb.Envelope_Ack{Ack: &pb.Ack{
				EnvelopeId: env.Id,
				Status:     pb.AckStatus_ACK_OK,
			}},
		})
		// Register a cancel handle for this run.  The run context derives from
		// the agent root context (not the session): a stream drop must not
		// kill the process — its output spools and replays on reconnect
		// (architecture §3.4). CANCEL still works via activeRunners.
		runCtx, runCancel := context.WithCancel(a.rootCtx)
		a.activeMu.Lock()
		a.activeRunners[cmd.RunId] = runCancel
		a.activeMu.Unlock()
		go a.execCommand(runCtx, cmd)

	case env.GetCancel() != nil:
		ca := env.GetCancel()
		a.log.Printf("agent: CANCEL %s", ca.RunId)
		a.activeMu.Lock()
		cancel, ok := a.activeRunners[ca.RunId]
		if ok {
			delete(a.activeRunners, ca.RunId)
		}
		a.activeMu.Unlock()
		if ok {
			cancel()
		}

	case env.GetFileOp() != nil:
		op := env.GetFileOp()
		// Write ops (upload begin, edit, perm) carry a signed decision and are
		// re-checked by the guardrail (architecture §5.3, D1). Read ops carry
		// no decision and run directly.
		if op.Decision != nil {
			if ok, reason := a.guard.RecheckFile(op); !ok {
				a.log.Printf("agent: file op %s DENIED: %s", op.OpId, reason)
				a.sendFileOpResult(&pb.FileOpResult{
					OpId: op.OpId, Kind: op.Kind, Code: 403, Error: reason,
				})
				return nil
			}
		}
		// Ops are request/response; run off the envelope loop so a slow
		// transfer cannot starve CANCEL/heartbeat traffic.
		go a.execFileOp(op)

	case env.GetPkgOp() != nil:
		op := env.GetPkgOp()
		// Apply ops carry a signed decision and are re-checked by the
		// guardrail (architecture §5.3, A6). List ops are read-only and
		// run directly.
		if op.Decision != nil {
			if ok, reason := a.guard.RecheckPkg(op); !ok {
				a.log.Printf("agent: pkg op %s DENIED: %s", op.OpId, reason)
				a.sendPkgResult(&pb.PkgResult{
					OpId: op.OpId, Kind: op.Kind, Code: 403, Error: reason,
				})
				return nil
			}
		}
		// Run off the envelope loop (apt/dnf can be slow).
		go a.execPkgOp(op)

	case env.GetTaskRun() != nil:
		run := env.GetTaskRun()
		// Task runs are gated by the task.run action class (M3, PRD §5.5).
		if ok, reason := a.guard.RecheckTask(run); !ok {
			a.log.Printf("agent: task %s DENIED: %s", run.RunId, reason)
			a.sendTaskResult(run.RunId, "failed", reason, nil)
			return nil
		}
		// Run off the envelope loop.
		go a.execTaskRun(run)

	case env.GetJobAssign() != nil:
		ja := env.GetJobAssign()
		// Jobs are server-resolved per-host schedules: no exec decision to
		// re-check (the task steps run under their own task.run gate when
		// manually dispatched; scheduled runs are agent-side by design).
		a.jobs.Apply(jaToAssignment(ja))

	case env.GetJobUnassign() != nil:
		ju := env.GetJobUnassign()
		a.jobs.Remove(ju.JobId)

	case env.GetSessionOpen() != nil:
		so := env.GetSessionOpen()
		// A session is an exec action: reuse the command guardrail re-check
		// (command regex applies to cmd + args, arch §5.3).
		synthetic := &pb.Command{
			RunId:    so.SessionId,
			Cmd:      so.Cmd,
			Args:     so.Args,
			Decision: so.Decision,
		}
		if ok, reason := a.guard.Recheck(synthetic); !ok {
			a.log.Printf("agent: session %s DENIED: %s", so.SessionId, reason)
			a.sendUpEnvelopeNoSpool(&pb.Envelope{
				Kind: pb.EnvelopeKind_SESSION_RESULT,
				Payload: &pb.Envelope_SessionResult{SessionResult: &pb.SessionResult{
					SessionId: so.SessionId, ExitCode: -1, State: "denied",
				}},
			})
			return nil
		}
		err := a.sessions.Open(so.SessionId, so.Cmd, so.Args, so.Env,
			so.Cols, so.Rows,
			func(sid string, data []byte) {
				a.sendUpEnvelopeNoSpool(&pb.Envelope{
					Kind: pb.EnvelopeKind_SESSION_DATA,
					Payload: &pb.Envelope_SessionData{SessionData: &pb.SessionData{
						SessionId: sid, Data: data,
					}},
				})
			})
		if err != nil {
			a.log.Printf("agent: session %s open failed: %v", so.SessionId, err)
			a.sendUpEnvelopeNoSpool(&pb.Envelope{
				Kind: pb.EnvelopeKind_SESSION_RESULT,
				Payload: &pb.Envelope_SessionResult{SessionResult: &pb.SessionResult{
					SessionId: so.SessionId, ExitCode: -1, State: "failed", Error: err.Error(),
				}},
			})
		}

	case env.GetSessionInput() != nil:
		si := env.GetSessionInput()
		if err := a.sessions.Input(si.SessionId, si.Data); err != nil {
			a.log.Printf("agent: session input %s: %v", si.SessionId, err)
		}

	case env.GetSessionResize() != nil:
		sr := env.GetSessionResize()
		if err := a.sessions.Resize(sr.SessionId, sr.Cols, sr.Rows); err != nil {
			a.log.Printf("agent: session resize %s: %v", sr.SessionId, err)
		}

	case env.GetSessionClose() != nil:
		scl := env.GetSessionClose()
		if err := a.sessions.Close(scl.SessionId); err != nil {
			a.log.Printf("agent: session close %s: %v", scl.SessionId, err)
		}

	case env.GetPolicyBundle() != nil:
		bundle := env.GetPolicyBundle()
		a.log.Printf("agent: policy bundle v%d received", bundle.Version)
		a.guard.OnBundle(bundle)
		if err := a.savePolicy(bundle); err != nil {
			a.log.Printf("agent: save policy: %v", err)
		}

	case env.GetRevoke() != nil:
		a.log.Printf("agent: REVOKED: %s", env.GetRevoke().Reason)
		return ErrRevoked

	case env.GetSecretMaterialize() != nil:
		sm := env.GetSecretMaterialize()
		if a.secrets == nil {
			a.log.Printf("agent: secret %s materialized but cache unavailable (no x25519 key)", sm.Ref)
			return nil
		}
		if _, err := a.secrets.Handle(sm); err != nil {
			// Fails closed: the value is not stored, so any run that declares
			// it will report "secret unavailable". Log (never the value).
			a.log.Printf("agent: secret %s materialize FAILED: %v", sm.Ref, err)
			return nil
		}
		a.log.Printf("agent: secret %s v%d materialized (ttl=%ds)", sm.Ref, sm.Version, sm.CacheTtlS)

	default:
		return nil
	}
	return nil
}

// execCommand runs a command, streaming output chunks, then the result.
// While the stream is down, output is routed to the offline spool and
// replayed on reconnect (architecture §3.4).  Once a run's output first
// enters the spool, all subsequent records for that run also go to the
// spool, so it holds a contiguous suffix that drains together when the
// result is appended (spool drain requires a result record).
func (a *Agent) execCommand(ctx context.Context, cmd *pb.Command) {
	var seq atomic.Uint64
	deliver := func(env *pb.Envelope) {
		// No spool: nothing to fall back to. Log once per run rather than per
		// envelope, and do not mark the run as spooled (Run already failed
		// fast on a missing spool; this is defensive).
		if a.spool == nil {
			a.spooledMu.Lock()
			warned := a.spooled[cmd.RunId]
			a.spooled[cmd.RunId] = true
			a.spooledMu.Unlock()
			if !warned {
				a.log.Printf("agent: no spool; dropping output for run %s", cmd.RunId)
			}
			return
		}
		a.spooledMu.Lock()
		spooling := a.spooled[cmd.RunId]
		a.spooledMu.Unlock()
		if !spooling {
			a.sendMu.Lock()
			err := a.streamC.Send(ctx, env)
			a.sendMu.Unlock()
			if err == nil {
				return
			}
			// Stream down: enter spool mode for this run. All future
			// records for the same run also go to the spool so the
			// spool holds a contiguous tail that drains together.
			a.spooledMu.Lock()
			a.spooled[cmd.RunId] = true
			a.spooledMu.Unlock()
			a.log.Printf("agent: stream down; spooling output for run %s", cmd.RunId)
		}
		if err := a.spool.Append(cmd.RunId, env); err != nil {
			a.log.Printf("agent: spool append %s: %v", cmd.RunId, err)
		}
	}
	onChunk := func(c exec.Chunk) {
		s := pb.OutputStream_OUTPUT_STDOUT
		if c.Stream == "stderr" {
			s = pb.OutputStream_OUTPUT_STDERR
		}
		deliver(&pb.Envelope{
			Kind: pb.EnvelopeKind_COMMAND_OUTPUT,
			Payload: &pb.Envelope_Output{Output: &pb.CommandOutput{
				RunId: cmd.RunId, ChunkSeq: seq.Add(1) - 1, Stream: s, Data: c.Data,
			}},
		})
	}

	res, err := exec.Run(ctx, cmd.Cmd, cmd.Args, cmd.Cwd, cmd.Env, cmd.TimeoutS, onChunk)
	if err != nil {
		res = &exec.Result{State: "failed", ExitCode: -1}
	}

	// Remove from active runners.
	a.activeMu.Lock()
	delete(a.activeRunners, cmd.RunId)
	a.activeMu.Unlock()

	deliver(&pb.Envelope{
		Kind: pb.EnvelopeKind_COMMAND_RESULT,
		Payload: &pb.Envelope_Result{Result: &pb.CommandResult{
			RunId: cmd.RunId, ExitCode: res.ExitCode, State: res.State, DurationMs: res.DurationMS,
		}},
	})

	// If this run spooled while disconnected, try a drain now (the stream
	// may be back). A failed drain keeps the spool for the next reconnect.
	if a.spool != nil {
		go a.drainSpool(context.Background())
	}
	a.log.Printf("agent: run %s finished: %s (exit=%d, %dms)", cmd.RunId, res.State, res.ExitCode, res.DurationMS)
}

// drainSpool sends spooled runs to the server (architecture §3.1.4: on
// reconnect the agent first drains its local spool, then receives pending
// down traffic). A run is removed from the spool only after a fully
// successful drain; a failed send keeps it for the next attempt.
func (a *Agent) drainSpool(ctx context.Context) error {
	if a.spool == nil || len(a.spool.Runs()) == 0 {
		return nil
	}
	sent, drained, err := a.spool.Drain(ctx, a.sendUpEnvelope)
	for _, rid := range drained {
		a.spooledMu.Lock()
		delete(a.spooled, rid)
		a.spooledMu.Unlock()
	}
	if sent > 0 || len(drained) > 0 {
		a.log.Printf("agent: drained %d spooled envelopes (%d runs)", sent, len(drained))
	}
	return err
}

// sendUpEnvelope is the spool Drain send callback: serialized on sendMu, sent
// over the live stream.
func (a *Agent) sendUpEnvelope(ctx context.Context, env *pb.Envelope) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return a.streamC.Send(ctx, env)
}

// sendUpEnvelopeNoSpool sends an up envelope that must never be spooled
// (session control traffic: it is tied to the live stream, D2). A failed
// send is logged, not returned: the stream teardown handles the rest.
func (a *Agent) sendUpEnvelopeNoSpool(env *pb.Envelope) {
	a.sendMu.Lock()
	err := a.streamC.Send(context.Background(), env)
	a.sendMu.Unlock()
	if err != nil {
		a.log.Printf("agent: up send %s failed: %v", env.Kind, err)
	}
}

// savePolicy writes the policy bundle to the agent data dir (M0: store + hash).
func (a *Agent) savePolicy(bundle *pb.PolicyBundle) error {
	if err := os.MkdirAll(a.policyDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(a.policyDir, "policy.json")
	if err := os.WriteFile(path, []byte(bundle.RulesJson), 0o600); err != nil {
		return err
	}
	meta := fmt.Sprintf("version=%d\ncontent_hash=%s\nreceived_unix=%d\n",
		bundle.Version, bundle.ContentHash, time.Now().Unix())
	return os.WriteFile(filepath.Join(a.policyDir, "policy.meta"), []byte(meta), 0o600)
}

// jitter returns a random value in [0, d).
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d)))
}

// sendFileOpResult sends a FileOpResult up the stream (no spooling: file ops
// are synchronous request/response, tied to the live stream).
func (a *Agent) sendFileOpResult(res *pb.FileOpResult) {
	a.sendMu.Lock()
	err := a.streamC.Send(context.Background(), &pb.Envelope{
		Kind:    pb.EnvelopeKind_FILE_OP_RESULT,
		Payload: &pb.Envelope_FileOpResult{FileOpResult: res},
	})
	a.sendMu.Unlock()
	if err != nil {
		a.log.Printf("agent: file result %s send failed: %v", res.OpId, err)
	}
}

// fileOpError maps an fs error to a stable FileOpResult code: 409 conflict
// (CAS mismatch), 413 size cap, 400 bad path, 500 other.
func fileOpError(op *pb.FileOp, err error) *pb.FileOpResult {
	code := int32(500)
	switch {
	case errors.Is(err, fs.ErrConflict):
		code = 409
	case errors.Is(err, fs.ErrCapExceeded):
		code = 413
	case errors.Is(err, fs.ErrBadPath):
		code = 400
	}
	return &pb.FileOpResult{
		OpId: op.OpId, Kind: op.Kind, Code: code, Error: err.Error(),
	}
}

// execFileOp executes one FileOp and sends its result (PRD §5.3). It runs
// off the envelope loop so a slow transfer cannot starve CANCEL/heartbeat
// traffic.
func (a *Agent) execFileOp(op *pb.FileOp) {
	cfg := a.fsCfg.Filled()
	var res *pb.FileOpResult
	switch op.Kind {
	case pb.FileOpKind_FILE_OP_STAT:
		st, err := fs.StatPath(op.Path)
		if err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{
				OpId: op.OpId, Kind: op.Kind, Code: 0,
				Stat: &pb.FileStat{
					Size: st.Size, Mode: st.Mode, Owner: st.Owner, Group: st.Group,
					MtimeUnix: st.MtimeUnix, Sha256: st.SHA256,
					IsDir: st.IsDir, IsSymlink: st.IsSymlink,
				},
			}
		}

	case pb.FileOpKind_FILE_OP_LIST:
		entries, truncated, err := fs.List(op.Path, cfg)
		if err != nil {
			res = fileOpError(op, err)
		} else {
			pbEntries := make([]*pb.FileEntry, 0, len(entries))
			for _, e := range entries {
				pbEntries = append(pbEntries, &pb.FileEntry{
					Name: e.Name, IsDir: e.IsDir, IsSymlink: e.IsSymlink,
					Size: e.Size, MtimeUnix: e.MtimeUnix, Mode: e.Mode,
				})
			}
			res = &pb.FileOpResult{
				OpId: op.OpId, Kind: op.Kind, Code: 0,
				Entries: pbEntries, Truncated: truncated,
			}
		}

	case pb.FileOpKind_FILE_OP_DOWNLOAD:
		data, _, done, err := fs.DownloadAt(op.Path, int64(op.Offset), cfg)
		if err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{
				OpId: op.OpId, Kind: op.Kind, Code: 0,
				Data: data, Done: done,
			}
		}

	case pb.FileOpKind_FILE_OP_UPLOAD_BEGIN:
		temp, err := fs.UploadBegin(op.Path, op.TotalSize, cfg)
		if err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{
				OpId: op.OpId, Kind: op.Kind, Code: 0,
				TempPath: temp,
			}
		}

	case pb.FileOpKind_FILE_OP_UPLOAD_CHUNK:
		recv, err := fs.UploadChunk(op.TempPath, int64(op.Offset), op.Data, cfg)
		if err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{
				OpId: op.OpId, Kind: op.Kind, Code: 0,
				Received: uint64(recv),
			}
		}

	case pb.FileOpKind_FILE_OP_UPLOAD_COMMIT:
		sha, err := fs.UploadCommit(op.TempPath, op.Path, op.Mode, op.TotalSize)
		if err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{
				OpId: op.OpId, Kind: op.Kind, Code: 0,
				NewSha256: sha,
			}
		}

	case pb.FileOpKind_FILE_OP_UPLOAD_ABORT:
		if err := fs.UploadAbort(op.TempPath); err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{OpId: op.OpId, Kind: op.Kind, Code: 0}
		}

	case pb.FileOpKind_FILE_OP_EDIT_CAS:
		newSha, err := fs.EditCAS(op.Path, op.ExpectedSha256, op.Data, cfg)
		if err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{
				OpId: op.OpId, Kind: op.Kind, Code: 0,
				NewSha256: newSha,
			}
		}

	case pb.FileOpKind_FILE_OP_SET_PERM:
		if err := fs.SetPerm(op.Path, op.Mode, op.User, op.Group); err != nil {
			res = fileOpError(op, err)
		} else {
			res = &pb.FileOpResult{OpId: op.OpId, Kind: op.Kind, Code: 0}
		}

	default:
		res = &pb.FileOpResult{
			OpId: op.OpId, Kind: op.Kind, Code: 400,
			Error: "unsupported file operation",
		}
	}
	a.sendFileOpResult(res)
}

// ---------------------------------------------------------------------------
// Package operations (PRD §5.6)
// ---------------------------------------------------------------------------

// pkgBackend selects the agent's package backend from the current fact set.
// The backend is stateless, so a fresh instance is safe to create per op.
func (a *Agent) pkgBackend() pkg.Backend {
	return pkg.SelectBackend(a.factset)
}

// sendPkgResult sends a PkgResult up the stream (no spooling: pkg ops are
// synchronous request/response, tied to the live stream).
func (a *Agent) sendPkgResult(res *pb.PkgResult) {
	a.sendMu.Lock()
	err := a.streamC.Send(context.Background(), &pb.Envelope{
		Kind:    pb.EnvelopeKind_PKG_RESULT,
		Payload: &pb.Envelope_PkgResult{PkgResult: res},
	})
	a.sendMu.Unlock()
	if err != nil {
		a.log.Printf("agent: pkg result %s send failed: %v", res.OpId, err)
	}
}

// execPkgOp executes one PkgOp and sends its result (PRD §5.6).
func (a *Agent) execPkgOp(op *pb.PkgOp) {
	var res *pb.PkgResult
	switch op.Kind {
	case pb.PkgOpKind_PKG_LIST_UPDATES:
		updates, err := a.pkgBackend().List(context.Background())
		if err != nil {
			res = &pb.PkgResult{OpId: op.OpId, Kind: op.Kind, Code: 500, Error: err.Error()}
		} else {
			res = &pb.PkgResult{OpId: op.OpId, Kind: op.Kind, Code: 0, Updates: toPbUpdates(updates)}
		}

	case pb.PkgOpKind_PKG_APPLY:
		res = a.execPkgApply(op)

	default:
		res = &pb.PkgResult{OpId: op.OpId, Kind: op.Kind, Code: 400, Error: "unsupported package operation"}
	}
	a.sendPkgResult(res)
}

// execPkgApply implements the apply flow (PRD §5.6): journal before, dry-run
// first, then (unless dry-run only) the real apply, then journal after.
func (a *Agent) execPkgApply(op *pb.PkgOp) *pb.PkgResult {
	kind := op.Kind
	b := a.pkgBackend()

	// 1. Before-state journal.
	before, err := b.Installed(context.Background())
	if err != nil {
		return &pb.PkgResult{OpId: op.OpId, Kind: kind, Code: 500, Error: "journal: " + err.Error()}
	}

	// 2. Dry-run — always, per PRD §5.6.
	drySummary, err := b.DryRun(context.Background())
	if err != nil {
		return &pb.PkgResult{
			OpId: op.OpId, Kind: kind, Code: 500,
			Error: "dry-run: " + err.Error(), DryRunSummary: drySummary,
		}
	}

	// Dry-run-only mode: stop here.
	if op.DryRun {
		return &pb.PkgResult{
			OpId: op.OpId, Kind: kind, Code: 0,
			DryRunSummary: drySummary, Before: toPbUpdates(before),
		}
	}

	// 3. Real apply.
	if err := b.Apply(context.Background()); err != nil {
		return &pb.PkgResult{
			OpId: op.OpId, Kind: kind, Code: 500,
			Error: "apply: " + err.Error(), DryRunSummary: drySummary,
			Before: toPbUpdates(before),
		}
	}

	// 4. After-state journal.
	after, err := b.Installed(context.Background())
	if err != nil {
		return &pb.PkgResult{
			OpId: op.OpId, Kind: kind, Code: 500,
			Error: "after-journal: " + err.Error(), DryRunSummary: drySummary,
			Before: toPbUpdates(before),
		}
	}

	return &pb.PkgResult{
		OpId: op.OpId, Kind: kind, Code: 0,
		Applied:       true,
		AppliedCount:  countPkgChanges(before, after),
		DryRunSummary: drySummary,
		Before:        toPbUpdates(before),
		After:         toPbUpdates(after),
	}
}

// toPbUpdates converts internal PkgUpdate slices to proto PkgUpdate slices.
func toPbUpdates(ups []pkg.PkgUpdate) []*pb.PkgUpdate {
	out := make([]*pb.PkgUpdate, 0, len(ups))
	for _, u := range ups {
		out = append(out, &pb.PkgUpdate{
			Name: u.Name, Installed: u.Installed, Available: u.Available,
			VulnCount: u.VulnCount, MaxSeverity: u.MaxSeverity, IsSecurity: u.IsSecurity,
		})
	}
	return out
}

// countPkgChanges counts packages whose installed version changed.
func countPkgChanges(before, after []pkg.PkgUpdate) int64 {
	afterByName := make(map[string]string, len(after))
	for _, u := range after {
		afterByName[u.Name] = u.Installed
	}
	var n int64
	for _, u := range before {
		if v, ok := afterByName[u.Name]; ok && v != u.Installed {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Task runs (M3, PRD §5.5)
// ---------------------------------------------------------------------------

// execTaskRun executes a TaskRun envelope and sends the result up.
func (a *Agent) execTaskRun(run *pb.TaskRun) {
	// Update the executor with the latest facts before running.
	a.taskExec.SetFacts(a.factset)

	// Run the task.
	res := a.taskRunner.Run(context.Background(), run)

	// Convert agent step results → proto.
	steps := make([]*pb.TaskStepResult, 0, len(res.Steps))
	for _, s := range res.Steps {
		steps = append(steps, &pb.TaskStepResult{
			StepIndex: int32(s.Index), State: s.State, Detail: s.Detail,
			Started: s.Started, Finished: s.Finished,
		})
	}

	// Send result up.
	a.sendTaskResult(run.GetRunId(), res.State, res.Error, steps)
}

// sendTaskResult sends a TaskRunResult up the stream (no spooling).
func (a *Agent) sendTaskResult(runID, state, errMsg string, steps []*pb.TaskStepResult) {
	a.sendMu.Lock()
	err := a.streamC.Send(context.Background(), &pb.Envelope{
		Kind:   pb.EnvelopeKind_TASK_RUN_RESULT,
		CorrId: runID,
		Payload: &pb.Envelope_TaskRunResult{TaskRunResult: &pb.TaskRunResult{
			RunId: runID,
			State: state,
			Error: errMsg,
			Steps: steps,
		}},
	})
	a.sendMu.Unlock()
	if err != nil {
		a.log.Printf("agent: task result %s send failed: %v", runID, err)
	}
}

// sendJobResult sends a JobRunResult up the stream (M3, PRD §5.4).
func (a *Agent) sendJobResult(r *jobs.Report) {
	a.sendMu.Lock()
	err := a.streamC.Send(context.Background(), &pb.Envelope{
		Kind:   pb.EnvelopeKind_JOB_RUN_RESULT,
		CorrId: r.RunID,
		Payload: &pb.Envelope_JobRunResult{JobRunResult: &pb.JobRunResult{
			RunId:       r.RunID,
			JobId:       r.JobID,
			State:       r.State,
			Error:       r.Error,
			ScheduledAt: r.ScheduledAt,
			StartedAt:   r.StartedAt,
			FinishedAt:  r.FinishedAt,
			Trigger:     r.Trigger,
			RetryOf:     r.RetryOf,
		}},
	})
	a.sendMu.Unlock()
	if err != nil {
		a.log.Printf("agent: job result %s send failed: %v", r.RunID, err)
	}
}

// jaToAssignment converts a proto JobAssignment to the agent's local type.
func jaToAssignment(ja *pb.JobAssignment) *jobs.Assignment {
	return &jobs.Assignment{
		JobID:            ja.JobId,
		Name:             ja.Name,
		Cron:             ja.Cron,
		Timezone:         ja.Timezone,
		TaskID:           ja.TaskId,
		TaskVersion:      ja.TaskVersion,
		Steps:            ja.Steps,
		MaxRunS:          ja.MaxRunS,
		OverlapPolicy:    ja.OverlapPolicy,
		FailurePolicy:    ja.FailurePolicy,
		RetryBackoffS:    ja.RetryBackoffS,
		SelectorSnapshot: ja.SelectorSnapshot,
		Version:          ja.Version,
	}
}
