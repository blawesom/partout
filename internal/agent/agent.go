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
	"github.com/blawesom/partout/internal/agent/guardrail"
	"github.com/blawesom/partout/internal/agent/stream"
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
	return &Agent{
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
		spooled:       make(map[string]bool),
		activeRunners: make(map[string]context.CancelFunc),
	}
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
	backoff := backoffBase
	for {
		err := a.connectAndStream(ctx)
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
