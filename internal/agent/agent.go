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
	"time"

	"github.com/blawesom/partout/internal/agent/exec"
	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/agent/stream"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/identity"

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
	return &Agent{
		id:            id,
		cfg:           cfg,
		log:           lg,
		streamC:       stream.New(id, stream.Config{ServerURL: cfg.ServerURL, CAFile: cfg.TLSCAFile, CertFile: cfg.TLSCertFile, KeyFile: cfg.TLSKeyFile}, lg),
		start:         time.Now(),
		factset:       facts.Collector(id, cfg.FactsInterval),
		policyDir:     filepath.Join(cfg.DataDir, "agent"),
		activeRunners: make(map[string]context.CancelFunc),
	}
}

// Run blocks until ctx is canceled or the agent is revoked. It manages the
// connect → stream → reconnect loop with exponential backoff + jitter.
func (a *Agent) Run(ctx context.Context) error {
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
		// ACK delivery.
		_ = a.streamC.Send(ctx, &pb.Envelope{
			Kind: pb.EnvelopeKind_ACK,
			Payload: &pb.Envelope_Ack{Ack: &pb.Ack{
				EnvelopeId: env.Id,
				Status:     pb.AckStatus_ACK_OK,
			}},
		})
		// Register a cancel handle for this run.
		runCtx, runCancel := context.WithCancel(ctx)
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
		pb := env.GetPolicyBundle()
		a.log.Printf("agent: policy bundle v%d received", pb.Version)
		if err := a.savePolicy(pb); err != nil {
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
func (a *Agent) execCommand(ctx context.Context, cmd *pb.Command) {
	seq := uint64(0)
	onChunk := func(c exec.Chunk) {
		s := pb.OutputStream_OUTPUT_STDOUT
		if c.Stream == "stderr" {
			s = pb.OutputStream_OUTPUT_STDERR
		}
		env := &pb.Envelope{
			Kind: pb.EnvelopeKind_COMMAND_OUTPUT,
			Payload: &pb.Envelope_Output{Output: &pb.CommandOutput{
				RunId: cmd.RunId, ChunkSeq: seq, Stream: s, Data: c.Data,
			}},
		}
		seq++
		if err := a.streamC.Send(ctx, env); err != nil {
			a.log.Printf("agent: send output %s: %v", cmd.RunId, err)
		}
	}

	res, err := exec.Run(ctx, cmd.Cmd, cmd.Args, cmd.Cwd, cmd.Env, cmd.TimeoutS, onChunk)
	if err != nil {
		res = &exec.Result{State: "failed", ExitCode: -1}
	}

	// Remove from active runners.
	a.activeMu.Lock()
	delete(a.activeRunners, cmd.RunId)
	a.activeMu.Unlock()

	result := &pb.Envelope{
		Kind: pb.EnvelopeKind_COMMAND_RESULT,
		Payload: &pb.Envelope_Result{Result: &pb.CommandResult{
			RunId: cmd.RunId, ExitCode: res.ExitCode, State: res.State, DurationMs: res.DurationMS,
		}},
	}
	if err := a.streamC.Send(ctx, result); err != nil {
		a.log.Printf("agent: send result %s: %v", cmd.RunId, err)
		return
	}
	a.log.Printf("agent: run %s finished: %s (exit=%d, %dms)", cmd.RunId, res.State, res.ExitCode, res.DurationMS)
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
