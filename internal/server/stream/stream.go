// Package stream implements the server side of the AgentStream gRPC service:
// the Ed25519 challenge-response handshake, the envelope loop, and the
// dispatch path for commands (architecture §3, PRD R3/R4).
package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blawesom/partout/internal/cryptoutil"
	"github.com/blawesom/partout/internal/hsauth"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/store"
)

// Emitter is the subset of sse.Broker the handler needs.
type Emitter interface {
	Emit(kind string, payload any)
}

// Handler implements pb.AgentStreamServer.
type Handler struct {
	pb.UnimplementedAgentStreamServer
	st           *store.Store
	sse          Emitter
	log          *log.Logger
	serverPubB64 string // server Ed25519 public key (b64) for policy bundles

	mu       sync.Mutex
	sessions map[string]*Session // agent_id -> active session

	// fileMu guards filePending: op_id -> result channel for synchronous
	// file request/response over the stream (M2, PRD §5.3).
	fileMu      sync.Mutex
	filePending map[string]chan *pb.FileOpResult

	// pkgMu guards pkgPending: op_id -> result channel for synchronous
	// package request/response over the stream (M3, PRD §5.6).
	pkgMu      sync.Mutex
	pkgPending map[string]chan *pb.PkgResult

	// taskMu guards taskPending: run_id -> result channel for synchronous
	// task request/response over the stream (M3, PRD §5.5).
	taskMu      sync.Mutex
	taskPending map[string]chan *pb.TaskRunResult

	// ResultHook, if set, is called after a CommandResult is recorded with the
	// execution id of the finished run. Control uses it to recompute the
	// execution's aggregate state.
	ResultHook func(executionID string)

	// DisconnectHook, if set, is called when a session ends with the agent id.
	// Control uses it to mark in-flight runs interrupted and recompute the
	// affected execution aggregates (architecture §3.4).
	DisconnectHook func(agentID string)

	// SessionDataHook, if set, receives every up PTY data chunk
	// (agent, session, data). The sessions controller wires it for SSE +
	// recording (PRD §5.2.2).
	SessionDataHook func(agentID, sessionID string, data []byte)

	// SessionResultHook, if set, is called when a PTY session terminates
	// (agent, session, exit, state, duration). The sessions controller
	// finalizes the store row.
	SessionResultHook func(agentID, sessionID string, exitCode int32, state string, durationMs int64)

	// JobRunResultHook, if set, is called when an agent reports a scheduled
	// job run (M3, PRD §5.4). The jobs controller records the job_run row +
	// audit event.
	JobRunResultHook func(agentID string, r *pb.JobRunResult)
}

// NewHandler builds a stream handler.
func NewHandler(st *store.Store, sse Emitter, lg *log.Logger) *Handler {
	if lg == nil {
		lg = log.Default()
	}
	return &Handler{st: st, sse: sse, log: lg, sessions: make(map[string]*Session), filePending: make(map[string]chan *pb.FileOpResult), pkgPending: make(map[string]chan *pb.PkgResult), taskPending: make(map[string]chan *pb.TaskRunResult)}
}

// SetServerPubKey installs the server's Ed25519 public key (b64) which is
// included in every policy bundle so agents can verify decision signatures.
func (h *Handler) SetServerPubKey(b64 string) { h.serverPubB64 = b64 }

// pushPolicyBundle sends the current policy bundle to a newly connected
// agent.  The bundle carries the rules, bundle version, content hash, the
// server's signing public key, and this agent's tags/roles/ID so the
// agent-side guardrail can re-evaluate rules locally (architecture §5.3).
func (h *Handler) pushPolicyBundle(sess *Session) {
	version, hash, rulesJSON, err := h.st.BuildPolicyBundle()
	if err != nil {
		h.log.Printf("stream: build policy bundle: %v", err)
		return
	}
	tags, _ := h.st.Tags(sess.AgentID)
	roles, _ := h.st.Roles(sess.AgentID)
	bundle := &pb.PolicyBundle{
		Version:      version,
		ContentHash:  hash,
		RulesJson:    rulesJSON,
		ServerPubkey: []byte(h.serverPubB64),
		HostTags:     tags,
		HostRoles:    roles,
		AgentId:      sess.AgentID,
	}
	sess.send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_POLICY_BUNDLE,
		Payload: &pb.Envelope_PolicyBundle{PolicyBundle: bundle},
	})
}

// BroadcastPolicyBundle pushes the current policy bundle to every active
// session.  Called after a policy rule is created or deleted so connected
// agents pick up the change without reconnecting.
func (h *Handler) BroadcastPolicyBundle() {
	h.mu.Lock()
	sessions := make([]*Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	for _, s := range sessions {
		h.pushPolicyBundle(s)
	}
}

// Session is one authenticated agent stream.
type Session struct {
	AgentID string
	send    func(*pb.Envelope) error
}

// Register wires the handler into a grpc.Server.
func (h *Handler) Register(s *grpc.Server) {
	pb.RegisterAgentStreamServer(s, h)
}

// Stream is the gRPC entry point: handshake then envelope loop.
func (h *Handler) Stream(stream pb.AgentStream_StreamServer) error {
	ctx := stream.Context()

	// 1. Issue challenge.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return status.Errorf(codes.Internal, "stream: nonce: %v", err)
	}
	challenge := &pb.Envelope{
		Kind: pb.EnvelopeKind_CHALLENGE,
		Payload: &pb.Envelope_Challenge{Challenge: &pb.Challenge{
			Nonce:    nonce,
			ServerTs: time.Now().Unix(),
		}},
	}
	if err := stream.Send(challenge); err != nil {
		return err
	}

	// 2. Receive AuthProof.
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	ap := msg.GetAuthProof()
	if ap == nil {
		return status.Errorf(codes.Unauthenticated, "stream: expected AUTH_PROOF, got %s", msg.Kind)
	}

	// 3. Verify signature + skew.
	agent, err := h.st.AgentByUUID(ap.AgentUuid)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "stream: unknown agent uuid")
	}
	if err := hsauth.CheckSkew(ap.Ts, time.Now()); err != nil {
		return status.Errorf(codes.Unauthenticated, "stream: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(agent.ED25519Pub)
	if err != nil {
		return status.Errorf(codes.Internal, "stream: bad stored pubkey: %v", err)
	}
	sigMsg := hsauth.BuildMsg(nonce, ap.AgentUuid, ap.Ts)
	if !cryptoutil.VerifyEd25519(ed25519.PublicKey(pub), sigMsg, ap.Sig) {
		return status.Error(codes.Unauthenticated, "stream: bad signature")
	}

	// 4. Authenticated. Mark connected, register session.
	if err := h.st.SetAgentState(agent.ID, "connected"); err != nil {
		h.log.Printf("stream: set connected %s: %v", agent.ID, err)
	}
	h.st.MarkSeen(agent.ID)
	if h.sse != nil {
		h.sse.Emit("host.state", map[string]string{"agent_id": agent.ID, "state": "connected"})
	}

	// Register the session with its send closure set, so SendCommand never
	// observes a published session whose send is nil (avoids a data race).
	sess := &Session{AgentID: agent.ID}
	sess.send = func(env *pb.Envelope) error {
		return stream.Send(env)
	}
	h.mu.Lock()
	h.sessions[agent.ID] = sess
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.sessions, agent.ID)
		h.mu.Unlock()
		if err := h.st.SetAgentState(agent.ID, "disconnected"); err != nil {
			h.log.Printf("stream: set disconnected %s: %v", agent.ID, err)
		}
		// Fast-fail pending synchronous file ops for this agent (they are tied
		// to the live stream; the waiter's ctx would time out anyway).
		h.fileMu.Lock()
		for opID, ch := range h.filePending {
			delete(h.filePending, opID)
			select {
			case ch <- nil:
			default:
			}
		}
		h.fileMu.Unlock()
		if h.sse != nil {
			h.sse.Emit("host.state", map[string]string{"agent_id": agent.ID, "state": "disconnected"})
		}
		if h.DisconnectHook != nil {
			h.DisconnectHook(agent.ID)
		}
	}()

	h.log.Printf("stream: agent %s (%s) authenticated", agent.ID, ap.AgentUuid)

	// 4b. Push the current policy bundle so the agent's guardrail is effective
	// immediately (fail-closed until first bundle).
	h.pushPolicyBundle(sess)

	// 5. Envelope loop.
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err != io.EOF {
				h.log.Printf("stream: agent %s envelope loop exit: %v", agent.ID, err)
			}
			return err
		}
		if err := h.handleUp(ctx, sess, msg); err != nil {
			return err
		}
	}
}

// handleUp processes an up envelope.
func (h *Handler) handleUp(ctx context.Context, sess *Session, msg *pb.Envelope) error {
	switch {
	case msg.GetHeartbeat() != nil:
		h.st.MarkSeen(sess.AgentID)
	case msg.GetFacts() != nil:
		f := msg.GetFacts()
		if f.HostId == "" {
			f.HostId = sess.AgentID
		}
		if err := h.st.UpsertFacts(store.Facts{AgentID: f.HostId, TS: time.Now().Unix(), Data: f.Facts}); err != nil {
			h.log.Printf("stream: upsert facts %s: %v", f.HostId, err)
		}
	case msg.GetOutput() != nil:
		o := msg.GetOutput()
		stream := "stdout"
		if o.Stream == pb.OutputStream_OUTPUT_STDERR {
			stream = "stderr"
		}
		if err := h.st.AppendOutput(store.OutputChunk{RunID: o.RunId, ChunkSeq: int(o.ChunkSeq), Stream: stream, Data: o.Data}); err != nil {
			h.log.Printf("stream: append output %s: %v", o.RunId, err)
		}
		// First output means the command actually started running.
		if err := h.st.PromoteRunToRunning(o.RunId); err != nil {
			h.log.Printf("stream: promote run %s: %v", o.RunId, err)
		}
	case msg.GetResult() != nil:
		r := msg.GetResult()
		if err := h.st.UpdateRunState(r.RunId, r.State, r.ExitCode, r.DurationMs); err != nil {
			h.log.Printf("stream: update run %s: %v", r.RunId, err)
		}
		// Look up the execution and notify the control plane to finalize it.
		if h.ResultHook != nil {
			if execID, err := h.st.ExecutionIDForRun(r.RunId); err == nil {
				h.ResultHook(execID)
			} else {
				h.log.Printf("stream: execution for run %s: %v", r.RunId, err)
			}
		}
	case msg.GetAck() != nil:
		a := msg.GetAck()
		// For M0, we just log the ack.
		h.log.Printf("stream: ack %s (status=%s)", a.EnvelopeId, a.Status)
	case msg.GetFileOpResult() != nil:
		fr := msg.GetFileOpResult()
		h.fileMu.Lock()
		ch := h.filePending[fr.OpId]
		h.fileMu.Unlock()
		if ch != nil {
			select {
			case ch <- fr:
			default:
				// Waiter already gave up (timed out / stream closed); drop it.
			}
		}
	case msg.GetPkgResult() != nil:
		pk := msg.GetPkgResult()
		h.pkgMu.Lock()
		ch := h.pkgPending[pk.OpId]
		h.pkgMu.Unlock()
		if ch != nil {
			select {
			case ch <- pk:
			default:
				// Waiter already gave up (timed out / stream closed); drop it.
			}
		}
	case msg.GetTaskRunResult() != nil:
		tr := msg.GetTaskRunResult()
		h.taskMu.Lock()
		ch := h.taskPending[tr.RunId]
		h.taskMu.Unlock()
		if ch != nil {
			select {
			case ch <- tr:
			default:
				// Waiter already gave up.
			}
		}
	case msg.GetJobRunResult() != nil:
		jr := msg.GetJobRunResult()
		if h.JobRunResultHook != nil {
			h.JobRunResultHook(sess.AgentID, jr)
		}
	case msg.GetSessionData() != nil:
		sd := msg.GetSessionData()
		if h.SessionDataHook != nil {
			h.SessionDataHook(sess.AgentID, sd.SessionId, sd.Data)
		}
	case msg.GetSessionResult() != nil:
		sr := msg.GetSessionResult()
		if h.SessionResultHook != nil {
			h.SessionResultHook(sess.AgentID, sr.SessionId, sr.ExitCode, sr.State, sr.DurationMs)
		}
	default:
		// Unknown or handshake message — ignore.
	}
	return nil
}

// SendCommand delivers a command envelope to an authenticated agent.
// Returns an error if the agent has no active session.
func (h *Handler) SendCommand(agentID string, cmd *pb.Command) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_COMMAND,
		Payload: &pb.Envelope_Command{Command: cmd},
	}
	return sess.send(env)
}

// SendCancel asks the agent to stop an in-flight run (kills the process,
// which will report state=cancelled via CommandResult).
func (h *Handler) SendCancel(agentID string, runID string) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_CANCEL,
		Payload: &pb.Envelope_Cancel{Cancel: &pb.Cancel{RunId: runID}},
	}
	return sess.send(env)
}

// ---- Files (M2, PRD §5.3) ---------------------------------------------------

// SendFileOp sends one file op down and registers a pending result slot.
// The matching FileOpResult up resolves WaitFileResult.
func (h *Handler) SendFileOp(agentID string, op *pb.FileOp) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	ch := make(chan *pb.FileOpResult, 1)
	h.fileMu.Lock()
	if old := h.filePending[op.OpId]; old != nil {
		h.fileMu.Unlock()
		return fmt.Errorf("stream: duplicate file op id %s", op.OpId)
	}
	h.filePending[op.OpId] = ch
	h.fileMu.Unlock()
	if err := sess.send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_FILE_OP,
		CorrId:  op.OpId,
		Payload: &pb.Envelope_FileOp{FileOp: op},
	}); err != nil {
		h.fileMu.Lock()
		delete(h.filePending, op.OpId)
		h.fileMu.Unlock()
		return err
	}
	return nil
}

// WaitFileResult blocks until the file op's result arrives (or the stream
// drops / ctx ends). A nil result means the stream closed before a reply.
// The caller owns the op's lifecycle: this deletes the pending slot when it
// returns (success, timeout, or context cancellation), so a late-arriving
// result is dropped rather than leaked.
func (h *Handler) WaitFileResult(ctx context.Context, opID string) (*pb.FileOpResult, error) {
	h.fileMu.Lock()
	ch, ok := h.filePending[opID]
	h.fileMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("stream: no pending file op %s", opID)
	}
	// Remove the slot once we are done waiting, regardless of outcome.
	defer func() {
		h.fileMu.Lock()
		delete(h.filePending, opID)
		h.fileMu.Unlock()
	}()
	select {
	case res := <-ch:
		if res == nil {
			return nil, fmt.Errorf("stream: file op %s: stream closed", opID)
		}
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---- Packages (M3, PRD §5.6) -------------------------------------------------

// SendPkgOp sends one package op down and registers a pending result slot.
// The matching PkgResult up resolves WaitPkgResult.
func (h *Handler) SendPkgOp(agentID string, op *pb.PkgOp) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	ch := make(chan *pb.PkgResult, 1)
	h.pkgMu.Lock()
	if old := h.pkgPending[op.OpId]; old != nil {
		h.pkgMu.Unlock()
		return fmt.Errorf("stream: duplicate pkg op id %s", op.OpId)
	}
	h.pkgPending[op.OpId] = ch
	h.pkgMu.Unlock()
	if err := sess.send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_PKG_OP,
		CorrId:  op.OpId,
		Payload: &pb.Envelope_PkgOp{PkgOp: op},
	}); err != nil {
		h.pkgMu.Lock()
		delete(h.pkgPending, op.OpId)
		h.pkgMu.Unlock()
		return err
	}
	return nil
}

// WaitPkgResult blocks until the package op's result arrives (or the stream
// drops / ctx ends). A nil result means the stream closed before a reply.
func (h *Handler) WaitPkgResult(ctx context.Context, opID string) (*pb.PkgResult, error) {
	h.pkgMu.Lock()
	ch, ok := h.pkgPending[opID]
	h.pkgMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("stream: no pending pkg op %s", opID)
	}
	defer func() {
		h.pkgMu.Lock()
		delete(h.pkgPending, opID)
		h.pkgMu.Unlock()
	}()
	select {
	case res := <-ch:
		if res == nil {
			return nil, fmt.Errorf("stream: pkg op %s: stream closed", opID)
		}
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---- Tasks (M3, PRD §5.5) --------------------------------------------------

// SendTaskRun dispatches a task run down the stream and registers a pending
// result slot. The matching TaskRunResult up resolves WaitTaskResult.
func (h *Handler) SendTaskRun(agentID string, run *pb.TaskRun) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	ch := make(chan *pb.TaskRunResult, 1)
	h.taskMu.Lock()
	if old := h.taskPending[run.RunId]; old != nil {
		h.taskMu.Unlock()
		return fmt.Errorf("stream: duplicate task run id %s", run.RunId)
	}
	h.taskPending[run.RunId] = ch
	h.taskMu.Unlock()
	if err := sess.send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_TASK_RUN,
		CorrId:  run.RunId,
		Payload: &pb.Envelope_TaskRun{TaskRun: run},
	}); err != nil {
		h.taskMu.Lock()
		delete(h.taskPending, run.RunId)
		h.taskMu.Unlock()
		return err
	}
	return nil
}

// WaitTaskResult blocks until the task run's result arrives (or the stream
// drops / ctx ends).
func (h *Handler) WaitTaskResult(ctx context.Context, runID string) (*pb.TaskRunResult, error) {
	h.taskMu.Lock()
	ch, ok := h.taskPending[runID]
	h.taskMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("stream: no pending task run %s", runID)
	}
	defer func() {
		h.taskMu.Lock()
		delete(h.taskPending, runID)
		h.taskMu.Unlock()
	}()
	select {
	case res := <-ch:
		if res == nil {
			return nil, fmt.Errorf("stream: task run %s: stream closed", runID)
		}
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---- Jobs (M3, PRD §5.4) ----------------------------------------------------

// SendJobAssign pushes a job assignment down to an agent (fire-and-forget;
// the agent schedules it on its own clock). Returns an error only if the
// agent is not currently connected.
func (h *Handler) SendJobAssign(agentID string, a *pb.JobAssignment) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	return sess.send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_JOB_ASSIGN,
		CorrId:  a.JobId,
		Payload: &pb.Envelope_JobAssign{JobAssign: a},
	})
}

// SendJobUnassign removes a job from an agent (fire-and-forget).
func (h *Handler) SendJobUnassign(agentID, jobID string) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	return sess.send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_JOB_UNASSIGN,
		CorrId:  jobID,
		Payload: &pb.Envelope_JobUnassign{JobUnassign: &pb.JobUnassignment{JobId: jobID}},
	})
}

// ---- Sessions (M2, PRD §5.2.2) ------------------------------------------------

func (h *Handler) sendSessionDown(agentID, sessionID string, env *pb.Envelope) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	return sess.send(env)
}

// SendSessionOpen dispatches a PTY session open to the agent.
func (h *Handler) SendSessionOpen(agentID string, open *pb.SessionOpen) error {
	return h.sendSessionDown(agentID, open.SessionId,
		&pb.Envelope{Kind: pb.EnvelopeKind_SESSION_OPEN, CorrId: open.SessionId,
			Payload: &pb.Envelope_SessionOpen{SessionOpen: open}})
}

// SendSessionInput forwards terminal input to the agent.
func (h *Handler) SendSessionInput(agentID, sessionID string, data []byte) error {
	return h.sendSessionDown(agentID, sessionID, &pb.Envelope{
		Kind: pb.EnvelopeKind_SESSION_INPUT, CorrId: sessionID,
		Payload: &pb.Envelope_SessionInput{SessionInput: &pb.SessionInput{
			SessionId: sessionID, Data: data}},
	})
}

// SendSessionResize forwards a terminal resize to the agent.
func (h *Handler) SendSessionResize(agentID, sessionID string, cols, rows int32) error {
	return h.sendSessionDown(agentID, sessionID, &pb.Envelope{
		Kind: pb.EnvelopeKind_SESSION_RESIZE, CorrId: sessionID,
		Payload: &pb.Envelope_SessionResize{SessionResize: &pb.SessionResize{
			SessionId: sessionID, Cols: cols, Rows: rows}},
	})
}

// SendSessionClose asks the agent to end a PTY session.
func (h *Handler) SendSessionClose(agentID, sessionID string) error {
	return h.sendSessionDown(agentID, sessionID, &pb.Envelope{
		Kind: pb.EnvelopeKind_SESSION_CLOSE, CorrId: sessionID,
		Payload: &pb.Envelope_SessionClose{SessionClose: &pb.SessionClose{
			SessionId: sessionID}},
	})
}

// ---- Secrets (M3, PRD §5.7) -------------------------------------------------

// SendSecretMaterialize delivers an E2E-encrypted secret to an agent. The
// agent holds it for the lifetime of the declaring run (and optionally
// caches the sealed form for offline use, per cache_ttl_s).
func (h *Handler) SendSecretMaterialize(agentID string, sm *pb.SecretMaterialize) error {
	h.mu.Lock()
	sess, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("stream: no active session for %s", agentID)
	}
	return sess.send(&pb.Envelope{
		Kind:    pb.EnvelopeKind_SECRET_MATERIALIZE,
		CorrId:  sm.Ref,
		Payload: &pb.Envelope_SecretMaterialize{SecretMaterialize: sm},
	})
}

// AgentSession returns the active session for an agent (for tests).
func (h *Handler) AgentSession(agentID string) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[agentID]
}
