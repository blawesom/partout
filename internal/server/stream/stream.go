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
	st  *store.Store
	sse Emitter
	log *log.Logger

	mu       sync.Mutex
	sessions map[string]*Session // agent_id -> active session

	// ResultHook, if set, is called after a CommandResult is recorded with the
	// execution id of the finished run. Control uses it to recompute the
	// execution's aggregate state.
	ResultHook func(executionID string)
}

// NewHandler builds a stream handler.
func NewHandler(st *store.Store, sse Emitter, lg *log.Logger) *Handler {
	if lg == nil {
		lg = log.Default()
	}
	return &Handler{st: st, sse: sse, log: lg, sessions: make(map[string]*Session)}
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
		if h.sse != nil {
			h.sse.Emit("host.state", map[string]string{"agent_id": agent.ID, "state": "disconnected"})
		}
	}()

	h.log.Printf("stream: agent %s (%s) authenticated", agent.ID, ap.AgentUuid)

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

// AgentSession returns the active session for an agent (for tests).
func (h *Handler) AgentSession(agentID string) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[agentID]
}
