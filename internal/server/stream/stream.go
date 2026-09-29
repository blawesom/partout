// Package stream implements the server side of the AgentStream gRPC service:
// the Ed25519 challenge-response handshake, the envelope loop, and the
// dispatch path for commands (architecture §3, PRD R3/R4).
package stream

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blawesom/partout/internal/certutil"
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
	serverPubB64 string       // server Ed25519 public key (b64) for policy bundles
	ca           *certutil.CA // root CA for mTLS leaf rotation (nil = plaintext)

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

	// updateMu guards updateGrants: one-time artifact download grants
	// (M8.1, PRD §11).
	updateMu     sync.Mutex
	updateGrants map[string]updateGrant

	// taskMu guards taskPending: run_id -> result channel for synchronous
	// task request/response over the stream (M3, PRD §5.5).
	taskMu      sync.Mutex
	taskPending map[string]chan *pb.TaskRunResult

	// offlineMu guards offlineQueue: agent_id -> down envelopes queued for an
	// agent that is not currently connected (dispatch to offline agents). Each
	// entry expires after offlineTTL; on reconnect the queue is drained.
	offlineMu    sync.Mutex
	offlineQueue map[string][]*queuedEnvelope
	offlineTTL   time.Duration
	offlineCap   int // max queued envelopes per agent (bounded growth)

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

	// TaskResultHook, if set, is called when a TaskRunResult arrives with no
	// live waiter — e.g. a post-reboot resume whose original dispatch already
	// timed out (PRD §5.5). Wired to the tasks controller, which finalizes
	// the existing run row in place.
	TaskResultHook func(agentID, runID string, tr *pb.TaskRunResult)

	// ObserveFactsHook, if set, is called when an agent reports structured
	// observe facts (M5). It receives the agent ID and the raw JSON blob
	// (already merged into host_facts).
	ObserveFactsHook func(agentID string)

	// UpdateResultHook, if set, is called when an agent reports a self-update
	// result (M8.1). The updates rollout manager maps the phase onto the
	// per-host run state machine.
	UpdateResultHook func(agentID string, r *pb.UpdateResult)
}

// queuedEnvelope is one down envelope held for an offline agent.
type queuedEnvelope struct {
	env       *pb.Envelope
	expiresAt time.Time
}

// ErrAgentOffline is returned by SendCommand when the target agent is not
// connected and the command has been queued for delivery on reconnect (within
// the offline TTL). Callers treat it as "accepted, pending delivery", not a
// failure.
var ErrAgentOffline = fmt.Errorf("stream: agent offline; command queued for delivery on reconnect")

// NewHandler builds a stream handler.
func NewHandler(st *store.Store, sse Emitter, lg *log.Logger) *Handler {
	if lg == nil {
		lg = log.Default()
	}
	return &Handler{st: st, sse: sse, log: lg, sessions: make(map[string]*Session), filePending: make(map[string]chan *pb.FileOpResult), pkgPending: make(map[string]chan *pb.PkgResult), taskPending: make(map[string]chan *pb.TaskRunResult), offlineQueue: make(map[string][]*queuedEnvelope), offlineTTL: 30 * time.Minute, offlineCap: 100}
}

// SetOfflineTTL sets how long a down envelope is held for an offline agent
// before it expires (default 30 minutes).
func (h *Handler) SetOfflineTTL(d time.Duration) {
	if d <= 0 {
		return
	}
	h.offlineMu.Lock()
	h.offlineTTL = d
	h.offlineMu.Unlock()
}

// SetServerPubKey installs the server's Ed25519 public key (b64) which is
// included in every policy bundle so agents can verify decision signatures.
func (h *Handler) SetServerPubKey(b64 string) { h.serverPubB64 = b64 }

// SetCA installs the root CA used to re-sign agent mTLS leaves on rotation.
// nil = plaintext mode (rotation disabled).
func (h *Handler) SetCA(ca *certutil.CA) { h.ca = ca }

// sendDown delivers a down envelope to a specific agent's live session.
// Returns an error if the agent is not currently connected.
func (h *Handler) sendDown(agentID string, env *pb.Envelope) error {
	h.mu.Lock()
	sess := h.sessions[agentID]
	h.mu.Unlock()
	if sess == nil {
		return fmt.Errorf("stream: agent %s not connected", agentID)
	}
	return sess.send(env)
}

// RotateAgentCert re-signs the agent's mTLS leaf from its enrolled ECDSA
// public key and delivers the new leaf over the live stream (TlsCert). The
// agent's private key is unchanged. Returns the new leaf's hex serial.
// Errors if rotation is disabled (plaintext), the agent has no enrolled key,
// or the agent is not connected.
func (h *Handler) RotateAgentCert(agentID string) (string, error) {
	if h.ca == nil {
		return "", fmt.Errorf("stream: TLS rotation disabled (plaintext mode)")
	}
	agent, err := h.st.Agent(agentID)
	if err != nil {
		return "", fmt.Errorf("stream: load agent %s: %w", agentID, err)
	}
	if agent.TlsPub == "" {
		return "", fmt.Errorf("stream: agent %s has no enrolled TLS key", agentID)
	}
	pubB64, err := base64.StdEncoding.DecodeString(agent.TlsPub)
	if err != nil {
		return "", fmt.Errorf("stream: decode tls_pub: %w", err)
	}
	pkixKey, err := x509.ParsePKIXPublicKey(pubB64)
	if err != nil {
		return "", fmt.Errorf("stream: parse tls_pub: %w", err)
	}
	pub, ok := pkixKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("stream: tls_pub is not ECDSA")
	}
	leafPEM, serial, err := h.ca.SignLeafForPublicKey(pub, agentID, []string{agent.UUID})
	if err != nil {
		return "", fmt.Errorf("stream: sign leaf: %w", err)
	}
	env := &pb.Envelope{
		Kind: pb.EnvelopeKind_TLS_CERT,
		Payload: &pb.Envelope_TlsCert{TlsCert: &pb.TlsCert{
			LeafCert: leafPEM,
			Serial:   serial,
		}},
	}
	if err := h.sendDown(agentID, env); err != nil {
		return "", err
	}
	// Record the new leaf's expiry (optimistic: the new leaf is valid now and
	// the old leaf stays valid until its own expiry, so this is safe even if
	// the agent swaps on its next reconnect).
	if na, err := certutil.ParseLeafNotAfter([]byte(leafPEM)); err == nil {
		if err := h.st.SetAgentTLS(agentID, agent.TlsPub, na.Unix()); err != nil {
			h.log.Printf("stream: set agent TLS expiry %s: %v", agentID, err)
		}
	}
	if h.sse != nil {
		h.sse.Emit("tls.rotated", map[string]string{"agent_id": agentID, "serial": serial})
	}
	h.log.Printf("stream: rotated mTLS leaf for %s (serial %s)", agentID, serial)
	return serial, nil
}

// PushCertExpiryRotation rotates every connected TLS agent whose current leaf
// is expired or within the given window. Returns the count rotated.
func (h *Handler) PushCertExpiryRotation(window time.Duration) int {
	if h.ca == nil {
		return 0
	}
	agents, err := h.st.Agents()
	if err != nil {
		return 0
	}
	n := 0
	for _, a := range agents {
		if a.TlsPub == "" || a.TlsNotAfter == 0 {
			continue
		}
		if time.Until(time.Unix(a.TlsNotAfter, 0)) > window {
			continue
		}
		// Only rotate connected agents: an offline agent cannot receive the new
		// leaf and would be retried (and error-logged) on every tick.
		if a.State != "connected" {
			continue
		}
		if _, err := h.RotateAgentCert(a.ID); err != nil {
			h.log.Printf("stream: expiry rotation %s: %v", a.ID, err)
			continue
		}
		n++
	}
	return n
}

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
	// sendMu serializes down-sends on this stream: grpc's SendMsg is not safe
	// to call concurrently from multiple goroutines, and down envelopes now
	// originate from several (control dispatch, offline drain, hourly cert
	// rotation ticker, admin rotate handler, session/file/pkg sends).
	sendMu sync.Mutex
	send   func(*pb.Envelope) error
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
		sess.sendMu.Lock()
		defer sess.sendMu.Unlock()
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

	// 4c. Deliver any down envelopes queued while this agent was offline
	// (dispatch to offline agents). Runs after the session is registered so
	// SendCommand would also find it, but we drain the explicit queue here.
	h.drainOffline(agent.ID, sess.send)

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
		// Key strictly by the authenticated session: FactsBatch.HostId is
		// agent-supplied and must not be trusted as a storage key, or an
		// enrolled agent could overwrite another host's facts. The field is
		// kept for wire compatibility and ignored here.
		if err := h.st.UpsertFacts(store.Facts{AgentID: sess.AgentID, TS: time.Now().Unix(), Data: f.Facts}); err != nil {
			h.log.Printf("stream: upsert facts %s: %v", sess.AgentID, err)
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
				h.log.Printf("stream: run %s result recorded (state=%s, exit=%d), finalizing execution %s", r.RunId, r.State, r.ExitCode, execID)
				h.ResultHook(execID)
			} else {
				// A skipped hook strands the execution aggregate in a
				// non-terminal state, so this is load-bearing: log it loudly.
				h.log.Printf("stream: execution for run %s: %v (execution aggregate will NOT be finalized)", r.RunId, err)
			}
		}
	case msg.GetAck() != nil:
		a := msg.GetAck()
		// For M0, we just log the ack.
		h.log.Printf("stream: ack %s (status=%s)", a.EnvelopeId, a.Status)
	case msg.GetTlsRenew() != nil:
		tr := msg.GetTlsRenew()
		h.log.Printf("stream: tls renew request from %s (reason=%s)", sess.AgentID, tr.Reason)
		if serial, err := h.RotateAgentCert(sess.AgentID); err != nil {
			h.log.Printf("stream: tls renew %s: %v", sess.AgentID, err)
		} else {
			h.log.Printf("stream: tls renewed %s (serial %s)", sess.AgentID, serial)
		}
	case msg.GetUpdateResult() != nil:
		// M8.1 update outcome (step 2). Audit + SSE so the control plane and
		// UI can watch the canary; the step-3 run state machine consumes the
		// same event via UpdateResultHook.
		ur := msg.GetUpdateResult()
		if h.UpdateResultHook != nil {
			h.UpdateResultHook(sess.AgentID, ur)
		}
		h.log.Printf("stream: update result %s (release %s, error=%q)", ur.Phase, ur.ReleaseId, ur.Error)
		_ = h.st.AppendAudit(store.AuditEvent{
			TS: time.Now().Unix(), Kind: "update.result", Actor: "agent", AgentID: sess.AgentID,
			Payload: fmt.Sprintf(`{"release_id":%q,"phase":%q,"error":%q,"version":%q}`,
				ur.ReleaseId, ur.Phase, ur.Error, ur.Version),
		})
		if h.sse != nil {
			h.sse.Emit("update.result", map[string]string{
				"agent_id": sess.AgentID, "release_id": ur.ReleaseId, "phase": ur.Phase,
			})
		}
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
		} else if h.TaskResultHook != nil {
			// Late result with no waiter (e.g. a post-reboot resume of a run
			// whose dispatch already timed out): let the controller finalize
			// the run row in place (PRD §5.5).
			h.TaskResultHook(sess.AgentID, tr.RunId, tr)
		}
	case msg.GetJobRunResult() != nil:
		jr := msg.GetJobRunResult()
		if h.JobRunResultHook != nil {
			h.JobRunResultHook(sess.AgentID, jr)
		}
	case msg.GetObserveFacts() != nil:
		of := msg.GetObserveFacts()
		// Merge structured facts into the host_facts JSON document (M5,
		// R18–R20); the store preserves the flat fact keys. Keyed by the
		// authenticated session, never by the agent-supplied HostId.
		if err := h.st.UpsertHostFactsJSON(sess.AgentID, of.Json); err != nil {
			h.log.Printf("stream: upsert observe facts %s: %v", of.Kind, err)
		}
		if h.ObserveFactsHook != nil {
			h.ObserveFactsHook(sess.AgentID)
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
	env := &pb.Envelope{
		Kind:    pb.EnvelopeKind_COMMAND,
		Payload: &pb.Envelope_Command{Command: cmd},
	}
	if !ok {
		// Dispatch-to-offline: hold the command for delivery on reconnect.
		h.queueOffline(agentID, env)
		return ErrAgentOffline
	}
	return sess.send(env)
}

// queueOffline enqueues a down envelope for an offline agent (bounded).
func (h *Handler) queueOffline(agentID string, env *pb.Envelope) {
	h.offlineMu.Lock()
	q := h.offlineQueue[agentID]
	var dropped *queuedEnvelope
	if len(q) >= h.offlineCap {
		dropped = q[0]
		q = q[1:] // drop the oldest to bound memory
	}
	ttl := h.offlineTTL
	h.offlineQueue[agentID] = append(q, &queuedEnvelope{env: env, expiresAt: time.Now().Add(ttl)})
	h.offlineMu.Unlock()

	// Finalize the evicted run OUTSIDE the lock so it cannot wedge in a
	// non-terminal state forever (the sweeper can no longer see it).
	if dropped != nil {
		h.log.Printf("stream: offline queue for %s full (%d); evicting oldest envelope", agentID, h.offlineCap)
		h.expireQueued(dropped)
	}
	h.log.Printf("stream: queued %s for offline agent %s (ttl %s)", env.Kind, agentID, ttl)
}

// drainOffline delivers any queued (non-expired) down envelopes to a
// reconnected agent. For COMMAND envelopes it marks the run delivered so the
// execution aggregate proceeds.
func (h *Handler) drainOffline(agentID string, send func(*pb.Envelope) error) {
	now := time.Now()
	h.offlineMu.Lock()
	q := h.offlineQueue[agentID]
	if len(q) == 0 {
		h.offlineMu.Unlock()
		return
	}
	delete(h.offlineQueue, agentID)
	h.offlineMu.Unlock()

	for i, qe := range q {
		if now.After(qe.expiresAt) {
			h.expireQueued(qe)
			continue
		}
		if err := send(qe.env); err != nil {
			// The stream failed mid-drain: re-queue this envelope and the
			// remaining tail (preserving expiry) so nothing is lost or wedged
			// in a non-terminal state with no sweepable queue entry.
			h.log.Printf("stream: drain offline %s: %v; re-queueing %d envelope(s)", agentID, err, len(q)-i)
			h.requeueOffline(agentID, q[i:])
			return
		}
		if c := qe.env.GetCommand(); c != nil {
			if err := h.st.UpdateRunState(c.RunId, "delivered", -1, 0); err != nil {
				h.log.Printf("stream: mark delivered %s: %v", c.RunId, err)
			}
		}
	}
}

// requeueOffline puts previously-queued envelopes back (preserving their
// original expiry) after a failed drain, so they stay visible to the sweeper.
func (h *Handler) requeueOffline(agentID string, qes []*queuedEnvelope) {
	h.offlineMu.Lock()
	h.offlineQueue[agentID] = append(h.offlineQueue[agentID], qes...)
	h.offlineMu.Unlock()
}

// expireQueued finalizes a timed-out (or evicted) queued envelope: a COMMAND
// run becomes 'expired', and the execution aggregate is recomputed so it does
// not stay non-terminal forever.
func (h *Handler) expireQueued(qe *queuedEnvelope) {
	c := qe.env.GetCommand()
	if c == nil {
		return
	}
	if err := h.st.UpdateRunState(c.RunId, "expired", -1, 0); err != nil {
		h.log.Printf("stream: mark expired %s: %v", c.RunId, err)
		return
	}
	if h.ResultHook != nil && c.ExecutionId != "" {
		h.ResultHook(c.ExecutionId)
	}
}

// QueueCount returns the number of down envelopes queued for an agent (tests).
func (h *Handler) QueueCount(agentID string) int {
	h.offlineMu.Lock()
	defer h.offlineMu.Unlock()
	return len(h.offlineQueue[agentID])
}

// StartOfflineSweeper periodically expires queued envelopes for agents that
// have not reconnected within the TTL. Runs until ctx is done.
func (h *Handler) StartOfflineSweeper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				var expired []*queuedEnvelope
				h.offlineMu.Lock()
				for agentID, q := range h.offlineQueue {
					kept := q[:0]
					for _, qe := range q {
						if now.After(qe.expiresAt) {
							expired = append(expired, qe)
						} else {
							kept = append(kept, qe)
						}
					}
					if len(kept) == 0 {
						delete(h.offlineQueue, agentID)
					} else {
						h.offlineQueue[agentID] = kept
					}
				}
				h.offlineMu.Unlock()
				for _, qe := range expired {
					h.expireQueued(qe)
				}
			}
		}
	}()
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
