// Package sessions implements the server-side PTY session manager
// (M2, PRD §5.2.2): open/input/resize/close over the agent stream, SSE
// output (session.data), optional recording (session_records, 30-day
// retention), and D2 semantics — sessions are interrupted on stream drop.
package sessions

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	"github.com/blawesom/partout/internal/server/stream"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// activeSession holds the runtime state for one open PTY session.
type activeSession struct {
	agentID string
	record  bool
}

// Manager owns the server-side view of PTY sessions.
type Manager struct {
	st    *store.Store
	h     *stream.Handler
	sse   *sse.Broker
	log   *log.Logger
	ident *certutil.ServerIdentity

	mu  sync.Mutex
	active map[string]activeSession

	// seqMu guards seq: per-session recording seq counters.
	seqMu sync.Mutex
	seq   map[string]int
}

// New builds a Manager and wires the stream handler hooks.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Manager {
	if lg == nil {
		lg = log.Default()
	}
	m := &Manager{st: st, h: h, sse: sseB, log: lg, active: make(map[string]activeSession), seq: make(map[string]int)}
	h.SessionDataHook = m.onSessionData
	h.SessionResultHook = m.onSessionResult
	return m
}

// SetIdentity installs the server's Ed25519 signing key (signs the Decision
// attached to SESSION_OPEN; the session is an exec action, arch §5.3).
func (m *Manager) SetIdentity(ident *certutil.ServerIdentity) { m.ident = ident }

// OpenRequest is a new PTY session.
type OpenRequest struct {
	AgentID string   `json:"agent_id"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args,omitempty"`
	Cols    int32    `json:"cols,omitempty"`
	Rows    int32    `json:"rows,omitempty"`
	Record  bool     `json:"record"`
	Actor   string   `json:"actor"`
	Role    string   `json:"role"`
}

// Open creates a session row, evaluates policy (exec action), and sends
// SESSION_OPEN down the stream. Returns the created session.
func (m *Manager) Open(ctx context.Context, req OpenRequest) (*store.Session, error) {
	if req.AgentID == "" || req.Cmd == "" {
		return nil, fmt.Errorf("sessions: agent_id and cmd required")
	}
	if req.Cols <= 0 {
		req.Cols = 80
	}
	if req.Rows <= 0 {
		req.Rows = 24
	}
	host, err := m.st.Agent(req.AgentID)
	if err != nil {
		return nil, fmt.Errorf("sessions: agent %s: %w", req.AgentID, err)
	}
	argsJSON := ""
	if req.Args != nil {
		b, err := json.Marshal(req.Args)
		if err != nil {
			return nil, fmt.Errorf("sessions: marshal args: %w", err)
		}
		argsJSON = string(b)
	}
	action := policy.Action{
		HostID:      host.ID,
		HostTags:    tagsFor(m.st, host.ID),
		HostRoles:   rolesFor(m.st, host.ID),
		ActorRole:   req.Role,
		Cmd:         req.Cmd,
		Args:        req.Args,
		CommandLine: joinCommandLine(req.Cmd, req.Args),
	}
	rules, err := m.st.GetPolicyRules()
	if err != nil {
		return nil, fmt.Errorf("sessions: load policies: %w", err)
	}
	decision := policy.Evaluate(rules, action)
	if decision.Effect != policy.EffectAllow {
		sess := &store.Session{
			ID: id.New("sess"), AgentID: req.AgentID,
			Cmd: req.Cmd, ArgsJSON: argsJSON, Cols: req.Cols, Rows: req.Rows,
			Record: req.Record, State: "denied", Actor: req.Actor, Opened: now(),
		}
		if err := m.st.CreateSession(*sess); err != nil {
			return nil, err
		}
		m.audit(sess.ID, req.AgentID, "denied", decision.Reason)
		return sess, fmt.Errorf("sessions: denied by policy: %s", decision.Reason)
	}
	sess := &store.Session{
		ID: id.New("sess"), AgentID: req.AgentID,
		Cmd: req.Cmd, ArgsJSON: argsJSON, Cols: req.Cols, Rows: req.Rows,
		Record: req.Record, State: "open", Actor: req.Actor, Opened: now(),
	}
	if err := m.st.CreateSession(*sess); err != nil {
		return nil, fmt.Errorf("sessions: create: %w", err)
	}
	// Build the open envelope (signed Decision for the agent guardrail).
	var dec *pb.Decision
	if m.ident != nil {
		version, _ := m.st.PolicyBundleVersion()
		dec = &pb.Decision{
			RunId:         sess.ID,
			BundleVersion: version,
			Effect:        decision.Effect,
			MatchedRules:  decision.MatchedRules,
			Sig: policy.SignDecision(m.ident.Priv, sess.ID, version,
				decision.Effect, decision.MatchedRules, req.Role),
			ActorRole: req.Role,
		}
	}
	open := &pb.SessionOpen{
		SessionId: sess.ID,
		Cmd:       req.Cmd,
		Args:      req.Args,
		Cols:      req.Cols,
		Rows:      req.Rows,
		Record:    req.Record,
		Decision:  dec,
	}
	if err := m.h.SendSessionOpen(req.AgentID, open); err != nil {
		_ = m.st.UpdateSessionState(sess.ID, "failed", -1, err.Error())
		m.audit(sess.ID, req.AgentID, "failed", err.Error())
		return nil, fmt.Errorf("sessions: dispatch: %w", err)
	}
	m.mu.Lock()
	m.active[sess.ID] = activeSession{agentID: req.AgentID, record: req.Record}
	m.mu.Unlock()
	if m.sse != nil {
		m.sse.Emit("session.opened", map[string]string{
			"session_id": sess.ID, "agent_id": req.AgentID, "cmd": req.Cmd,
		})
	}
	return sess, nil
}

// Input forwards terminal input to the agent.
func (m *Manager) Input(sessionID string, data []byte) error {
	aid, ok := m.agentFor(sessionID)
	if !ok {
		return fmt.Errorf("sessions: %s: not found or not open", sessionID)
	}
	return m.h.SendSessionInput(aid, sessionID, data)
}

// Resize forwards a window resize to the agent.
func (m *Manager) Resize(sessionID string, cols, rows int32) error {
	aid, ok := m.agentFor(sessionID)
	if !ok {
		return fmt.Errorf("sessions: %s: not found or not open", sessionID)
	}
	return m.h.SendSessionResize(aid, sessionID, cols, rows)
}

// Close ends a session (SIGHUP, escalate).
func (m *Manager) Close(sessionID string) error {
	aid, ok := m.agentFor(sessionID)
	if !ok {
		return fmt.Errorf("sessions: %s: not found or not open", sessionID)
	}
	return m.h.SendSessionClose(aid, sessionID)
}

// List returns recent sessions (newest first).
func (m *Manager) List(agentID string, limit int) ([]*store.Session, error) {
	if limit <= 0 {
		limit = 50
	}
	return m.st.ListSessions(agentID, limit)
}

// Get fetches one session.
func (m *Manager) Get(sessionID string) (*store.Session, error) {
	return m.st.GetSession(sessionID)
}

// Replay returns the recorded PTY chunks for a session.
func (m *Manager) Replay(sessionID string) ([]store.SessionRecord, error) {
	sess, err := m.st.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if !sess.Record {
		return nil, fmt.Errorf("sessions: %s: not recorded", sessionID)
	}
	return m.st.ListSessionRecords(sessionID)
}

// OnDisconnect interrupts all open sessions for the agent (D2: the PTY is
// killed on stream drop; the server marks it interrupted).
func (m *Manager) OnDisconnect(agentID string) {
	n, _ := m.st.InterruptAgentSessions(agentID)
	m.mu.Lock()
	for sid, info := range m.active {
		if info.agentID == agentID {
			delete(m.active, sid)
		}
	}
	m.mu.Unlock()
	if n > 0 {
		m.log.Printf("sessions: %d session(s) interrupted for agent %s", n, agentID)
		if m.sse != nil {
			m.sse.Emit("session.interrupted", map[string]string{"agent_id": agentID})
		}
	}
}

// agentFor returns the agent for an active session.
func (m *Manager) agentFor(sessionID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, ok := m.active[sessionID]
	return info.agentID, ok
}

// onSessionData handles an up PTY data chunk (SSE + optional recording).
func (m *Manager) onSessionData(agentID, sessionID string, data []byte) {
	m.mu.Lock()
	info := m.active[sessionID]
	m.mu.Unlock()
	if m.sse != nil {
		m.sse.Emit("session.data", map[string]any{
			"session_id": sessionID,
			"agent_id":   agentID,
			"data":       data,
		})
	}
	// Optional recording (PRD §9: 30 d retention, swept by Retention).
	if info.record {
		m.seqMu.Lock()
		seq := m.seq[sessionID]
		m.seq[sessionID] = seq + 1
		m.seqMu.Unlock()
		_ = m.st.AppendSessionRecord(sessionID, seq, data)
	}
}

// onSessionResult finalizes a session (exit code + state + closed ts).
func (m *Manager) onSessionResult(agentID, sessionID string, exitCode int32, state string, durationMs int64) {
	m.mu.Lock()
	delete(m.active, sessionID)
	m.mu.Unlock()
	switch state {
	case "interrupted":
		state = "interrupted"
	case "denied":
		state = "denied"
	case "succeeded", "failed":
		state = "closed"
	default:
		state = "closed"
	}
	_ = m.st.UpdateSessionState(sessionID, state, exitCode, "")
	m.audit(sessionID, agentID, state, "")
	if m.sse != nil {
		m.sse.Emit("session.result", map[string]any{
			"session_id": sessionID, "agent_id": agentID,
			"state": state, "exit_code": exitCode, "duration_ms": durationMs,
		})
	}
}

// audit records a session audit event (append-only).
func (m *Manager) audit(sessionID, agentID, state, errMsg string) {
	payload, _ := json.Marshal(map[string]any{
		"session_id": sessionID, "state": state, "error": errMsg,
	})
	_ = m.st.AppendAudit(store.AuditEvent{
		TS: now(), Kind: "session", AgentID: agentID,
		Payload: string(payload),
	})
}

// Retention purges session recordings past the retention window (PRD §9:
// 30 days). Called by the server's retention sweeper.
func (m *Manager) Retention(retentionDays int64) (int64, error) {
	cutoff := now() - retentionDays*86400
	return m.st.DeleteSessionRecordsOlderThan(cutoff)
}

func tagsFor(st *store.Store, agentID string) map[string]string {
	t, _ := st.Tags(agentID)
	return t
}

func rolesFor(st *store.Store, agentID string) []string {
	r, _ := st.Roles(agentID)
	return r
}

func joinCommandLine(cmd string, args []string) string {
	out := cmd
	for _, a := range args {
		out += " " + a
	}
	return out
}

func now() int64 { return time.Now().Unix() }
