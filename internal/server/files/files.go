// Package files implements the server-side file operations (M2, PRD §5.3,
// arch A6): synchronous request/response over the agent stream,
// policy-gated for write ops (D1: reads bypass policy), audited in
// files_actions + audit_events, and emitted as file.action SSE events.
//
// The controller is the REST layer's entry point: it builds the FileOp
// (with a signed Decision for write ops), sends it down, waits for the
// FileOpResult, records the audit row, and returns the result.
package files

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	"github.com/blawesom/partout/internal/server/stream"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// Controller dispatches file operations to agents.
type Controller struct {
	st    *store.Store
	h     *stream.Handler
	sse   *sse.Broker
	log   *log.Logger
	ident *certutil.ServerIdentity
	// opTimeout bounds one synchronous file op over the stream.
	opTimeout time.Duration
}

// New builds a Controller.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{st: st, h: h, sse: sseB, log: lg, opTimeout: 30 * time.Second}
}

// SetIdentity installs the server's Ed25519 signing key (signs Decisions on
// write ops so the agent guardrail can verify them).
func (c *Controller) SetIdentity(ident *certutil.ServerIdentity) { c.ident = ident }

// Actor carries the requester identity for audit + policy.
type Actor struct {
	Principal string // who (token name / user)
	Role      string // viewer|operator|admin
}

// Stat returns file metadata (PRD §5.3).
func (c *Controller) Stat(ctx context.Context, agentID, path string, actor Actor) (*pb.FileStat, error) {
	op := &pb.FileOp{OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_STAT, Path: path}
	res, err := c.do(ctx, agentID, op, actor)
	if err != nil {
		return nil, err
	}
	return res.Stat, nil
}

// List returns a directory listing (file browser).
func (c *Controller) List(ctx context.Context, agentID, path string, actor Actor) ([]*pb.FileEntry, bool, error) {
	op := &pb.FileOp{OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_LIST, Path: path}
	res, err := c.do(ctx, agentID, op, actor)
	if err != nil {
		return nil, false, err
	}
	return res.Entries, res.Truncated, nil
}

// Download streams a file to w, chunk by chunk (resumable within the call).
func (c *Controller) Download(ctx context.Context, agentID, path string, w io.Writer, actor Actor) (int64, error) {
	var offset uint64
	var size int64
	for {
		op := &pb.FileOp{
			OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_DOWNLOAD,
			Path: path, Offset: offset,
		}
		res, err := c.do(ctx, agentID, op, actor)
		if err != nil {
			return 0, err
		}
		if len(res.Data) > 0 {
			if _, err := w.Write(res.Data); err != nil {
				return 0, fmt.Errorf("files: write: %w", err)
			}
		}
		offset += uint64(len(res.Data))
		if res.Done {
			size = int64(offset)
			break
		}
	}
	return size, nil
}

// Upload sends r to path atomically (begin → chunks → commit). On failure it
// aborts the temp file and returns an error. Returns the committed sha256.
func (c *Controller) Upload(ctx context.Context, agentID, path string, r io.Reader, size int64, mode string, actor Actor) (string, error) {
	const chunk = 256 << 10 // 256 KiB per chunk (D3)
	// 1. Begin (policy-gated: file.write).
	beginOp := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_UPLOAD_BEGIN,
		Path: path, TotalSize: size, Mode: mode,
	}
	if err := c.policyGate(ctx, agentID, beginOp, actor, "upload"); err != nil {
		return "", err
	}
	beginRes, err := c.doSend(ctx, agentID, beginOp)
	if err != nil {
		c.audit(agentID, "upload", path, beginOp.OpId, actor, "error", 0, 0, "", err.Error())
		return "", err
	}
	temp := beginRes.TempPath
	committed := false
	defer func() {
		if !committed {
			_ = c.abort(ctx, agentID, path, temp, actor, "upload")
		}
	}()

	// 2. Chunks.
	var offset uint64
	buf := make([]byte, chunk)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			chunkOp := &pb.FileOp{
				OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK,
				Path: path, TempPath: temp, Offset: offset, Data: buf[:n],
			}
			chunkRes, err := c.doSend(ctx, agentID, chunkOp)
			if err != nil {
				c.audit(agentID, "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", err.Error())
				return "", err
			}
			if chunkRes.Code != 0 {
				c.audit(agentID, "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", chunkRes.Error)
				return "", fmt.Errorf("files: upload chunk: %s (code %d)", chunkRes.Error, chunkRes.Code)
			}
			offset += uint64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			c.audit(agentID, "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", rerr.Error())
			return "", fmt.Errorf("files: read upload: %w", rerr)
		}
	}

	// 3. Commit (atomic temp → path on the agent).
	commitOp := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_UPLOAD_COMMIT,
		Path: path, TempPath: temp, TotalSize: int64(offset), Mode: mode,
	}
	commitRes, err := c.doSend(ctx, agentID, commitOp)
	if err != nil {
		c.audit(agentID, "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", err.Error())
		return "", err
	}
	if commitRes.Code != 0 {
		c.audit(agentID, "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", commitRes.Error)
		return "", fmt.Errorf("files: upload commit: %s (code %d)", commitRes.Error, commitRes.Code)
	}
	committed = true
	c.audit(agentID, "upload", path, beginOp.OpId, actor, "ok", int64(offset), 0, commitRes.NewSha256, "")
	return commitRes.NewSha256, nil
}

// Edit performs a compare-and-swap rewrite (PRD §5.3).
func (c *Controller) Edit(ctx context.Context, agentID, path, expectedSHA string, content []byte, actor Actor) (string, error) {
	op := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_EDIT_CAS,
		Path: path, ExpectedSha256: expectedSHA, Data: content,
	}
	if err := c.policyGate(ctx, agentID, op, actor, "edit"); err != nil {
		return "", err
	}
	res, err := c.doSend(ctx, agentID, op)
	if err != nil {
		c.audit(agentID, "edit", path, op.OpId, actor, "error", int64(len(content)), 0, "", err.Error())
		return "", err
	}
	state := "ok"
	if res.Code != 0 {
		state = opStateForCode(res.Code)
		c.audit(agentID, "edit", path, op.OpId, actor, state, int64(len(content)), 0, "", res.Error)
		if res.Code == 409 {
			return "", ErrConflict
		}
		return "", fmt.Errorf("files: edit: %s (code %d)", res.Error, res.Code)
	}
	c.audit(agentID, "edit", path, op.OpId, actor, state, int64(len(content)), 0, res.NewSha256, "")
	return res.NewSha256, nil
}

// SetPerm changes mode and/or owner/group (PRD §5.3: own audit entry).
func (c *Controller) SetPerm(ctx context.Context, agentID, path, mode, owner, group string, actor Actor) error {
	op := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_SET_PERM,
		Path: path, Mode: mode, User: owner, Group: group,
	}
	if err := c.policyGate(ctx, agentID, op, actor, "perm"); err != nil {
		return err
	}
	res, err := c.doSend(ctx, agentID, op)
	if err != nil {
		c.audit(agentID, "perm", path, op.OpId, actor, "error", 0, 0, "", err.Error())
		return err
	}
	state := "ok"
	if res.Code != 0 {
		state = opStateForCode(res.Code)
		c.audit(agentID, "perm", path, op.OpId, actor, state, 0, 0, "", res.Error)
		return fmt.Errorf("files: perm: %s (code %d)", res.Error, res.Code)
	}
	c.audit(agentID, "perm", path, op.OpId, actor, state, 0, 0, "", "")
	return nil
}

// ErrConflict is returned by Edit on a CAS mismatch (409).
var ErrConflict = fmt.Errorf("files: checksum mismatch (file changed)")

// ---- internals -------------------------------------------------------------

// doSend dispatches one FileOp and waits for its result (no policy/audit:
// callers do that at the right granularity).
func (c *Controller) doSend(ctx context.Context, agentID string, op *pb.FileOp) (*pb.FileOpResult, error) {
	if err := c.h.SendFileOp(agentID, op); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, c.opTimeout)
	defer cancel()
	res, err := c.h.WaitFileResult(opCtx, op.OpId)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 && res.Code != 409 {
		// Non-conflict agent errors are surfaced here; callers that need the
		// raw code (Edit → 409) handle it themselves.
		return res, nil
	}
	return res, nil
}

// do is the read-path helper: dispatch + result + audit.
func (c *Controller) do(ctx context.Context, agentID string, op *pb.FileOp, actor Actor) (*pb.FileOpResult, error) {
	opKind := string(op.Kind)
	res, err := c.doSend(ctx, agentID, op)
	if err != nil {
		c.audit(agentID, opKind, op.Path, op.OpId, actor, "error", 0, 0, "", err.Error())
		return nil, err
	}
	state := "ok"
	if res.Code != 0 {
		state = opStateForCode(res.Code)
		c.audit(agentID, opKind, op.Path, op.OpId, actor, state, 0, 0, "", res.Error)
		return res, fmt.Errorf("files: %s: %s (code %d)", opKind, res.Error, res.Code)
	}
	c.audit(agentID, opKind, op.Path, op.OpId, actor, state, 0, 0, "", "")
	return res, nil
}

// policyGate evaluates policy for a write op (D1) and attaches a signed
// Decision. A deny returns an error (403); the audit row is recorded.
func (c *Controller) policyGate(ctx context.Context, agentID string, op *pb.FileOp, actor Actor, opName string) error {
	class, ok := policy.FileOpClass(op.Kind)
	if !ok {
		return fmt.Errorf("files: %s: no action class for kind %s", opName, op.Kind)
	}
	host, err := c.st.Agent(agentID)
	if err != nil {
		return fmt.Errorf("files: agent %s: %w", agentID, err)
	}
	action := policy.FileAction(class, op.Path)
	action.HostID = host.ID
	action.HostTags, _ = c.st.Tags(host.ID)
	action.HostRoles, _ = c.st.Roles(host.ID)
	action.ActorRole = actor.Role
	rules, err := c.st.GetPolicyRules()
	if err != nil {
		return fmt.Errorf("files: load policies: %w", err)
	}
	decision := policy.Evaluate(rules, action)
	if decision.Effect != policy.EffectAllow {
		c.audit(agentID, opName, op.Path, op.OpId, actor, "denied", 0, 0, "", decision.Reason)
		return fmt.Errorf("files: %s denied by policy: %s", opName, decision.Reason)
	}
	// Sign the decision (agent guardrail verifies; arch §5.3).
	if c.ident != nil {
		dec := c.signDecision(op.OpId, decision, actor.Role)
		op.Decision = dec
	}
	return nil
}

func (c *Controller) signDecision(opID string, d policy.Decision, actorRole string) *pb.Decision {
	version, _ := c.st.PolicyBundleVersion()
	sig := []byte(nil)
	if c.ident != nil {
		sig = policy.SignDecision(c.ident.Priv, opID, version, d.Effect, d.MatchedRules, actorRole)
	}
	return &pb.Decision{
		RunId:        opID,
		BundleVersion: version,
		Effect:       d.Effect,
		MatchedRules: d.MatchedRules,
		Sig:          sig,
		ActorRole:    actorRole,
	}
}

// abort best-effort removes the upload temp file after a failed upload.
func (c *Controller) abort(ctx context.Context, agentID, path, temp string, actor Actor, opName string) error {
	if temp == "" {
		return nil
	}
	op := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_UPLOAD_ABORT,
		Path: path, TempPath: temp,
	}
	res, err := c.doSend(ctx, agentID, op)
	if err != nil {
		c.log.Printf("files: abort %s: %v", temp, err)
		return err
	}
	if res.Code != 0 {
		c.log.Printf("files: abort %s: code %d: %s", temp, res.Code, res.Error)
	}
	return nil
}

// audit records a files_actions row + audit event + SSE event.
func (c *Controller) audit(agentID, opName, path, opID string, actor Actor, state string, size int64, _ int32, sha, errMsg string) {
	var sz sql.NullInt64
	if size > 0 {
		sz = sql.NullInt64{Int64: size, Valid: true}
	}
	fa := store.FileAction{
		ID:      id.New("fa"),
		AgentID: agentID,
		Op:      opName,
		OpID:    opID,
		Path:    path,
		Actor:   actor.Principal,
		State:   state,
		Size:    sz,
		SHA256:  sha,
		Error:   errMsg,
		Created: time.Now().Unix(),
	}
	// Derive a numeric code from state for the row.
	switch state {
	case "ok":
		fa.Code = 0
	case "denied":
		fa.Code = 403
	default:
		fa.Code = 500
	}
	if err := c.st.InsertFileAction(fa); err != nil {
		c.log.Printf("files: insert action %s: %v", fa.ID, err)
	}
	// Audit event (append-only, PRD §7: full-fidelity audit).
	payload, _ := json.Marshal(map[string]any{
		"op":      opName,
		"path":    path,
		"op_id":   opID,
		"state":   state,
		"size":    size,
		"sha256":  sha,
		"error":   errMsg,
	})
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: "file", Actor: actor.Principal,
		AgentID: agentID, Payload: string(payload),
	})
	// SSE.
	if c.sse != nil {
		c.sse.Emit("file.action", map[string]any{
			"agent_id": agentID, "op": opName, "path": path,
			"state": state, "actor": actor.Principal,
		})
	}
}

func opStateForCode(code int32) string {
	switch code {
	case 0:
		return "ok"
	case 403:
		return "denied"
	default:
		return "error"
	}
}