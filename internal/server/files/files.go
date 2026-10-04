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
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/stream"
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
	// approvals is the M4 approvals engine (require_approval parking).
	approvals *approvals.Controller
	// stagingDir holds uploaded bodies while their approval request is
	// pending (0600 <opid>.part); empty = uploads fail closed on
	// require_approval (no place to hold the body).
	stagingDir string
	// requireFileRoot (PARTOUT_REQUIRE_FILE_ROOT, default false): refuse
	// file ops to agents without a file_root fact (legacy, pre file-root).
	requireFileRoot bool
	// opTimeout bounds one synchronous file op over the stream.
	opTimeout time.Duration
}

// ErrLegacyFileSurface is returned when PARTOUT_REQUIRE_FILE_ROOT is set and
// the target agent reports no file root.
var ErrLegacyFileSurface = errors.New("files: agent has no file root (legacy agent, pre file-root) — upgrade the agent or set PARTOUT_REQUIRE_FILE_ROOT=false")

// New builds a Controller.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{
		st:              st,
		h:               h,
		sse:             sseB,
		log:             lg,
		opTimeout:       30 * time.Second,
		requireFileRoot: os.Getenv("PARTOUT_REQUIRE_FILE_ROOT") == "true",
	}
}

// SetIdentity installs the server's Ed25519 signing key (signs Decisions on
// write ops so the agent guardrail can verify them).
func (c *Controller) SetIdentity(ident *certutil.ServerIdentity) { c.ident = ident }

// SetApprovals installs the M4 approvals engine (require_approval parking).
func (c *Controller) SetApprovals(ac *approvals.Controller) { c.approvals = ac }

// SetStagingDir installs the directory where parked upload bodies are held
// until their approval is decided.
func (c *Controller) SetStagingDir(dir string) { c.stagingDir = dir }

// ApprovalRequiredError is returned when a file op is parked on an approval
// request (M4). The API layer maps it to 202 with the request id.
type ApprovalRequiredError struct {
	ApprovalID string
}

func (e *ApprovalRequiredError) Error() string {
	return "files: approval required (" + e.ApprovalID + ")"
}

// approvalHold is the internal policyGate signal that a write op matched a
// require_approval rule (and the approvals engine is wired): the caller
// parks the exact payload and returns an ApprovalRequiredError.
type approvalHold struct {
	class    string
	decision policy.Decision
}

func (a *approvalHold) Error() string { return "files: " + a.class + " requires approval" }

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
		var hold *approvalHold
		if errors.As(err, &hold) {
			// Park: stage the body (the approved re-dispatch replays it) and
			// create the approval request for the exact payload.
			stage, serr := c.stageBody(id.New("fstage"), r)
			if serr != nil {
				return "", serr
			}
			return "", c.park(agentID, "upload", hold, beginOp, actor,
				map[string]any{"staged": stage, "total_size": size})
		}
		return "", err
	}
	beginRes, err := c.doSend(ctx, agentID, beginOp)
	if err != nil {
		c.audit(agentID, "file", "upload", path, beginOp.OpId, actor, "error", 0, 0, "", err.Error())
		return "", err
	}
	if beginRes.Code != 0 {
		// Field feedback F19: the begin failure used to be ignored and the
		// chunk loop then ran with an empty temp path ("not an upload temp
		// file: .").
		c.audit(agentID, fileAuditKind(beginRes.Code), "upload", path, beginOp.OpId, actor, opStateForCode(beginRes.Code), 0, 0, "", beginRes.Error)
		return "", fmt.Errorf("files: upload begin: %s (code %d)", beginRes.Error, beginRes.Code)
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
				c.audit(agentID, "file", "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", err.Error())
				return "", err
			}
			if chunkRes.Code != 0 {
				c.audit(agentID, fileAuditKind(chunkRes.Code), "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", chunkRes.Error)
				return "", fmt.Errorf("files: upload chunk: %s (code %d)", chunkRes.Error, chunkRes.Code)
			}
			offset += uint64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			c.audit(agentID, "file", "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", rerr.Error())
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
		c.audit(agentID, "file", "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", err.Error())
		return "", err
	}
	if commitRes.Code != 0 {
		c.audit(agentID, fileAuditKind(commitRes.Code), "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", commitRes.Error)
		return "", fmt.Errorf("files: upload commit: %s (code %d)", commitRes.Error, commitRes.Code)
	}
	committed = true
	c.audit(agentID, fileAuditKind(commitRes.Code), "upload", path, beginOp.OpId, actor, "ok", int64(offset), 0, commitRes.NewSha256, "")
	return commitRes.NewSha256, nil
}

// Edit performs a compare-and-swap rewrite (PRD §5.3).
func (c *Controller) Edit(ctx context.Context, agentID, path, expectedSHA string, content []byte, actor Actor) (string, error) {
	op := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_EDIT_CAS,
		Path: path, ExpectedSha256: expectedSHA, Data: content,
	}
	if err := c.policyGate(ctx, agentID, op, actor, "edit"); err != nil {
		var hold *approvalHold
		if errors.As(err, &hold) {
			stage, serr := c.stageBody(id.New("fstage"), bytes.NewReader(content))
			if serr != nil {
				return "", serr
			}
			return "", c.park(agentID, "edit", hold, op, actor,
				map[string]any{"staged": stage, "size": len(content)})
		}
		return "", err
	}
	res, err := c.doSend(ctx, agentID, op)
	if err != nil {
		c.audit(agentID, "file", "edit", path, op.OpId, actor, "error", int64(len(content)), 0, "", err.Error())
		return "", err
	}
	state := "ok"
	if res.Code != 0 {
		state = opStateForCode(res.Code)
		c.audit(agentID, fileAuditKind(res.Code), "edit", path, op.OpId, actor, state, int64(len(content)), 0, "", res.Error)
		if res.Code == 409 {
			return "", ErrConflict
		}
		return "", fmt.Errorf("files: edit: %s (code %d)", res.Error, res.Code)
	}
	c.audit(agentID, fileAuditKind(res.Code), "edit", path, op.OpId, actor, state, int64(len(content)), 0, res.NewSha256, "")
	return res.NewSha256, nil
}

// SetPerm changes mode and/or owner/group (PRD §5.3: own audit entry).
func (c *Controller) SetPerm(ctx context.Context, agentID, path, mode, owner, group string, actor Actor) error {
	op := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_SET_PERM,
		Path: path, Mode: mode, User: owner, Group: group,
	}
	if err := c.policyGate(ctx, agentID, op, actor, "perm"); err != nil {
		var hold *approvalHold
		if errors.As(err, &hold) {
			return c.park(agentID, "perm", hold, op, actor, nil)
		}
		return err
	}
	res, err := c.doSend(ctx, agentID, op)
	if err != nil {
		c.audit(agentID, "file", "perm", path, op.OpId, actor, "error", 0, 0, "", err.Error())
		return err
	}
	state := "ok"
	if res.Code != 0 {
		state = opStateForCode(res.Code)
		c.audit(agentID, fileAuditKind(res.Code), "perm", path, op.OpId, actor, state, 0, 0, "", res.Error)
		return fmt.Errorf("files: perm: %s (code %d)", res.Error, res.Code)
	}
	c.audit(agentID, "file", "perm", path, op.OpId, actor, state, 0, 0, "", "")
	return nil
}

// ErrConflict is returned by Edit on a CAS mismatch (409).
var ErrConflict = fmt.Errorf("files: checksum mismatch (file changed)")

// ---- internals -------------------------------------------------------------

// doSend dispatches one FileOp and waits for its result (no policy/audit:
// callers do that at the right granularity).
func (c *Controller) doSend(ctx context.Context, agentID string, op *pb.FileOp) (*pb.FileOpResult, error) {
	// File-root gate (docs/spec-file-root.md): when enabled, file ops to an
	// agent that reports no file root (pre-file-root / legacy agent) are
	// refused — the server would be forwarding absolute-path semantics it
	// can no longer reason about. A 0.9.5+ agent that cannot prepare its
	// root reports partout.file_root_error: surface the real reason and
	// remedy instead of the legacy "upgrade the agent" advice.
	if c.requireFileRoot {
		fl, err := c.st.LatestFacts(agentID)
		if err != nil || fl.Data["partout.file_root"] == "" {
			if err == nil && fl.Data["partout.file_root_error"] != "" {
				return nil, fmt.Errorf("files: agent file root unavailable (%s) — the file surface is disabled (fail closed); create the root on the host and restart the agent, or set PARTOUT_FILE_ROOT", fl.Data["partout.file_root_error"])
			}
			return nil, ErrLegacyFileSurface
		}
	}
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
	// op.Kind is a proto enum: string(op.Kind) renders the raw number as a
	// rune (the field saw "\u0001" in a download error) — use its name.
	opKind := op.Kind.String()
	res, err := c.doSend(ctx, agentID, op)
	if err != nil {
		c.audit(agentID, "file", opKind, op.Path, op.OpId, actor, "error", 0, 0, "", err.Error())
		return nil, err
	}
	state := "ok"
	if res.Code != 0 {
		state = opStateForCode(res.Code)
		c.audit(agentID, fileAuditKind(res.Code), opKind, op.Path, op.OpId, actor, state, 0, 0, "", res.Error)
		return res, fmt.Errorf("files: %s: %s (code %d)", opKind, res.Error, res.Code)
	}
	c.audit(agentID, "file", opKind, op.Path, op.OpId, actor, state, 0, 0, "", "")
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
	switch decision.Effect {
	case policy.EffectAllow:
		// Sign the decision (agent guardrail verifies; arch §5.3).
		if c.ident != nil {
			dec := c.signDecision(op.OpId, decision, actor.Role)
			op.Decision = dec
		}
		return nil
	case policy.EffectRequireApproval:
		if c.approvals == nil {
			// Fail closed without the approvals engine.
			c.audit(agentID, "file", opName, op.Path, op.OpId, actor, "denied", 0, 0, "", decision.Reason)
			return fmt.Errorf("files: %s requires approval but the approvals engine is not wired; failing closed", opName)
		}
		return &approvalHold{class: class, decision: decision}
	default:
		c.audit(agentID, "file", opName, op.Path, op.OpId, actor, "denied", 0, 0, "", decision.Reason)
		return fmt.Errorf("files: %s denied by policy: %s", opName, decision.Reason)
	}
}

// stageBody copies r into the staging dir (0600) and returns the path.
// require_approval parking is fail-closed without a staging dir (no place
// to hold the body until an admin decides).
func (c *Controller) stageBody(prefix string, r io.Reader) (string, error) {
	if c.stagingDir == "" {
		return "", fmt.Errorf("files: require_approval matched but no staging dir is configured; failing closed")
	}
	if err := os.MkdirAll(c.stagingDir, 0o700); err != nil {
		return "", fmt.Errorf("files: staging dir: %w", err)
	}
	p := filepath.Join(c.stagingDir, prefix+".part")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("files: stage: %w", err)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(p)
		return "", fmt.Errorf("files: stage: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return "", fmt.Errorf("files: stage: %w", err)
	}
	return p, nil
}

// park creates the approval request for a held write op and returns the
// error the API maps to 202 {approval_required}.
func (c *Controller) park(agentID, opName string, hold *approvalHold, op *pb.FileOp, actor Actor, extra map[string]any) *ApprovalRequiredError {
	payload := map[string]any{
		"op":   opName,
		"path": op.Path,
		"kind": int32(op.Kind),
	}
	if op.Mode != "" {
		payload["mode"] = op.Mode
	}
	if op.ExpectedSha256 != "" {
		payload["expected_sha256"] = op.ExpectedSha256
	}
	if op.User != "" {
		payload["owner"] = op.User
	}
	if op.Group != "" {
		payload["group"] = op.Group
	}
	for k, v := range extra {
		payload[k] = v
	}
	req, err := c.approvals.NewRequest(approvals.NewRequestParams{
		ActionClass:  hold.class,
		AgentID:      agentID,
		Actor:        actor.Principal,
		ActorRole:    actor.Role,
		MatchedRules: hold.decision.MatchedRules,
		Payload:      payload,
	})
	if err != nil {
		c.log.Printf("files: approval request %s: %v", opName, err)
		return &ApprovalRequiredError{ApprovalID: "error"}
	}
	return &ApprovalRequiredError{ApprovalID: req.ID}
}

// DispatchApprovedFileOp re-dispatches a stored file op after its approval
// was granted (registered as the approvals dispatcher for file.write and
// file.perm). The signed decision (bound to the approval id) rides the op
// down; the agent guardrail's approval path honors it. Staged bodies are
// consumed and removed.
func (c *Controller) DispatchApprovedFileOp(ctx context.Context, req *store.ApprovalRequest, dec *pb.Decision) error {
	var p struct {
		Op          string `json:"op"`
		Path        string `json:"path"`
		Mode        string `json:"mode"`
		ExpectedSHA string `json:"expected_sha256"`
		Owner       string `json:"owner"`
		Group       string `json:"group"`
		Staged      string `json:"staged"`
	}
	if err := json.Unmarshal([]byte(req.PayloadJSON), &p); err != nil {
		return fmt.Errorf("files: approval %s: bad payload: %w", req.ID, err)
	}
	actor := Actor{Principal: req.Actor, Role: req.ActorRole}
	defer func() {
		if p.Staged != "" {
			os.Remove(p.Staged) // consume the staged body either way
		}
	}()
	switch p.Op {
	case "upload":
		data, err := os.ReadFile(p.Staged)
		if err != nil {
			return fmt.Errorf("files: approval %s: staged body: %w", req.ID, err)
		}
		sha, err := c.uploadFromBytes(ctx, req.AgentID, p.Path, data, p.Mode, dec, actor)
		if err != nil {
			return err
		}
		c.audit(req.AgentID, "file", "upload", p.Path, dec.RunId, actor, "ok", int64(len(data)), 0, sha, "approval:"+req.ID)
		return nil
	case "edit":
		data, err := os.ReadFile(p.Staged)
		if err != nil {
			return fmt.Errorf("files: approval %s: staged body: %w", req.ID, err)
		}
		op := &pb.FileOp{
			OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_EDIT_CAS,
			Path: p.Path, ExpectedSha256: p.ExpectedSHA, Data: data,
			Decision: dec,
		}
		res, err := c.doSend(ctx, req.AgentID, op)
		if err != nil {
			c.audit(req.AgentID, "file", "edit", p.Path, op.OpId, actor, "error", int64(len(data)), 0, "", err.Error())
			return err
		}
		if res.Code != 0 {
			state := opStateForCode(res.Code)
			c.audit(req.AgentID, fileAuditKind(res.Code), "edit", p.Path, op.OpId, actor, state, int64(len(data)), 0, "", res.Error)
			if res.Code == 409 {
				return ErrConflict
			}
			return fmt.Errorf("files: edit: %s (code %d)", res.Error, res.Code)
		}
		c.audit(req.AgentID, fileAuditKind(res.Code), "edit", p.Path, op.OpId, actor, "ok", int64(len(data)), 0, res.NewSha256, "approval:"+req.ID)
		return nil
	case "perm":
		op := &pb.FileOp{
			OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_SET_PERM,
			Path: p.Path, Mode: p.Mode, User: p.Owner, Group: p.Group,
			Decision: dec,
		}
		res, err := c.doSend(ctx, req.AgentID, op)
		if err != nil {
			c.audit(req.AgentID, "file", "perm", p.Path, op.OpId, actor, "error", 0, 0, "", err.Error())
			return err
		}
		if res.Code != 0 {
			state := opStateForCode(res.Code)
			c.audit(req.AgentID, fileAuditKind(res.Code), "perm", p.Path, op.OpId, actor, state, 0, 0, "", res.Error)
			return fmt.Errorf("files: perm: %s (code %d)", res.Error, res.Code)
		}
		c.audit(req.AgentID, "file", "perm", p.Path, op.OpId, actor, "ok", 0, 0, "", "approval:"+req.ID)
		return nil
	default:
		return fmt.Errorf("files: approval %s: unknown op %q", req.ID, p.Op)
	}
}

// uploadFromBytes replays the begin/chunks/commit sequence for a staged
// upload body (used by the approval re-dispatch). dec rides the begin op.
func (c *Controller) uploadFromBytes(ctx context.Context, agentID, path string, data []byte, mode string, dec *pb.Decision, actor Actor) (string, error) {
	const chunk = 256 << 10
	beginOp := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_UPLOAD_BEGIN,
		Path: path, TotalSize: int64(len(data)), Mode: mode,
		Decision: dec,
	}
	beginRes, err := c.doSend(ctx, agentID, beginOp)
	if err != nil {
		c.audit(agentID, "file", "upload", path, beginOp.OpId, actor, "error", 0, 0, "", err.Error())
		return "", err
	}
	temp := beginRes.TempPath
	committed := false
	defer func() {
		if !committed {
			_ = c.abort(ctx, agentID, path, temp, actor, "upload")
		}
	}()
	offset := 0
	for offset < len(data) {
		n := chunk
		if len(data)-offset < n {
			n = len(data) - offset
		}
		chunkOp := &pb.FileOp{
			OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK,
			Path: path, TempPath: temp, Offset: uint64(offset), Data: data[offset : offset+n],
		}
		chunkRes, err := c.doSend(ctx, agentID, chunkOp)
		if err != nil {
			c.audit(agentID, "file", "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", err.Error())
			return "", err
		}
		if chunkRes.Code != 0 {
			c.audit(agentID, fileAuditKind(chunkRes.Code), "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", chunkRes.Error)
			return "", fmt.Errorf("files: upload chunk: %s (code %d)", chunkRes.Error, chunkRes.Code)
		}
		offset += n
	}
	commitOp := &pb.FileOp{
		OpId: id.New("fop"), Kind: pb.FileOpKind_FILE_OP_UPLOAD_COMMIT,
		Path: path, TempPath: temp, TotalSize: int64(offset), Mode: mode,
	}
	commitRes, err := c.doSend(ctx, agentID, commitOp)
	if err != nil {
		c.audit(agentID, "file", "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", err.Error())
		return "", err
	}
	if commitRes.Code != 0 {
		c.audit(agentID, fileAuditKind(commitRes.Code), "upload", path, beginOp.OpId, actor, "error", int64(offset), 0, "", commitRes.Error)
		return "", fmt.Errorf("files: upload commit: %s (code %d)", commitRes.Error, commitRes.Code)
	}
	committed = true
	return commitRes.NewSha256, nil
}

func (c *Controller) signDecision(opID string, d policy.Decision, actorRole string) *pb.Decision {
	version, _ := c.st.PolicyBundleVersion()
	sig := []byte(nil)
	if c.ident != nil {
		sig = policy.SignDecision(c.ident.Priv, opID, version, d.Effect, d.MatchedRules, actorRole, "")
	}
	return &pb.Decision{
		RunId:         opID,
		BundleVersion: version,
		Effect:        d.Effect,
		MatchedRules:  d.MatchedRules,
		Sig:           sig,
		ActorRole:     actorRole,
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
// fileAuditKind returns the audit event kind for an agent result code: a
// 403 (path escapes the file root) is recorded as file.path_escape
// (docs/spec-file-root.md); everything else is a plain file action. Policy
// denials (pre-dispatch) stay kind "file" with state "denied".
func fileAuditKind(code int32) string {
	if code == 403 {
		return "file.path_escape"
	}
	return "file"
}

func (c *Controller) audit(agentID, kind, opName, path, opID string, actor Actor, state string, size int64, _ int32, sha, errMsg string) {
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
		"op":     opName,
		"path":   path,
		"op_id":  opID,
		"state":  state,
		"size":   size,
		"sha256": sha,
		"error":  errMsg,
	})
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: kind, Actor: actor.Principal,
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
