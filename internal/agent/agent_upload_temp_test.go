package agent_test

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/blawesom/partout/internal/agent"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestAgentRejectsForgedUploadTempPath: FILE_OP_UPLOAD_CHUNK/ABORT/COMMIT
// whose TempPath was not created by this agent's UPLOAD_BEGIN must be refused
// (403) — the wire-supplied TempPath is an absolute path, and without the
// agent-side binding a malicious server could steer chunk writes anywhere the
// agent user can write. A real BEGIN → CHUNK → COMMIT flow must still work.
func TestAgentRejectsForgedUploadTempPath(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sseB := sse.New()
	h, _ := newTestServer(t, st, sseB, log.New(io.Discard, "srv: ", 0), nil)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_up", UUID: id.UUID,
		ED25519Pub: id.Ed25519PubB64(), X25519Pub: id.X25519PubB64(),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	dataDir := t.TempDir()
	agentCfg := &config.Config{
		Mode:          "agent",
		ServerURL:     lis.Addr().String(),
		DataDir:       dataDir,
		FactsInterval: 3600,
		Elevate:       "none",
		Root:          "/",
		FileRoot:      filepath.Join(dataDir, "files"),
	}
	ag := agent.New(id, agentCfg, log.New(io.Discard, "agent: ", 0))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- ag.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
		}
	})

	waitFor := func(ok func() bool, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitFor(func() bool { return h.AgentSession("ag_up") != nil }, "agent connect")
	waitFor(ag.GuardLoaded, "policy bundle")

	sendOp := func(op *pb.FileOp) *pb.FileOpResult {
		t.Helper()
		if err := h.SendFileOp("ag_up", op); err != nil {
			t.Fatalf("SendFileOp: %v", err)
		}
		res, err := h.WaitFileResult(ctx, op.OpId)
		if err != nil {
			t.Fatalf("WaitFileResult %s: %v", op.OpId, err)
		}
		return res
	}

	// 1. Forged CHUNK with an absolute temp path never begun → 403.
	res := sendOp(&pb.FileOp{OpId: "forged1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK,
		TempPath: filepath.Join(dataDir, "evil.partout-tmp-aaaa"), Offset: 0, Data: []byte("x")})
	if res.Code != 403 {
		t.Fatalf("forged chunk code = %d (%s), want 403", res.Code, res.Error)
	}

	// 2. Forged ABORT → 403.
	res = sendOp(&pb.FileOp{OpId: "forged2", Kind: pb.FileOpKind_FILE_OP_UPLOAD_ABORT,
		TempPath: filepath.Join(dataDir, "evil.partout-tmp-bbbb")})
	if res.Code != 403 {
		t.Fatalf("forged abort code = %d (%s), want 403", res.Code, res.Error)
	}

	// 3. Real BEGIN → CHUNK → COMMIT still works end to end.
	begin := sendOp(&pb.FileOp{OpId: "begin1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_BEGIN, Path: "ok.txt", TotalSize: 3})
	if begin.Code != 0 || begin.TempPath == "" {
		t.Fatalf("begin code = %d (%s)", begin.Code, begin.Error)
	}
	chunk := sendOp(&pb.FileOp{OpId: "chunk1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK,
		TempPath: begin.TempPath, Offset: 0, Data: []byte("abc")})
	if chunk.Code != 0 || chunk.Received != 3 {
		t.Fatalf("chunk code = %d received=%d (%s), want 0/3", chunk.Code, chunk.Received, chunk.Error)
	}
	commit := sendOp(&pb.FileOp{OpId: "commit1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_COMMIT,
		TempPath: begin.TempPath, Path: "ok.txt", TotalSize: 3})
	if commit.Code != 0 || commit.NewSha256 == "" {
		t.Fatalf("commit code = %d (%s)", commit.Code, commit.Error)
	}

	// 4. After COMMIT, the temp path is forgotten: a replayed COMMIT → 403.
	res = sendOp(&pb.FileOp{OpId: "commit2", Kind: pb.FileOpKind_FILE_OP_UPLOAD_COMMIT,
		TempPath: begin.TempPath, Path: "ok.txt", TotalSize: 3})
	if res.Code != 403 {
		t.Fatalf("replayed commit code = %d (%s), want 403", res.Code, res.Error)
	}
}

// uploadRig bundles the server+agent setup shared by the upload tests.
type uploadRig struct {
	h     *stream.Handler
	st    *store.Store
	lis   net.Listener
	gs    *grpc.Server
	addr  string
	ctx   context.Context
	agent *agent.Agent
}

func startUploadRig(t *testing.T, agentID string) *uploadRig {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sseB := sse.New()
	h, _ := newTestServer(t, st, sseB, log.New(io.Discard, "srv: ", 0), nil)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: agentID, UUID: id.UUID,
		ED25519Pub: id.Ed25519PubB64(), X25519Pub: id.X25519PubB64(),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	dataDir := t.TempDir()
	cfg := &config.Config{
		Mode:          "agent",
		ServerURL:     lis.Addr().String(),
		DataDir:       dataDir,
		FactsInterval: 3600,
		Elevate:       "none",
		Root:          "/",
		FileRoot:      filepath.Join(dataDir, "files"),
	}
	ag := agent.New(id, cfg, log.New(io.Discard, "agent: ", 0))
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- ag.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
		}
		gs.Stop()
		lis.Close()
	})

	rig := &uploadRig{h: h, st: st, lis: lis, gs: gs, addr: lis.Addr().String(), ctx: ctx, agent: ag}
	rig.waitFor(t, func() bool { return h.AgentSession(agentID) != nil }, "agent connect")
	rig.waitFor(t, ag.GuardLoaded, "policy bundle")
	return rig
}

func (r *uploadRig) waitFor(t *testing.T, ok func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *uploadRig) sendOp(t *testing.T, agentID string, op *pb.FileOp) *pb.FileOpResult {
	t.Helper()
	if err := r.h.SendFileOp(agentID, op); err != nil {
		t.Fatalf("SendFileOp: %v", err)
	}
	res, err := r.h.WaitFileResult(r.ctx, op.OpId)
	if err != nil {
		t.Fatalf("WaitFileResult %s: %v", op.OpId, err)
	}
	return res
}

// TestAgentFailedCommitThenCleanup (council F1): a COMMIT that fails on the
// size check consumes the temp (fs.UploadCommit removes it) — the agent must
// then drop the registration (temp confirmed gone) rather than 403-ing
// forever while believing a file exists, and a fresh upload must still work.
func TestAgentFailedCommitThenCleanup(t *testing.T) {
	rig := startUploadRig(t, "ag_f1")

	begin := rig.sendOp(t, "ag_f1", &pb.FileOp{OpId: "b1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_BEGIN, Path: "f.txt", TotalSize: 3})
	if begin.Code != 0 {
		t.Fatalf("begin: %d %s", begin.Code, begin.Error)
	}
	temp := begin.TempPath
	chunk := rig.sendOp(t, "ag_f1", &pb.FileOp{OpId: "c1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK, TempPath: temp, Offset: 0, Data: []byte("abc")})
	if chunk.Code != 0 {
		t.Fatalf("chunk: %d %s", chunk.Code, chunk.Error)
	}
	// Wrong expected size → commit fails; fs removes the temp.
	bad := rig.sendOp(t, "ag_f1", &pb.FileOp{OpId: "m1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_COMMIT, TempPath: temp, Path: "f.txt", TotalSize: 99})
	if bad.Code == 0 {
		t.Fatal("commit with wrong size must fail")
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temp should be consumed by the failed commit, stat err = %v", err)
	}
	// Registration was dropped because the temp is gone → further ops 403.
	res := rig.sendOp(t, "ag_f1", &pb.FileOp{OpId: "c2", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK, TempPath: temp, Offset: 0, Data: []byte("x")})
	if res.Code != 403 {
		t.Fatalf("chunk after consumed temp = %d, want 403", res.Code)
	}
	// Agent still healthy: fresh BEGIN → CHUNK → COMMIT works.
	b2 := rig.sendOp(t, "ag_f1", &pb.FileOp{OpId: "b2", Kind: pb.FileOpKind_FILE_OP_UPLOAD_BEGIN, Path: "g.txt", TotalSize: 3})
	c3 := rig.sendOp(t, "ag_f1", &pb.FileOp{OpId: "c3", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK, TempPath: b2.TempPath, Offset: 0, Data: []byte("xyz")})
	m2 := rig.sendOp(t, "ag_f1", &pb.FileOp{OpId: "m2", Kind: pb.FileOpKind_FILE_OP_UPLOAD_COMMIT, TempPath: b2.TempPath, Path: "g.txt", TotalSize: 3})
	if b2.Code != 0 || c3.Code != 0 || m2.Code != 0 {
		t.Fatalf("fresh upload broken: begin=%d chunk=%d commit=%d (%s)", b2.Code, c3.Code, m2.Code, m2.Error)
	}
}

// TestAgentFailedAbortRetained (council F1): when ABORT fails and the temp
// file still exists, the registration must be RETAINED so a retry can clean
// up — not 403'd into limbo.
func TestAgentFailedAbortRetained(t *testing.T) {
	rig := startUploadRig(t, "ag_f1b")

	begin := rig.sendOp(t, "ag_f1b", &pb.FileOp{OpId: "b1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_BEGIN, Path: "h.txt", TotalSize: 3})
	if begin.Code != 0 {
		t.Fatalf("begin: %d %s", begin.Code, begin.Error)
	}
	temp := begin.TempPath

	// Sabotage: replace the temp file with a non-empty directory so
	// os.Remove fails with ENOTEMPTY (not IsNotExist).
	if err := os.Remove(temp); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temp, "inner"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	ab1 := rig.sendOp(t, "ag_f1b", &pb.FileOp{OpId: "a1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_ABORT, TempPath: temp})
	if ab1.Code == 0 {
		t.Fatal("abort on a non-empty dir must fail")
	}
	// Registration retained: CHUNK passes the 403 gate (fails later at the fs
	// layer because the path is a directory — any non-403 code proves it).
	ch := rig.sendOp(t, "ag_f1b", &pb.FileOp{OpId: "c1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK, TempPath: temp, Offset: 0, Data: []byte("x")})
	if ch.Code == 403 {
		t.Fatal("registration must be retained after a failed abort (got 403)")
	}

	// Clean the sabotage and retry ABORT → succeeds, registration dropped.
	if err := os.Remove(filepath.Join(temp, "inner")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(temp); err != nil {
		t.Fatal(err)
	}
	ab2 := rig.sendOp(t, "ag_f1b", &pb.FileOp{OpId: "a2", Kind: pb.FileOpKind_FILE_OP_UPLOAD_ABORT, TempPath: temp})
	if ab2.Code != 0 {
		t.Fatalf("retried abort = %d (%s), want 0", ab2.Code, ab2.Error)
	}
	res := rig.sendOp(t, "ag_f1b", &pb.FileOp{OpId: "c2", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK, TempPath: temp, Offset: 0, Data: []byte("x")})
	if res.Code != 403 {
		t.Fatalf("chunk after successful abort = %d, want 403", res.Code)
	}
}

// TestAgentUploadStreamScopedAcrossReconnect (council F2): an upload temp
// authorized on stream N must be rejected (403) on stream N+1, and its temp
// file removed at teardown.
func TestAgentUploadStreamScopedAcrossReconnect(t *testing.T) {
	rig := startUploadRig(t, "ag_f2")

	begin := rig.sendOp(t, "ag_f2", &pb.FileOp{OpId: "b1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_BEGIN, Path: "r.txt", TotalSize: 3})
	if begin.Code != 0 {
		t.Fatalf("begin: %d %s", begin.Code, begin.Error)
	}
	temp := begin.TempPath
	oldSess := rig.h.AgentSession("ag_f2")

	// Drop the stream server-side: close the listener (fails the old server's
	// Accept so Stop can return and kills the agent's stream), stop the old
	// gRPC server, then re-listen on the SAME address and serve a fresh server
	// so the agent's reconnect loop lands on it.
	rig.lis.Close()
	rig.gs.Stop()
	var lis2 net.Listener
	var err error
	for i := 0; i < 50; i++ {
		lis2, err = net.Listen("tcp", rig.addr)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("re-listen %s: %v", rig.addr, err)
	}
	rig.lis = lis2
	gs2 := grpc.NewServer()
	rig.h.Register(gs2)
	go func() { _ = gs2.Serve(lis2) }()
	t.Cleanup(gs2.Stop)

	// Wait for a NEW session object (the agent reconnected).
	deadline := time.Now().Add(15 * time.Second)
	for {
		s := rig.h.AgentSession("ag_f2")
		if s != nil && s != oldSess {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not reconnect within 15s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The old temp path is no longer authorized on the new stream.
	res := rig.sendOp(t, "ag_f2", &pb.FileOp{OpId: "c1", Kind: pb.FileOpKind_FILE_OP_UPLOAD_CHUNK, TempPath: temp, Offset: 0, Data: []byte("x")})
	if res.Code != 403 {
		t.Fatalf("chunk with pre-reconnect temp = %d (%s), want 403", res.Code, res.Error)
	}
	// ...and teardown removed the orphaned temp file.
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("orphaned temp must be removed at stream teardown, stat err = %v", err)
	}
}
