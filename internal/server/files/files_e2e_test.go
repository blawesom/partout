package files_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	agentfs "github.com/blawesom/partout/internal/agent/fs"
	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/files"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// startFilesServer wires a stream handler + files controller on bufconn and
// runs a fake agent that executes FILE_OP envelopes with the real agent/fs
// package against a temp dir.
func startFilesServer(t *testing.T) (*store.Store, *files.Controller, *grpc.ClientConn, func()) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_files", UUID: id.UUID,
		ED25519Pub: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
		X25519Pub:  base64.StdEncoding.EncodeToString(id.X25519Pub),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	sseB := sse.New()
	lg := log.New(io.Discard, "srv: ", 0)
	h := stream.NewHandler(st, sseB, lg)
	fc := files.New(st, h, sseB, lg)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	agentClient := pb.NewAgentStreamClient(conn)
	s, err := agentClient.Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Handshake.
	env, err := s.Recv()
	if err != nil {
		t.Fatalf("Recv challenge: %v", err)
	}
	ch := env.GetChallenge()
	ts := time.Now().Unix()
	if err := s.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: id.UUID, Ts: ts, Sig: id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, ts)),
		}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}

	// Fake agent loop: handle FILE_OP down envelopes with real fs ops.
	fsys := agentfs.Config{}.Filled()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			op := down.GetFileOp()
			if op == nil {
				continue
			}
			var res *pb.FileOpResult
			res, err = fakeAgentFileOp(op, fsys)
			if err != nil {
				res = &pb.FileOpResult{OpId: op.OpId, Code: 500, Error: err.Error()}
			}
			if err := s.Send(&pb.Envelope{
				Kind:    pb.EnvelopeKind_FILE_OP_RESULT,
				CorrId:  op.OpId,
				Payload: &pb.Envelope_FileOpResult{FileOpResult: res},
			}); err != nil {
				return
			}
		}
	}()

	// Wait for the server to register the session.
	deadline := time.Now().Add(3 * time.Second)
	for h.AgentSession("ag_files") == nil {
		if time.Now().After(deadline) {
			cancel()
			conn.Close()
			st.Close()
			t.Fatal("session not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cleanup := func() {
		s.CloseSend()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		cancel()
		conn.Close()
		st.Close()
	}
	return st, fc, conn, cleanup
}

func fakeAgentFileOp(op *pb.FileOp, cfg agentfs.Config) (*pb.FileOpResult, error) {
	switch op.Kind {
	case pb.FileOpKind_FILE_OP_STAT:
		st, err := agentfs.StatPath(op.Path)
		if err != nil {
			return nil, err
		}
		return &pb.FileOpResult{
			OpId: op.OpId, Code: 0,
			Stat: &pb.FileStat{
				Size: st.Size, Mode: st.Mode, Owner: st.Owner, Group: st.Group,
				MtimeUnix: st.MtimeUnix, Sha256: st.SHA256,
				IsDir: st.IsDir, IsSymlink: st.IsSymlink,
			},
		}, nil
	case pb.FileOpKind_FILE_OP_LIST:
		entries, truncated, err := agentfs.List(op.Path, cfg)
		if err != nil {
			return nil, err
		}
		out := &pb.FileOpResult{OpId: op.OpId, Code: 0, Truncated: truncated}
		for _, e := range entries {
			out.Entries = append(out.Entries, &pb.FileEntry{
				Name: e.Name, IsDir: e.IsDir, IsSymlink: e.IsSymlink,
				Size: e.Size, MtimeUnix: e.MtimeUnix, Mode: e.Mode,
			})
		}
		return out, nil
	case pb.FileOpKind_FILE_OP_DOWNLOAD:
		data, _, done, err := agentfs.DownloadAt(op.Path, int64(op.Offset), cfg)
		if err != nil {
			return nil, err
		}
		return &pb.FileOpResult{OpId: op.OpId, Code: 0, Data: data, Done: done}, nil
	case pb.FileOpKind_FILE_OP_UPLOAD_BEGIN:
		temp, err := agentfs.UploadBegin(op.Path, op.TotalSize, cfg)
		if err != nil {
			return nil, err
		}
		return &pb.FileOpResult{OpId: op.OpId, Code: 0, TempPath: temp}, nil
	case pb.FileOpKind_FILE_OP_UPLOAD_CHUNK:
		w, err := agentfs.UploadChunk(op.TempPath, int64(op.Offset), op.Data, cfg)
		if err != nil {
			return nil, err
		}
		return &pb.FileOpResult{OpId: op.OpId, Code: 0, Received: uint64(w)}, nil
	case pb.FileOpKind_FILE_OP_UPLOAD_COMMIT:
		sha, err := agentfs.UploadCommit(op.TempPath, op.Path, op.Mode, op.TotalSize)
		if err != nil {
			return nil, err
		}
		return &pb.FileOpResult{OpId: op.OpId, Code: 0, NewSha256: sha}, nil
	case pb.FileOpKind_FILE_OP_UPLOAD_ABORT:
		return &pb.FileOpResult{OpId: op.OpId, Code: 0}, agentfs.UploadAbort(op.TempPath)
	case pb.FileOpKind_FILE_OP_EDIT_CAS:
		sha, err := agentfs.EditCAS(op.Path, op.ExpectedSha256, op.Data, cfg)
		if err != nil {
			if err == agentfs.ErrConflict {
				return &pb.FileOpResult{OpId: op.OpId, Code: 409, Error: "checksum mismatch"}, nil
			}
			return nil, err
		}
		return &pb.FileOpResult{OpId: op.OpId, Code: 0, NewSha256: sha}, nil
	case pb.FileOpKind_FILE_OP_SET_PERM:
		if err := agentfs.SetPerm(op.Path, op.Mode, op.User, op.Group); err != nil {
			return nil, err
		}
		return &pb.FileOpResult{OpId: op.OpId, Code: 0}, nil
	default:
		return nil, io.ErrUnexpectedEOF
	}
}

var actor = files.Actor{Principal: "local", Role: "local"}

func TestFilesE2E(t *testing.T) {
	st, fc, _, cleanup := startFilesServer(t)
	defer cleanup()
	ctx := context.Background()

	// Prepare a file + dir on the "agent".
	dir := t.TempDir()
	p := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(p, []byte("hello files"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Stat.
	stt, err := fc.Stat(ctx, "ag_files", p, actor)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if stt.Size != 11 {
		t.Fatalf("size=%d, want 11", stt.Size)
	}
	if stt.Sha256 == "" {
		t.Fatalf("stat sha256 empty")
	}

	// 2. List.
	entries, truncated, err := fc.List(ctx, "ag_files", dir, actor)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if truncated {
		t.Fatal("unexpected truncation")
	}
	found := false
	for _, e := range entries {
		if e.Name == "hello.txt" && e.Size == 11 {
			found = true
		}
	}
	if !found {
		t.Fatalf("hello.txt not in listing: %+v", entries)
	}

	// 3. Download.
	var buf bytes.Buffer
	n, err := fc.Download(ctx, "ag_files", p, &buf, actor)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if n != 11 || buf.String() != "hello files" {
		t.Fatalf("download=%d %q", n, buf.String())
	}

	// 4. Upload.
	up := filepath.Join(dir, "up.bin")
	sha, err := fc.Upload(ctx, "ag_files", up, bytes.NewReader([]byte("upload-body")), 11, "0644", actor)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if len(sha) != 64 {
		t.Fatalf("bad sha %q", sha)
	}
	got, err := os.ReadFile(up)
	if err != nil || string(got) != "upload-body" {
		t.Fatalf("uploaded content wrong: %q err=%v", got, err)
	}

	// 5. Edit (CAS).
	up2 := filepath.Join(dir, "edit.txt")
	os.WriteFile(up2, []byte("v1"), 0o644)
	cur, _ := fc.Stat(ctx, "ag_files", up2, actor)
	sha2, err := fc.Edit(ctx, "ag_files", up2, cur.Sha256, []byte("v2"), actor)
	if err != nil {
		t.Fatalf("Edit: %v", err)
	}
	_ = sha2
	got2, _ := os.ReadFile(up2)
	if string(got2) != "v2" {
		t.Fatalf("edit content=%q, want v2", got2)
	}

	// 6. Edit CAS conflict → ErrConflict.
	if _, err := fc.Edit(ctx, "ag_files", up2, cur.Sha256, []byte("v3"), actor); err != files.ErrConflict {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	// 7. Perm.
	if err := fc.SetPerm(ctx, "ag_files", up2, "0600", "", "", actor); err != nil {
		t.Fatalf("SetPerm: %v", err)
	}
	st2, _ := fc.Stat(ctx, "ag_files", up2, actor)
	if st2.Mode != "0600" {
		t.Fatalf("mode=%s, want 0600", st2.Mode)
	}

	// 8. Symlink rejection (D4).
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.Stat(ctx, "ag_files", link, actor); err == nil {
		t.Fatal("stat on symlink should be rejected")
	}

	// 9. Audit rows recorded.
	events, err := st.AuditPage("", "", 0, 20, 0)
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	fileEvents := 0
	for _, ev := range events {
		if ev.Kind == "file" {
			fileEvents++
		}
	}
	if fileEvents < 7 {
		t.Fatalf("file audit events=%d, want >=7", fileEvents)
	}
}

// TestFilesPolicyDeny verifies D1: write ops require policy; a deny rule
// blocks the upload with 403 and records an audit row.
func TestFilesPolicyDeny(t *testing.T) {
	st, fc, _, cleanup := startFilesServer(t)
	defer cleanup()
	ctx := context.Background()
	dir := t.TempDir()

	if err := st.CreatePolicy("pol_deny_upload", "deny-uploads", policy.Match{
		Actions: []string{policy.ActionFileWrite},
	}, policy.EffectDeny, 100); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	_, err := fc.Upload(ctx, "ag_files", filepath.Join(dir, "x"), bytes.NewReader([]byte("x")), 1, "0644", actor)
	if err == nil {
		t.Fatal("upload should be denied")
	}

	events, err := st.AuditPage("", "", 0, 20, 0)
	if err != nil {
		t.Fatalf("AuditPage: %v", err)
	}
	denied := 0
	for _, ev := range events {
		if ev.Kind == "file" && ev.Payload != "" && contains(ev.Payload, `"state":"denied"`) {
			denied++
		}
	}
	if denied < 1 {
		t.Fatalf("no denied file audit event found")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

var _ = certutil.LoadOrCreateServerIdentity
var _ = policy.ActionFileWrite
