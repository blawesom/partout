package files_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/files"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// newFilesBufconn builds a bufconn server + connected fake agent that
// answers FILE_OP envelopes (begin/chunk/commit → canned results). The
// seenKinds channel records every op kind that hit the wire.
func newFilesBufconn(t *testing.T) (*store.Store, *files.Controller, *stream.Handler, func(), chan string) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	sseB := sse.New()
	lg := log.New(io.Discard, "srv:", 0)
	h := stream.NewHandler(st, sseB, lg)
	fc := files.New(st, h, sseB, lg)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
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

	seenKinds := make(chan string, 16)
	go func() {
		for {
			down, err := s.Recv()
			if err != nil {
				return
			}
			op := down.GetFileOp()
			if op == nil {
				continue
			}
			seenKinds <- op.Kind.String()
			var res *pb.FileOpResult
			switch op.Kind {
			case pb.FileOpKind_FILE_OP_UPLOAD_BEGIN:
				res = &pb.FileOpResult{OpId: op.OpId, Kind: op.Kind, Code: 0, TempPath: "/tmp/staged"}
			case pb.FileOpKind_FILE_OP_UPLOAD_COMMIT:
				res = &pb.FileOpResult{OpId: op.OpId, Kind: op.Kind, Code: 0, NewSha256: "sha-uploaded"}
			default:
				res = &pb.FileOpResult{OpId: op.OpId, Kind: op.Kind, Code: 0}
			}
			_ = s.Send(&pb.Envelope{
				Kind:    pb.EnvelopeKind_FILE_OP_RESULT,
				Payload: &pb.Envelope_FileOpResult{FileOpResult: res},
			})
		}
	}()

	cleanup := func() {
		cancel()
		_ = conn.Close()
		gs.Stop()
	}
	return st, fc, h, cleanup, seenKinds
}

// TestUploadRequireApprovalParksAndApprove is the M4 files E2E loop: a
// require_approval rule on file.write parks the upload (no ops on the wire,
// body staged); admin approval re-dispatches the staged body and the file
// lands.
func TestUploadRequireApprovalParksAndApprove(t *testing.T) {
	st, fc, h, cleanup, seen := newFilesBufconn(t)
	defer cleanup()
	fc.SetStagingDir(t.TempDir())

	if err := st.CreatePolicy("pol_file_appr", "file-write-needs-approval", policy.Match{
		Actions: []string{policy.ActionFileWrite},
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	apr := approvals.New(st, h, sse.New(), nil)
	apr.SetIdentity(ident)
	fc.SetApprovals(apr)
	apr.RegisterDispatcher(policy.ActionFileWrite, func(req *store.ApprovalRequest, dec *pb.Decision) error {
		return fc.DispatchApprovedFileOp(context.Background(), req, dec)
	})

	body := "hello approved upload\n"
	_, err = fc.Upload(context.Background(), "ag_files", "/etc/hello",
		strings.NewReader(body), int64(len(body)), "0644",
		files.Actor{Principal: "alice", Role: "operator"})
	var apprErr *files.ApprovalRequiredError
	if !errors.As(err, &apprErr) {
		t.Fatalf("Upload err = %v, want *ApprovalRequiredError", err)
	}
	if apprErr.ApprovalID == "" {
		t.Fatal("expected an approval id")
	}

	// Nothing may have hit the wire before approval.
	select {
	case k := <-seen:
		t.Fatalf("wire traffic before approval: %s", k)
	case <-time.After(200 * time.Millisecond):
	}

	// Non-admin cannot approve.
	if _, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "carol", Role: "operator"}); err == nil {
		t.Fatal("operator must not approve")
	}

	// Admin approval → the staged body replays begin/chunk/commit.
	got, err := apr.Approve(apprErr.ApprovalID, approvals.Actor{Principal: "bob", Role: "admin"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.State != "approved" {
		t.Fatalf("after approve: %+v", got)
	}

	// The begin op (with the signed decision) must have gone down.
	var joined strings.Builder
	for {
		select {
		case k := <-seen:
			joined.WriteString(k + ",")
		case <-time.After(300 * time.Millisecond):
			goto drained
		}
	}
drained:
	ops := joined.String()
	for _, want := range []string{"FILE_OP_UPLOAD_BEGIN", "FILE_OP_UPLOAD_COMMIT"} {
		if !strings.Contains(ops, want) {
			t.Fatalf("expected %s in wire ops, got %s", want, ops)
		}
	}
}
