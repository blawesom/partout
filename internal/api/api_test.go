package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/hsauth"
	"github.com/blawesom/partout/internal/identity"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// startAPITest sets up an in-memory store, stream handler, gRPC server,
// connected agent, and an httptest HTTP server. Returns the HTTP handler
// and the stream handler (for session checks).
func startAPITest(t *testing.T) (*api.Handler, *stream.Handler, *httptest.Server) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := api.New(st, h, sseB, log.New(io.Discard, "api: ", 0))

	// bufconn gRPC.
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// Seed agent.
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(id.Ed25519Pub)
	xpubB64 := base64.StdEncoding.EncodeToString(id.X25519Pub)
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_api", UUID: id.UUID, ED25519Pub: pubB64, X25519Pub: xpubB64,
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetRole("ag_api", "test"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// Agent connects.
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	streamClient, err := pb.NewAgentStreamClient(conn).Stream(ctx)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	env, err := streamClient.Recv()
	if err != nil {
		t.Fatalf("Recv challenge: %v", err)
	}
	ch := env.GetChallenge()
	if ch == nil {
		t.Fatalf("expected CHALLENGE, got %s", env.Kind)
	}
	ts := time.Now().Unix()
	sig := id.Sign(hsauth.BuildMsg(ch.Nonce, id.UUID, ts))
	if err := streamClient.Send(&pb.Envelope{
		Kind: pb.EnvelopeKind_AUTH_PROOF,
		Payload: &pb.Envelope_AuthProof{AuthProof: &pb.AuthProof{
			AgentUuid: id.UUID, Ts: ts, Sig: sig,
		}},
	}); err != nil {
		t.Fatalf("Send proof: %v", err)
	}

	// Wait for session to be registered.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if sess := h.AgentSession("ag_api"); sess != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Agent command loop: respond to commands with output + succeeded.
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		for {
			down, err := streamClient.Recv()
			if err != nil {
				return
			}
			cmd := down.GetCommand()
			if cmd == nil {
				continue
			}
			for i, a := range cmd.Args {
				data := append([]byte(a), '\n')
				streamClient.Send(&pb.Envelope{
					Kind: pb.EnvelopeKind_COMMAND_OUTPUT,
					Payload: &pb.Envelope_Output{Output: &pb.CommandOutput{
						RunId: cmd.RunId, ChunkSeq: uint64(i), Data: data,
					}},
				})
			}
			streamClient.Send(&pb.Envelope{
				Kind: pb.EnvelopeKind_COMMAND_RESULT,
				Payload: &pb.Envelope_Result{Result: &pb.CommandResult{
					RunId: cmd.RunId, ExitCode: 0, State: "succeeded", DurationMs: 1,
				}},
			})
		}
	}()

	// HTTP server.
	srv := httptest.NewServer(apiH)
	// Cleanup: cancel the context first so the stream closes and the agent loop
	// exits (its Recv returns an error). Wait for the loop to terminate (no more
	// Send calls), then close the send side. conn.Close (registered earlier) runs
	// after this block, LIFO.
	t.Cleanup(func() {
		cancel()
		select {
		case <-agentDone:
		case <-time.After(2 * time.Second):
			t.Log("agent loop did not stop within 2s")
		}
		streamClient.CloseSend()
	})

	return apiH, h, srv
}

func TestHealthz(t *testing.T) {
	_, _, srv := startAPITest(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestReadyz(t *testing.T) {
	_, _, srv := startAPITest(t)
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDispatchViaAPI(t *testing.T) {
	_, h, srv := startAPITest(t)
	if sess := h.AgentSession("ag_api"); sess == nil {
		t.Fatal("session missing before dispatch")
	}
	body := `{"selector":"role:test","cmd":"echo","args":["from","api"],"timeout_s":10,"created_by":"admin"}`
	resp, err := http.Post(srv.URL+"/api/v1/executions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /executions: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if sess := h.AgentSession("ag_api"); sess == nil {
		t.Log("session GONE after dispatch")
	} else {
		t.Log("session present after dispatch")
	}
	t.Logf("POST body: %s", string(b))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(b, []byte(`"execution_id"`)) {
		t.Fatalf("body = %s, want execution_id", string(b))
	}
}

func TestDispatchInvalidBody(t *testing.T) {
	_, _, srv := startAPITest(t)
	resp, err := http.Post(srv.URL+"/api/v1/executions", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("POST /executions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDispatchEmptySelector(t *testing.T) {
	_, _, srv := startAPITest(t)
	body := `{"selector":"","cmd":"echo"}`
	resp, err := http.Post(srv.URL+"/api/v1/executions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /executions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("empty selector should fail")
	}
}

func TestSSEStream(t *testing.T) {
	_, _, srv := startAPITest(t)
	resp, err := http.Get(srv.URL + "/api/v1/events")
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
}

// TestObserveEndpoints is the M5 read-API test: structured facts merged into
// the host_facts document are served by GET /api/v1/services,
// /api/v1/certificates, /api/v1/configs with label/agent filtering.
func TestObserveEndpoints(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sseB := sse.New()
	streamH := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := api.New(st, streamH, sseB, log.New(io.Discard, "api: ", 0))

	if err := st.UpsertAgent(store.Agent{ID: "ag_api", UUID: "u-observe"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	blob := `{
		"host.arch": "amd64",
		"services_detailed": {"units": [
			{"name": "myapp", "state": "active", "sub_state": "running", "enabled": true, "labels": ["myapp", "prod"]},
			{"name": "other", "state": "active", "sub_state": "running", "enabled": true, "labels": ["legacy"]}
		]},
		"configs": {"haproxy": {"present": true, "version": "2.8", "config_valid": true, "config_sha256": "abc123"}},
		"certificates": {"items": [
			{"path": "/etc/ssl/app.pem", "subject": "CN=app", "days_remaining": 12, "chain_valid": true},
			{"path": "/etc/ssl/ok.pem", "subject": "CN=ok", "days_remaining": 200, "chain_valid": true}
		]}
	}`
	if err := st.UpsertHostFactsJSON("ag_api", blob); err != nil {
		t.Fatalf("UpsertHostFactsJSON: %v", err)
	}
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)

	getJSON := func(path string, out any) int {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return resp.StatusCode
	}

	// Services: unfiltered, then label-filtered, then agent-filtered.
	var sv struct {
		Count int `json:"count"`
		Items []struct {
			HostID string `json:"host_id"`
			Unit   struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"unit"`
		} `json:"items"`
	}
	if code := getJSON("/api/v1/services", &sv); code != 200 || sv.Count != 2 {
		t.Fatalf("services: code=%d count=%d, want 200/2", code, sv.Count)
	}
	if code := getJSON("/api/v1/services?label=myapp", &sv); code != 200 || sv.Count != 1 || sv.Items[0].Unit.Name != "myapp" {
		t.Fatalf("services?label=myapp: code=%d count=%d, want 200/1/myapp", code, sv.Count)
	}
	if code := getJSON("/api/v1/services?agent_id=ag_nope", &sv); code != 200 || sv.Count != 0 {
		t.Fatalf("services?agent_id=ag_nope: code=%d count=%d, want 200/0", code, sv.Count)
	}

	// Certificates: unfiltered, then max_days filter.
	var certs struct {
		Count int `json:"count"`
		Items []struct {
			Cert struct {
				Path          string `json:"path"`
				DaysRemaining int64  `json:"days_remaining"`
			} `json:"cert"`
		} `json:"items"`
	}
	if code := getJSON("/api/v1/certificates", &certs); code != 200 || certs.Count != 2 {
		t.Fatalf("certificates: code=%d count=%d, want 200/2", code, certs.Count)
	}
	if code := getJSON("/api/v1/certificates?days_remaining_lt=30", &certs); code != 200 || certs.Count != 1 || certs.Items[0].Cert.Path != "/etc/ssl/app.pem" {
		t.Fatalf("certificates?days_remaining_lt=30: code=%d count=%d, want 200/1/app.pem", code, certs.Count)
	}

	// Configs.
	var cfgs struct {
		Count int `json:"count"`
		Items []struct {
			Kind    string `json:"kind"`
			HAProxy struct {
				Present     bool   `json:"present"`
				Version     string `json:"version"`
				ConfigValid bool   `json:"config_valid"`
			} `json:"haproxy"`
		} `json:"items"`
	}
	if code := getJSON("/api/v1/configs", &cfgs); code != 200 || cfgs.Count != 1 {
		t.Fatalf("configs: code=%d count=%d, want 200/1", code, cfgs.Count)
	}
	if cfgs.Items[0].Kind != "haproxy" {
		t.Fatalf("config kind = %q, want haproxy", cfgs.Items[0].Kind)
	}
	if h := cfgs.Items[0].HAProxy; !h.Present || h.Version != "2.8" || !h.ConfigValid {
		t.Fatalf("haproxy = %+v, want present/2.8/valid", h)
	}

	// kind filter: nginx is not present on this host → empty.
	if code := getJSON("/api/v1/configs?kind=nginx", &cfgs); code != 200 || cfgs.Count != 0 {
		t.Fatalf("configs?kind=nginx: code=%d count=%d, want 200/0", code, cfgs.Count)
	}
}
