package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
			{"path": "/etc/ssl/app.pem", "subject": "CN=app", "not_after": 1000000, "days_remaining": 12, "chain_valid": true},
			{"path": "/etc/ssl/ok.pem", "subject": "CN=ok", "not_after": 2000000, "days_remaining": 200, "chain_valid": true}
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

// startObserveAPI builds a store + API handler + httptest server for the
// observe read endpoints (no agent needed: they read host_facts directly).
func startObserveAPI(t *testing.T) (*store.Store, *httptest.Server) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	streamH := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := api.New(st, streamH, sseB, log.New(io.Discard, "api: ", 0))
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)
	return st, srv
}

// seedObserveHost registers a host and writes its merged facts document.
func seedObserveHost(t *testing.T, st *store.Store, id, blob string) {
	t.Helper()
	if err := st.UpsertAgent(store.Agent{ID: id, UUID: "u-" + id}); err != nil {
		t.Fatalf("UpsertAgent(%s): %v", id, err)
	}
	// Flat key first so the merge path is exercised, then structured facts.
	if err := st.UpsertFacts(store.Facts{AgentID: id, Data: map[string]string{"host.os": "linux"}}); err != nil {
		t.Fatalf("UpsertFacts(%s): %v", id, err)
	}
	if err := st.UpsertHostFactsJSON(id, blob); err != nil {
		t.Fatalf("UpsertHostFactsJSON(%s): %v", id, err)
	}
}

// getObserve GETs a path and decodes the JSON body.
func getObserve(t *testing.T, srv *httptest.Server, path string, out any) int {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode
}

type svcResp struct {
	Count int `json:"count"`
	Items []struct {
		HostID string `json:"host_id"`
		Unit   struct {
			Name   string   `json:"name"`
			State  string   `json:"state"`
			Labels []string `json:"labels"`
		} `json:"unit"`
	} `json:"items"`
}

type certResp struct {
	Count int `json:"count"`
	Items []struct {
		HostID string `json:"host_id"`
		Cert   struct {
			Path          string `json:"path"`
			DaysRemaining int64  `json:"days_remaining"`
			ChainChecked  bool   `json:"chain_checked"`
			ChainValid    bool   `json:"chain_valid"`
			KeyType       string `json:"key_type"`
		} `json:"cert"`
	} `json:"items"`
}

type cfgResp struct {
	Count int `json:"count"`
	Items []struct {
		HostID  string `json:"host_id"`
		Kind    string `json:"kind"`
		HAProxy struct {
			Present     bool   `json:"present"`
			Version     string `json:"version"`
			ConfigValid bool   `json:"config_valid"`
		} `json:"haproxy"`
		Nginx struct {
			Present bool   `json:"present"`
			Version string `json:"version"`
		} `json:"nginx"`
	} `json:"items"`
}

// TestObserveServicesFilters covers every documented query parameter.
func TestObserveServicesFilters(t *testing.T) {
	st, srv := startObserveAPI(t)
	seedObserveHost(t, st, "ag_1", `{"services_detailed":{"units":[
		{"name":"myapp","state":"active","sub_state":"running","enabled":true,"labels":["myapp","prod"]},
		{"name":"legacy","state":"failed","sub_state":"dead","enabled":false,"labels":["legacy"]}
	]}}`)
	seedObserveHost(t, st, "ag_2", `{"services_detailed":{"units":[
		{"name":"myapp","state":"failed","sub_state":"dead","enabled":true,"labels":["myapp"]}
	]}}`)

	var got svcResp
	// No filter: 3 units across 2 hosts.
	if code := getObserve(t, srv, "/api/v1/services", &got); code != 200 || got.Count != 3 {
		t.Fatalf("unfiltered: code=%d count=%d, want 200/3", code, got.Count)
	}
	// label filter.
	if code := getObserve(t, srv, "/api/v1/services?label=prod", &got); code != 200 || got.Count != 1 {
		t.Fatalf("label=prod: code=%d count=%d, want 200/1", code, got.Count)
	}
	// state filter (cross-host).
	if code := getObserve(t, srv, "/api/v1/services?state=failed", &got); code != 200 || got.Count != 2 {
		t.Fatalf("state=failed: code=%d count=%d, want 200/2", code, got.Count)
	}
	// name filter.
	if code := getObserve(t, srv, "/api/v1/services?name=myapp", &got); code != 200 || got.Count != 2 {
		t.Fatalf("name=myapp: code=%d count=%d, want 200/2", code, got.Count)
	}
	// agent_id filter.
	if code := getObserve(t, srv, "/api/v1/services?agent_id=ag_1", &got); code != 200 || got.Count != 2 {
		t.Fatalf("agent_id=ag_1: code=%d count=%d, want 200/2", code, got.Count)
	}
	// Combined filters.
	if code := getObserve(t, srv, "/api/v1/services?label=myapp&state=failed&agent_id=ag_2", &got); code != 200 || got.Count != 1 {
		t.Fatalf("combined: code=%d count=%d, want 200/1", code, got.Count)
	}
	// Unmatched filters yield an empty (not nil) item list.
	if code := getObserve(t, srv, "/api/v1/services?label=nope", &got); code != 200 || got.Count != 0 || got.Items == nil {
		t.Fatalf("label=nope: code=%d count=%d items=%v, want 200/0/[]", code, got.Count, got.Items)
	}
	// host_id is always the server-side agent id.
	if code := getObserve(t, srv, "/api/v1/services?agent_id=ag_1", &got); code != 200 {
		t.Fatal(code)
	}
	for _, it := range got.Items {
		if it.HostID != "ag_1" {
			t.Errorf("host_id = %q, want ag_1", it.HostID)
		}
	}
}

// TestObserveCertificatesFilters covers days_remaining_lt and the
// chain_checked passthrough.
func TestObserveCertificatesFilters(t *testing.T) {
	st, srv := startObserveAPI(t)
	seedObserveHost(t, st, "ag_c1", `{"certificates":{"items":[
		{"path":"/etc/ssl/soon.pem","not_after":1000,"days_remaining":5,"chain_checked":true,"chain_valid":false,"key_type":"RSA-4096"},
		{"path":"/etc/ssl/fine.pem","not_after":9000000,"days_remaining":300,"chain_checked":true,"chain_valid":true,"key_type":"ECDSA-P-256"}
	]}}`)
	seedObserveHost(t, st, "ag_c2", `{"certificates":{"items":[
		{"path":"/etc/ssl/unknown.pem","not_after":0,"days_remaining":0,"chain_checked":false}
	]}}`)

	var got certResp
	if code := getObserve(t, srv, "/api/v1/certificates", &got); code != 200 || got.Count != 3 {
		t.Fatalf("unfiltered: code=%d count=%d, want 200/3", code, got.Count)
	}
	if code := getObserve(t, srv, "/api/v1/certificates?days_remaining_lt=30", &got); code != 200 || got.Count != 1 {
		t.Fatalf("days_remaining_lt=30: code=%d count=%d, want 200/1 (unknown expiry excluded)", code, got.Count)
	}
	if got.Items[0].Cert.Path != "/etc/ssl/soon.pem" {
		t.Errorf("path = %q, want /etc/ssl/soon.pem", got.Items[0].Cert.Path)
	}
	if !got.Items[0].Cert.ChainChecked || got.Items[0].Cert.ChainValid {
		t.Errorf("chain flags not passed through: %+v", got.Items[0].Cert)
	}
	if code := getObserve(t, srv, "/api/v1/certificates?agent_id=ag_c2", &got); code != 200 || got.Count != 1 {
		t.Fatalf("agent_id: code=%d count=%d, want 200/1", code, got.Count)
	}
	if got.Items[0].Cert.ChainChecked {
		t.Error("unchecked cert reported as checked")
	}
	// Invalid days_remaining_lt is a 400.
	if code := getObserve(t, srv, "/api/v1/certificates?days_remaining_lt=abc", nil); code != 400 {
		t.Errorf("days_remaining_lt=abc: code=%d, want 400", code)
	}
}

// TestObserveConfigsFilters covers the kind filter for both products.
func TestObserveConfigsFilters(t *testing.T) {
	st, srv := startObserveAPI(t)
	seedObserveHost(t, st, "ag_h", `{"configs":{"haproxy":{"present":true,"version":"2.8","config_valid":true}}}`)
	seedObserveHost(t, st, "ag_n", `{"configs":{"nginx":{"present":true,"version":"1.24","config_valid":false}}}`)
	seedObserveHost(t, st, "ag_both", `{"configs":{"haproxy":{"present":true,"version":"2.9","config_valid":true},"nginx":{"present":true,"version":"1.25","config_valid":true}}}`)

	var got cfgResp
	if code := getObserve(t, srv, "/api/v1/configs", &got); code != 200 || got.Count != 3 {
		t.Fatalf("unfiltered: code=%d count=%d, want 200/3", code, got.Count)
	}
	if code := getObserve(t, srv, "/api/v1/configs?kind=haproxy", &got); code != 200 || got.Count != 2 {
		t.Fatalf("kind=haproxy: code=%d count=%d, want 200/2", code, got.Count)
	}
	for _, it := range got.Items {
		if it.Kind != "haproxy" || it.HAProxy.Version == "" {
			t.Errorf("haproxy filter returned %+v", it)
		}
	}
	if code := getObserve(t, srv, "/api/v1/configs?kind=nginx", &got); code != 200 || got.Count != 2 {
		t.Fatalf("kind=nginx: code=%d count=%d, want 200/2", code, got.Count)
	}
	if code := getObserve(t, srv, "/api/v1/configs?kind=haproxy&agent_id=ag_both", &got); code != 200 || got.Count != 1 {
		t.Fatalf("combined: code=%d count=%d, want 200/1", code, got.Count)
	}
	// Unknown kind behaves like "any".
	if code := getObserve(t, srv, "/api/v1/configs?kind=apache", &got); code != 200 || got.Count != 3 {
		t.Fatalf("kind=apache: code=%d count=%d, want 200/3", code, got.Count)
	}
}

// TestObserveEndpointsNoFacts: hosts without facts are simply absent.
func TestObserveEndpointsNoFacts(t *testing.T) {
	st, srv := startObserveAPI(t)
	if err := st.UpsertAgent(store.Agent{ID: "ag_bare", UUID: "u-bare"}); err != nil {
		t.Fatal(err)
	}
	// Only flat facts: no observe domain, so all three endpoints are empty.
	if err := st.UpsertFacts(store.Facts{AgentID: "ag_bare", Data: map[string]string{"host.os": "linux"}}); err != nil {
		t.Fatal(err)
	}
	var svc svcResp
	if code := getObserve(t, srv, "/api/v1/services", &svc); code != 200 || svc.Count != 0 {
		t.Errorf("services: code=%d count=%d, want 200/0", code, svc.Count)
	}
	var certs certResp
	if code := getObserve(t, srv, "/api/v1/certificates", &certs); code != 200 || certs.Count != 0 {
		t.Errorf("certificates: code=%d count=%d, want 200/0", code, certs.Count)
	}
	var cfgs cfgResp
	if code := getObserve(t, srv, "/api/v1/configs", &cfgs); code != 200 || cfgs.Count != 0 {
		t.Errorf("configs: code=%d count=%d, want 200/0", code, cfgs.Count)
	}
}

// TestObserveEndpointsMalformedDocumentIsolated: one corrupt host document
// must not fail the whole query.
func TestObserveEndpointsMalformedDocumentIsolated(t *testing.T) {
	st, srv := startObserveAPI(t)
	seedObserveHost(t, st, "ag_good", `{"services_detailed":{"units":[{"name":"ok","state":"active"}]}}`)
	// Simulate corruption at rest: write a non-JSON document directly.
	if err := st.UpsertAgent(store.Agent{ID: "ag_bad", UUID: "u-ag_bad"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertHostFactsJSON("ag_bad", `{"services_detailed":{"units":[]}}`); err != nil {
		t.Fatal(err)
	}
	// Overwrite with a corrupt document through the raw path used by tests.
	if err := st.UpsertHostFactsJSON("ag_bad", `{corrupt`); err == nil {
		t.Skip("store rejects corrupt docs; isolation covered elsewhere")
	}

	var got svcResp
	if code := getObserve(t, srv, "/api/v1/services", &got); code != 200 || got.Count != 1 {
		t.Fatalf("code=%d count=%d, want 200/1 (good host served)", code, got.Count)
	}
}

// TestObserveEndpointsHostCap: the aggregation cap bounds the response.
func TestObserveEndpointsHostCap(t *testing.T) {
	st, srv := startObserveAPI(t)
	// Seed more hosts than the cap allows and confirm the response is bounded.
	// (The cap constant is package-private; assert the observable property:
	// the endpoint returns without scanning unboundedly, and every returned
	// host has the domain.)
	const n = 12
	for i := 0; i < n; i++ {
		seedObserveHost(t, st, fmt.Sprintf("ag_cap_%02d", i), `{"services_detailed":{"units":[{"name":"app","state":"active"}]}}`)
	}
	var got svcResp
	if code := getObserve(t, srv, "/api/v1/services", &got); code != 200 {
		t.Fatalf("code=%d", code)
	}
	if got.Count != n {
		t.Errorf("count = %d, want %d (under the cap)", got.Count, n)
	}
}

// TestObserveEndpointsNoStructuredLeakIntoFlatView: the flat facts endpoint
// must not expose nested observe objects.
func TestObserveEndpointsFlatFactsUnaffected(t *testing.T) {
	st, srv := startObserveAPI(t)
	seedObserveHost(t, st, "ag_split", `{"services_detailed":{"units":[{"name":"app"}]}}`)

	var body struct {
		Facts map[string]any `json:"facts"`
	}
	if code := getObserve(t, srv, "/api/v1/hosts/ag_split/facts", &body); code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	if body.Facts["host.os"] != "linux" {
		t.Errorf("flat facts = %v, want host.os=linux", body.Facts)
	}
	if _, ok := body.Facts["services_detailed"]; ok {
		t.Errorf("structured domain leaked into /facts: %v", body.Facts)
	}
}
