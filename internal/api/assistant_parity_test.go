// Feedback-parity test (docs/assistant.md "Feedback parity"): the same
// governed action performed once via the REST surface (as the UI does) and
// once via an assistant tool call must leave the system identically
// observable — same approval rows (class, actor, role, state), same
// execution attribution (created_by from the token, never the body), and
// the assistant's tool message carrying the same ids the REST response
// returned, so the chat can render the same artifacts.
package api

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/certutil"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/assistant"
	"github.com/blawesom/partout/internal/server/mcp"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestAssistantFeedbackParity drives run_command through both front doors
// against a require_approval policy and asserts the observable state is
// indistinguishable.
func TestAssistantFeedbackParity(t *testing.T) {
	llm := newFakeLLM(t,
		fakeReply{content: "ok"}, // consumed by the enablement probe
		fakeReply{toolName: "run_command", toolArgs: `{"selector":"host:ag_par","cmd":"uptime"}`},
		fakeReply{content: "I requested the run; it is parked on an approval — an admin decides."},
	)

	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	streamH := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := New(st, streamH, sseB, log.New(io.Discard, "api: ", 0))
	apiH.SetAssistant(assistant.New(st, mcp.NewLocalAPI(apiH), nil, log.New(io.Discard, "as: ", 0)))

	// Approvals engine with the exec dispatcher (mirrors main.go wiring).
	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	apr := approvals.New(st, streamH, sseB, log.New(io.Discard, "apr: ", 0))
	apr.SetIdentity(ident)
	apiH.Control().SetApprovals(apr) // the dispatch path parks through control
	apr.RegisterDispatcher("exec", func(req *store.ApprovalRequest, d *pb.Decision) error { return nil })
	apiH.SetApprovals(apr)

	// A host + a require_approval rule for exec.
	if err := st.UpsertAgent(store.Agent{ID: "ag_par", UUID: "u-par"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)
	mustPost(t, srv, "POST", "/api/v1/policies",
		`{"name":"parity-guard","effect":"require_approval","match":{"actions":["exec"]}}`)

	// ---- Path 1: the user dispatches from the UI (REST) ------------------
	resp := mustPost(t, srv, "POST", "/api/v1/executions",
		`{"selector":"host:ag_par","cmd":"uptime","created_by":"spoofed-by-client"}`)
	var direct struct {
		ExecutionID string `json:"execution_id"`
		Runs        []struct {
			RunID      string `json:"run_id"`
			State      string `json:"state"`
			ApprovalID string `json:"approval_id"`
		} `json:"runs"`
	}
	_ = json.Unmarshal([]byte(resp), &direct)
	if len(direct.Runs) != 1 || direct.Runs[0].State != "awaiting_approval" ||
		!strings.HasPrefix(direct.Runs[0].ApprovalID, "apr_") {
		t.Fatalf("direct dispatch: %s", resp)
	}
	// Attribution comes from the token, never the body.
	var directExec struct {
		CreatedBy string `json:"created_by"`
	}
	_ = json.Unmarshal([]byte(mustGet(t, srv, "/api/v1/executions/"+direct.ExecutionID)), &directExec)
	if directExec.CreatedBy != "local" {
		t.Fatalf("direct exec created_by = %q, want \"local\" (client value must be ignored)", directExec.CreatedBy)
	}

	// ---- Path 2: the assistant requests the same action -------------------
	configureAssistant(t, srv, llm.srv.URL)
	sess := mustPost(t, srv, "POST", "/api/v1/assistant/sessions", `{"profile":"full"}`)
	var sessBody struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(sess), &sessBody)
	if sessBody.ID == "" {
		t.Fatalf("no session id: %s", sess)
	}

	chatResp, err := http.Post(srv.URL+"/api/v1/assistant/sessions/"+sessBody.ID+"/chat",
		"application/json", strings.NewReader(`{"text":"run uptime on ag_par"}`))
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	defer chatResp.Body.Close()

	// Collect the SSE events of the turn.
	type ev struct {
		Type string          `json:"type"`
		Tool string          `json:"tool"`
		Meta json.RawMessage `json:"meta"`
	}
	var events []ev
	sc := bufio.NewScanner(chatResp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var e ev
		if json.Unmarshal([]byte(line[6:]), &e) == nil {
			events = append(events, e)
		}
	}

	var approvalEv *ev
	toolResults := 0
	for i := range events {
		switch events[i].Type {
		case "approval_required":
			if approvalEv != nil {
				t.Fatalf("multiple approval_required events (was every one a real park?)")
			}
			approvalEv = &events[i]
		case "tool_result":
			toolResults++
		}
	}
	if approvalEv == nil {
		t.Fatalf("no approval_required event; events = %+v", events)
	}
	if approvalEv.Tool != "run_command" {
		t.Fatalf("approval_required tool = %q", approvalEv.Tool)
	}
	var meta struct {
		ApprovalIDs []string `json:"approval_ids"`
		ExecutionID string   `json:"execution_id"`
		RunIDs      []string `json:"run_ids"`
	}
	if err := json.Unmarshal(approvalEv.Meta, &meta); err != nil {
		t.Fatalf("event meta: %v (%s)", err, approvalEv.Meta)
	}
	if len(meta.ApprovalIDs) != 1 || !strings.HasPrefix(meta.ApprovalIDs[0], "apr_") {
		t.Fatalf("meta.approval_ids = %v", meta.ApprovalIDs)
	}
	if !strings.HasPrefix(meta.ExecutionID, "exec_") || len(meta.RunIDs) != 1 {
		t.Fatalf("meta = %+v", meta)
	}
	if toolResults != 0 {
		t.Fatalf("a parked tool call must emit approval_required, not tool_result")
	}

	// The transcript carries the same ids (a reloaded session renders the
	// same cards).
	transcript := mustGet(t, srv, "/api/v1/assistant/sessions/"+sessBody.ID)
	var tr struct {
		Messages []struct {
			Role string `json:"role"`
			Tool string `json:"tool_name"`
			Meta *struct {
				ApprovalIDs []string `json:"approval_ids"`
				ExecutionID string   `json:"execution_id"`
			} `json:"meta"`
		} `json:"messages"`
	}
	_ = json.Unmarshal([]byte(transcript), &tr)
	var toolMeta *struct {
		ApprovalIDs []string `json:"approval_ids"`
		ExecutionID string   `json:"execution_id"`
	}
	for _, m := range tr.Messages {
		if m.Role == "tool" && m.Tool == "run_command" {
			toolMeta = m.Meta
		}
	}
	if toolMeta == nil || len(toolMeta.ApprovalIDs) != 1 ||
		toolMeta.ApprovalIDs[0] != meta.ApprovalIDs[0] ||
		toolMeta.ExecutionID != meta.ExecutionID {
		t.Fatalf("transcript meta mismatch: %+v (event meta %+v)", toolMeta, meta)
	}

	// The assistant-initiated execution is attributed to the user whose
	// token drove it — same as the UI dispatch.
	var asstExec struct {
		CreatedBy string `json:"created_by"`
	}
	_ = json.Unmarshal([]byte(mustGet(t, srv, "/api/v1/executions/"+meta.ExecutionID)), &asstExec)
	if asstExec.CreatedBy != "local" {
		t.Fatalf("assistant exec created_by = %q, want \"local\"", asstExec.CreatedBy)
	}

	// Both paths left the same observable approval state: two pending exec
	// requests, same class, same actor, same role — indistinguishable
	// except by id.
	list := mustGet(t, srv, "/api/v1/approvals?state=pending")
	var page struct {
		Approvals []struct {
			ActionClass string `json:"action_class"`
			Actor       string `json:"actor"`
			ActorRole   string `json:"actor_role"`
			State       string `json:"state"`
		} `json:"approvals"`
	}
	_ = json.Unmarshal([]byte(list), &page)
	if len(page.Approvals) != 2 {
		t.Fatalf("want 2 pending approvals (one per path), got %d: %s", len(page.Approvals), list)
	}
	for _, a := range page.Approvals {
		if a.ActionClass != "exec" || a.Actor != "local" || a.ActorRole != "admin" || a.State != "pending" {
			t.Fatalf("approval row not parity-shaped: %+v", a)
		}
	}
}

func mustPost(t *testing.T, srv *httptest.Server, method, path, body string) string {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("%s %s: status %d: %s", method, path, resp.StatusCode, b)
	}
	return string(b)
}

func mustGet(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, b)
	}
	return string(b)
}
