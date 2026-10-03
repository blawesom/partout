// Assistant API integration (R26, M9): drives the full in-process path —
// REST config → session → SSE chat turn — against a FAKE OpenAI-compatible
// endpoint. The fake answers with a tool call (list_hosts) then a prose
// reply, which exercises: profile filtering, in-process tool execution via
// localAPI (single-user local mode ⇒ admin principal), transcript
// persistence, audit rows (egress + tool_call with prompt hash, no
// content), and the SSE event stream.
package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/server/assistant"
	"github.com/blawesom/partout/internal/server/mcp"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// fakeLLM is an OpenAI-compatible /chat/completions endpoint scripted per
// test: each turn pops the next scripted assistant reply.
type fakeLLM struct {
	srv    *httptest.Server
	calls  int
	script []fakeReply
}

type fakeReply struct {
	content  string
	toolName string // empty → prose-only reply
	toolArgs string
}

func (f *fakeLLM) handler(w http.ResponseWriter, r *http.Request) {
	f.calls++
	var body struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &body)
	if f.calls > len(f.script) {
		// Exhausted script: end with prose.
		writeFakeReply(w, fakeReply{content: "done"}, "")
		return
	}
	writeFakeReply(w, f.script[f.calls-1], fmt.Sprintf("call_%d", f.calls))
}

func writeFakeReply(w http.ResponseWriter, rep fakeReply, callID string) {
	msg := map[string]any{"role": "assistant", "content": rep.content}
	if rep.toolName != "" {
		msg["tool_calls"] = []any{map[string]any{
			"id":   callID,
			"type": "function",
			"function": map[string]any{
				"name":      rep.toolName,
				"arguments": rep.toolArgs,
			},
		}}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"choices": []any{map[string]any{"message": msg, "finish_reason": "stop"}},
	})
}

func newFakeLLM(t *testing.T, script ...fakeReply) *fakeLLM {
	t.Helper()
	f := &fakeLLM{script: script}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(f.srv.Close)
	return f
}

func startAssistantTest(t *testing.T, llm *fakeLLM) *httptest.Server {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := New(st, h, sseB, log.New(io.Discard, "api: ", 0))
	apiH.SetAssistant(assistant.New(st, mcp.NewLocalAPI(apiH), nil, log.New(io.Discard, "as: ", 0)))
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)
	return srv
}

func configureAssistant(t *testing.T, srv *httptest.Server, llmURL string) {
	body := fmt.Sprintf(`{"base_url":%q,"model":"fake-model","enabled":true,"default_profile":"readonly","max_tool_calls":5,"timeout_s":30}`, llmURL)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/assistant/config", strings.NewReader(body))
	if err != nil {
		t.Fatalf("PUT config: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT config: status %d: %s", resp.StatusCode, b)
	}
}

// TestAssistantChatEndToEnd drives a turn with one tool call.
func TestAssistantChatEndToEnd(t *testing.T) {
	llm := newFakeLLM(t,
		fakeReply{content: "ok"}, // consumed by the enablement probe
		fakeReply{toolName: "list_hosts", toolArgs: `{}`},
		fakeReply{content: "There is 1 host."},
	)
	srv := startAssistantTest(t, llm)
	configureAssistant(t, srv, llm.srv.URL)

	// Create a session.
	resp, err := http.Post(srv.URL+"/api/v1/assistant/sessions", "application/json",
		strings.NewReader(`{"profile":"full"}`))
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create session: status %d", resp.StatusCode)
	}
	var sess struct {
		ID      string `json:"id"`
		Profile string `json:"profile"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	if sess.ID == "" {
		t.Fatalf("no session id")
	}
	// Single-user local mode is admin, so "full" is honored; the profile
	// cap logic is exercised in the assistant package tests.

	// Chat turn (SSE).
	resp2, err := http.Post(srv.URL+"/api/v1/assistant/sessions/"+sess.ID+"/chat",
		"application/json", strings.NewReader(`{"text":"list the hosts"}`))
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("chat: status %d", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}

	events := map[string]bool{}
	sc := bufio.NewScanner(resp2.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			events[strings.TrimPrefix(line, "event: ")] = true
		}
	}
	for _, want := range []string{"egress", "tool_call", "tool_result", "assistant_delta", "done"} {
		if !events[want] {
			t.Fatalf("missing SSE event %q (got %v)", want, events)
		}
	}

	// Transcript persisted: user + assistant tool-call row + tool row + prose.
	resp3, err := http.Get(srv.URL + "/api/v1/assistant/sessions/" + sess.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	defer resp3.Body.Close()
	var tr struct {
		Messages []struct {
			Role     string `json:"role"`
			Content  string `json:"content"`
			ToolName string `json:"tool_name"`
		} `json:"messages"`
	}
	_ = json.NewDecoder(resp3.Body).Decode(&tr)
	var user, tool, prose int
	for _, m := range tr.Messages {
		switch {
		case m.Role == "user":
			user++
		case m.Role == "tool" && m.ToolName == "list_hosts":
			tool++
		case m.Role == "assistant" && m.ToolName == "":
			prose++
		}
	}
	if user != 1 || tool != 1 || prose != 1 {
		t.Fatalf("transcript: user=%d tool=%d prose=%d (msgs=%+v)", user, tool, prose, tr.Messages)
	}
	// The tool result is real (from the in-process REST router), not the
	// fake's output.
	found := false
	for _, m := range tr.Messages {
		if m.Role == "tool" && strings.Contains(m.Content, "ag_") || strings.Contains(m.Content, "hosts") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tool result does not look like a real list_hosts reply: %+v", tr.Messages)
	}

	// Audit: egress + tool_call rows, prompt hash not content.
	resp4, err := http.Get(srv.URL + "/api/v1/audit")
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	defer resp4.Body.Close()
	var audit struct {
		Items []struct {
			Kind    string `json:"kind"`
			Payload string `json:"payload"`
		} `json:"items"`
	}
	_ = json.NewDecoder(resp4.Body).Decode(&audit)
	var sawEgress, sawTool, sawContent bool
	for _, a := range audit.Items {
		switch a.Kind {
		case "assistant.egress":
			sawEgress = true
		case "assistant.tool_call":
			sawTool = true
			if strings.Contains(a.Payload, "list the hosts") {
				sawContent = true // prompt content must NOT be in the audit row
			}
		}
	}
	if !sawEgress || !sawTool {
		t.Fatalf("audit rows missing (egress=%v tool=%v)", sawEgress, sawTool)
	}
	if sawContent {
		t.Fatalf("audit tool_call row contains prompt content (must be hash only)")
	}
}

// TestAssistantDisabled503 verifies the routes 503 before SetAssistant.
func TestAssistantDisabled503(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := New(st, h, sseB, log.New(io.Discard, "api: ", 0))
	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/assistant/config")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (no assistant service)", resp.StatusCode)
	}
}

// TestAssistantEnablementProbeGate verifies enabling against a dead
// endpoint is refused (probe fails → config stays disabled).
func TestAssistantEnablementProbeGate(t *testing.T) {
	llm := newFakeLLM(t) // never called: probe fails against a closed port
	dead := llm.srv.URL
	llm.srv.Close()

	srv := startAssistantTest(t, llm)
	body := fmt.Sprintf(`{"base_url":%q,"model":"m","enabled":true}`, dead)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/assistant/config", strings.NewReader(body))
	if err != nil {
		t.Fatalf("PUT config: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (probe gate)", resp.StatusCode)
	}

	// Config exists but is not enabled → the capability stays off.
	cfgResp, err := http.Get(srv.URL + "/api/v1/assistant/config")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	defer cfgResp.Body.Close()
	var cfg struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(cfgResp.Body).Decode(&cfg)
	if cfg.Enabled {
		t.Fatalf("config enabled despite failed probe")
	}
}
