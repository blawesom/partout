// Assistant package tests: profile derivation + capping (the documented
// boundaries), the tool-call budget, and turn cancellation.
package assistant

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/server/mcp"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func TestProfilesDerivation(t *testing.T) {
	p := Profiles()
	// readonly ⊆ operator ⊆ full.
	if len(p[ProfileReadonly]) == 0 {
		t.Fatalf("readonly profile empty")
	}
	for name := range p[ProfileReadonly] {
		if !p[ProfileOperator][name] || !p[ProfileFull][name] {
			t.Fatalf("read tool %q missing from operator/full", name)
		}
	}
	// The never-reachable set is excluded everywhere.
	for _, prof := range []string{ProfileReadonly, ProfileOperator, ProfileFull} {
		if p[prof]["decide_approval"] {
			t.Fatalf("decide_approval reachable under %q — approvals are a human act", prof)
		}
	}
	// Writes are not in readonly.
	if p[ProfileReadonly]["run_command"] {
		t.Fatalf("run_command reachable under readonly")
	}
	// The schema filter agrees with the allow-list.
	for _, prof := range []string{ProfileReadonly, ProfileOperator, ProfileFull} {
		allow := p[prof]
		for _, schema := range ToolSchemasFor(prof) {
			fn := schema["function"].(map[string]any)
			if !allow[fn["name"].(string)] {
				t.Fatalf("schema for %q offers non-allow-listed tool %v", prof, fn["name"])
			}
		}
	}
}

func TestProfileForCappedByRole(t *testing.T) {
	cases := []struct {
		ask, role, want string
	}{
		{"full", "admin", "full"},
		{"full", "operator", "operator"}, // capped: full requires admin
		{"full", "viewer", "readonly"},   // capped twice
		{"operator", "operator", "operator"},
		{"operator", "viewer", "readonly"}, // capped
		{"readonly", "viewer", "readonly"},
		{"garbage", "admin", "readonly"}, // unknown fails safe
		{"", "admin", "readonly"},
	}
	for _, c := range cases {
		if got := ProfileFor(c.ask, c.role); got != c.want {
			t.Fatalf("ProfileFor(%q,%q) = %q, want %q", c.ask, c.role, got, c.want)
		}
	}
}

// newService builds a Service over an in-memory store with a fake in-process
// API (tools resolve against a stub router; the API-level tests exercise
// the real REST path).
func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	_ = stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	api := mcp.NewLocalAPI(http.NotFoundHandler())
	return New(st, api, nil, log.New(io.Discard, "as: ", 0)), st
}

// TestRunTurnBudget verifies the tool-call cap fires and is reported.
func TestRunTurnBudget(t *testing.T) {
	svc, st := newService(t)
	// Configure a tiny budget and a script that loops on tool calls.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = writeScripted(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"list_hosts","arguments":"{}"}}]}}]}`)
	}))
	t.Cleanup(fake.Close)
	if err := svc.SaveConfig(&ConfigView{BaseURL: fake.URL, Model: "m", MaxToolCalls: 2, TimeoutS: 30, DefaultProfile: ProfileReadonly, Enabled: true}, ""); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	ss, err := svc.CreateSession("u", "admin", ProfileReadonly)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	var events []Event
	err = svc.RunTurn(context.Background(), ss.ID, "loop forever", "tok", "u", "admin", func(ev Event) { events = append(events, ev) })
	if err != nil {
		t.Fatalf("RunTurn: %v", err)
	}
	var budget bool
	for _, ev := range events {
		if ev.Type == "error" && strings.Contains(ev.Content, "budget") {
			budget = true
		}
	}
	if !budget {
		t.Fatalf("no budget error event (events: %+v)", events)
	}
	// The tool ran exactly MaxToolCalls times (transcript tool rows).
	msgs, _ := st.ListAssistantMessages(ss.ID)
	var toolRows int
	for _, m := range msgs {
		if m.Role == "tool" {
			toolRows++
		}
	}
	if toolRows != 2 {
		t.Fatalf("tool rows = %d, want 2 (the cap)", toolRows)
	}
}

// TestRunTurnCancel verifies Cancel aborts the in-flight turn.
func TestRunTurnCancel(t *testing.T) {
	svc, _ := newService(t)
	block := make(chan struct{})
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hold the first chat completion
		_ = writeScripted(w, `{"choices":[{"message":{"role":"assistant","content":"late"}}]}`)
	}))
	t.Cleanup(fake.Close)
	if err := svc.SaveConfig(&ConfigView{BaseURL: fake.URL, Model: "m", MaxToolCalls: 5, TimeoutS: 30, DefaultProfile: ProfileReadonly, Enabled: true}, ""); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	ss, _ := svc.CreateSession("u", "admin", ProfileReadonly)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- svc.RunTurn(ctx, ss.ID, "hi", "tok", "u", "admin", func(ev Event) {})
	}()
	time.Sleep(100 * time.Millisecond)
	svc.Cancel(ss.ID) // cancels via the active-turn map
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunTurn after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("cancel did not stop the turn")
	}
	close(block)
}

// TestRunTurnOwnerOnly verifies a non-owner cannot turn someone's session.
func TestRunTurnOwnerOnly(t *testing.T) {
	svc, _ := newService(t)
	if err := svc.SaveConfig(&ConfigView{BaseURL: "http://x", Model: "m", Enabled: true}, ""); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	ss, _ := svc.CreateSession("alice", "admin", ProfileReadonly)
	err := svc.RunTurn(context.Background(), ss.ID, "hi", "tok", "bob", "admin", func(ev Event) {})
	if err != store.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound (not the owner)", err)
	}
}

func writeScripted(w http.ResponseWriter, body string) error {
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write([]byte(body))
	return err
}
