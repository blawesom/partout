package sse

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestEmitAndServe verifies that Emit broadcasts an event that a connected SSE
// client receives.
func TestEmitAndServe(t *testing.T) {
	b := New()
	srv := httptest.NewServer(b)
	defer srv.Close()

	// Connect an SSE client.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept", "text/event-stream")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	// Read the initial "connected" ping, then emit and read the event.
	sc := bufio.NewScanner(resp.Body)
	readEvent := func() (kind string, ok bool) {
		for {
			if !sc.Scan() {
				return "", false
			}
			line := sc.Text()
			if strings.HasPrefix(line, "event: ") {
				return strings.TrimPrefix(line, "event: "), true
			}
		}
	}

	if kind, ok := readEvent(); !ok || kind != "connected" {
		t.Fatalf("first event = %q (ok=%v), want connected", kind, ok)
	}

	// Emit an event from another goroutine (after the client is subscribed).
	time.Sleep(100 * time.Millisecond)
	go func() {
		b.Emit("host.state", map[string]string{"agent_id": "ag_x", "state": "connected"})
	}()

	kind, ok := readEvent()
	if !ok {
		t.Fatal("no event received after Emit")
	}
	if kind != "host.state" {
		t.Fatalf("event = %q, want host.state", kind)
	}
}

// TestEmitNoClients verifies Emit with no clients does not panic.
func TestEmitNoClients(t *testing.T) {
	b := New()
	b.Emit("audit.event", map[string]string{"kind": "exec"})
	b.Emit("audit.event", "raw-string-payload")
	b.Emit("audit.event", nil)
}

// TestSlowClientDropped verifies a full buffer causes the client to be dropped
// (no panic, broker continues).
func TestSlowClientDropped(t *testing.T) {
	b := New()
	srv := httptest.NewServer(b)
	defer srv.Close()

	// Open a client but don't read (buffer fills).
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	// Give the client a moment to subscribe, then stop reading.
	time.Sleep(100 * time.Millisecond)

	// Emit many events; the buffer (256) fills and the client is dropped.
	for i := 0; i < 400; i++ {
		b.Emit("flood", map[string]int{"i": i})
	}

	// Broker must still work for new clients.
	b.Emit("after", map[string]int{"i": 1})
}

// TestEmitRoleGated verifies that an event kind registered with a minimum
// clearance is delivered only to subscribers at or above it (the api package
// gates session.* at operator; viewers must not tap live PTY output).
func TestEmitRoleGated(t *testing.T) {
	b := New()
	b.SetKindMinRole("session.", 2) // operator

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate the api middleware attaching the subscriber's role.
		clearance := 1 // viewer
		if r.URL.Query().Get("as") == "operator" {
			clearance = 2
		}
		b.ServeHTTP(w, ContextWithClearance(r, clearance))
	}))
	defer srv.Close()

	readKind := func(resp *http.Response) string {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "event: ") {
				return strings.TrimPrefix(line, "event: ")
			}
		}
		return ""
	}

	viewerReq, _ := http.NewRequest("GET", srv.URL, nil)
	viewerResp, err := http.DefaultClient.Do(viewerReq)
	if err != nil {
		t.Fatalf("viewer connect: %v", err)
	}
	defer viewerResp.Body.Close()
	if k := readKind(viewerResp); k != "connected" {
		t.Fatalf("viewer first event = %q, want connected", k)
	}

	opReq, _ := http.NewRequest("GET", srv.URL+"?as=operator", nil)
	opResp, err := http.DefaultClient.Do(opReq)
	if err != nil {
		t.Fatalf("operator connect: %v", err)
	}
	defer opResp.Body.Close()
	if k := readKind(opResp); k != "connected" {
		t.Fatalf("operator first event = %q, want connected", k)
	}

	b.Emit("session.data", map[string]string{"chunk": "x"})
	b.Emit("alert.firing", map[string]string{"rule": "r1"})

	// Operator receives both.
	if k := readKind(opResp); k != "session.data" {
		t.Fatalf("operator got %q, want session.data", k)
	}
	if k := readKind(opResp); k != "alert.firing" {
		t.Fatalf("operator got %q, want alert.firing", k)
	}
	// Viewer receives only the ungated kind.
	if k := readKind(viewerResp); k != "alert.firing" {
		t.Fatalf("viewer got %q, want alert.firing (session.data must be filtered)", k)
	}
}
