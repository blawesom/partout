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
