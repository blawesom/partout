package session

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type resultCh struct {
	mu     sync.Mutex
	states map[string]string
	notify chan string
}

func newResultCh() *resultCh {
	return &resultCh{states: make(map[string]string), notify: make(chan string, 16)}
}

func (r *resultCh) fn(sessionID string, exitCode int32, state string, durationMs int64) {
	r.mu.Lock()
	r.states[sessionID] = state
	r.mu.Unlock()
	select {
	case r.notify <- state:
	default:
	}
}

func (r *resultCh) waitResult(timeout time.Duration) string {
	select {
	case got := <-r.notify:
		return got
	case <-time.After(timeout):
		return ""
	}
}

func (r *resultCh) snapshot() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.states))
	for k, v := range r.states {
		out[k] = v
	}
	return out
}

func TestOpenAndRun(t *testing.T) {
	rc := newResultCh()
	m := NewManager(rc.fn)
	defer m.KillAll()

	var mu sync.Mutex
	var output strings.Builder
	err := m.Open("s1", "echo", []string{"hello"}, nil, 80, 24, func(sessionID string, data []byte) {
		mu.Lock()
		output.Write(data)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if m.Active() != 1 {
		t.Fatalf("active = %d, want 1", m.Active())
	}

	got := rc.waitResult(3 * time.Second)
	if got != "succeeded" {
		t.Fatalf("result = %q, want succeeded (states: %v)", got, rc.snapshot())
	}
	mu.Lock()
	out := output.String()
	mu.Unlock()
	if !strings.Contains(out, "hello") {
		t.Fatalf("output = %q, want hello", out)
	}
}

func TestSessionInput(t *testing.T) {
	rc := newResultCh()
	m := NewManager(rc.fn)
	defer m.KillAll()

	var mu sync.Mutex
	var output strings.Builder
	err := m.Open("s1", "cat", nil, nil, 80, 24, func(sessionID string, data []byte) {
		mu.Lock()
		output.Write(data)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("open cat: %v", err)
	}

	if err := m.Input("s1", []byte("hi\n")); err != nil {
		t.Fatalf("input: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		got := output.String()
		mu.Unlock()
		if strings.Contains(got, "hi") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("output = %q, want hi", got)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := m.Close("s1"); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := rc.waitResult(5 * time.Second); got != "closed" {
		t.Fatalf("result = %q, want closed (states: %v)", got, rc.snapshot())
	}
}

func TestSessionResize(t *testing.T) {
	rc := newResultCh()
	m := NewManager(rc.fn)
	defer m.KillAll()

	if err := m.Open("s1", "echo", []string{"ok"}, nil, 80, 24, func(sessionID string, data []byte) {}); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := m.Resize("s1", 120, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if err := m.Resize("missing", 120, 40); err == nil {
		t.Fatal("expected error resizing unknown session")
	}
	if err := m.Input("missing", []byte("x")); err == nil {
		t.Fatal("expected error writing to unknown session")
	}
	_ = m.Close("s1")
}

func TestSessionKillAll(t *testing.T) {
	rc := newResultCh()
	m := NewManager(rc.fn)

	if err := m.Open("s1", "sleep", []string{"30"}, nil, 80, 24, func(sessionID string, data []byte) {}); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := m.Open("s2", "sleep", []string{"30"}, nil, 80, 24, func(sessionID string, data []byte) {}); err != nil {
		t.Fatalf("open s2: %v", err)
	}
	if m.Active() != 2 {
		t.Fatalf("active = %d, want 2", m.Active())
	}

	if n := m.KillAll(); n != 2 {
		t.Fatalf("killed = %d, want 2", n)
	}
	if m.Active() != 0 {
		t.Fatalf("active = %d, want 0 after KillAll", m.Active())
	}

	var gotStates []string
	deadline := time.Now().Add(3 * time.Second)
	for len(gotStates) < 2 && time.Now().Before(deadline) {
		if s := rc.waitResult(time.Until(deadline)); s != "" {
			gotStates = append(gotStates, s)
		}
	}
	if len(gotStates) != 2 {
		t.Fatalf("results = %d, want 2 (states: %v)", len(gotStates), rc.snapshot())
	}
	for _, s := range gotStates {
		if s != "interrupted" {
			t.Fatalf("state = %q, want interrupted", s)
		}
	}
}

func TestCloseInterrupted(t *testing.T) {
	rc := newResultCh()
	m := NewManager(rc.fn)
	defer m.KillAll()

	if err := m.Open("s1", "sleep", []string{"30"}, nil, 80, 24, func(sessionID string, data []byte) {}); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := m.Close("s1"); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := rc.waitResult(5 * time.Second); got != "closed" {
		t.Fatalf("state = %q, want closed (all: %v)", got, rc.snapshot())
	}
}

func TestOpenBadCommand(t *testing.T) {
	m := NewManager(func(sessionID string, exitCode int32, state string, durationMs int64) {})
	defer m.KillAll()
	err := m.Open("s1", "/no/such/binary", nil, nil, 80, 24, func(sessionID string, data []byte) {})
	if err == nil {
		t.Fatal("expected error for bad command")
	}
}

func TestOpenDuplicateSession(t *testing.T) {
	m := NewManager(func(sessionID string, exitCode int32, state string, durationMs int64) {})
	defer m.KillAll()
	if err := m.Open("s1", "sleep", []string{"30"}, nil, 80, 24, func(sessionID string, data []byte) {}); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := m.Open("s1", "sleep", []string{"30"}, nil, 80, 24, func(sessionID string, data []byte) {}); err == nil {
		t.Fatal("expected error for duplicate session id")
	}
}
