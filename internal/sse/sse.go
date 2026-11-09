// Package sse is the Server-Sent Events broker: a single fan-out point that
// pushes live events (command output, host state, audit, approvals) to
// browsers without polling (PRD R10, arch §10.2). Slow consumers are dropped
// and must reconnect (SSE retry); they never block the broker.
//
// Events can be role-gated: SetKindMinRole registers the minimum clearance an
// event kind requires, and Emit skips subscribers below it. The clearance is
// an opaque int (the api package maps its RBAC roles onto ints; higher =
// more privileged). Subscribers without a clearance in the request context
// (direct broker use in tests, single-user local mode) get the maximum, so
// they keep receiving everything.
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Event is a single SSE message.
type Event struct {
	Kind    string
	Payload json.RawMessage
}

// client is one SSE subscriber: its event channel plus the clearance the
// subscriber authenticated with (see ContextWithClearance).
type client struct {
	ch        chan Event
	clearance int
}

// Broker fans out events to subscribed SSE clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[uint64]*client
	nextID  uint64

	// kindMinRole maps an event-kind PREFIX to the minimum clearance. The
	// longest matching prefix wins; unregistered kinds default to 0 (all).
	kindMu      sync.RWMutex
	kindMinRole map[string]int
}

// New returns an empty broker.
func New() *Broker {
	return &Broker{clients: make(map[uint64]*client), kindMinRole: make(map[string]int)}
}

// SetKindMinRole registers the minimum clearance required to receive events
// whose kind starts with prefix (e.g. "session." for live PTY traffic).
func (b *Broker) SetKindMinRole(prefix string, min int) {
	b.kindMu.Lock()
	defer b.kindMu.Unlock()
	b.kindMinRole[prefix] = min
}

// minRoleFor returns the clearance required for an event kind (longest
// registered prefix wins; default 0 = every subscriber).
func (b *Broker) minRoleFor(kind string) int {
	b.kindMu.RLock()
	defer b.kindMu.RUnlock()
	best := 0
	bestLen := -1
	for prefix, min := range b.kindMinRole {
		if len(prefix) > bestLen && strings.HasPrefix(kind, prefix) {
			best, bestLen = min, len(prefix)
		}
	}
	return best
}

// Emit broadcasts an event to all connected clients whose clearance allows
// it. It never blocks: each client's buffer has capacity; if a client's
// buffer is full it is dropped and re-subscribes via SSE retry.
func (b *Broker) Emit(kind string, payload any) {
	var raw json.RawMessage
	if payload == nil {
		raw = json.RawMessage("null")
	} else if rm, ok := payload.(json.RawMessage); ok {
		raw = rm
	} else if rm2, ok := payload.(string); ok {
		raw = json.RawMessage(rm2)
	} else {
		enc, err := json.Marshal(payload)
		if err != nil {
			return
		}
		raw = enc
	}
	ev := Event{Kind: kind, Payload: raw}
	need := b.minRoleFor(kind)

	b.mu.RLock()
	dropped := make([]uint64, 0)
	for id, c := range b.clients {
		if c.clearance < need {
			continue // role-gated event: not for this subscriber
		}
		select {
		case c.ch <- ev:
		default:
			dropped = append(dropped, id)
		}
	}
	b.mu.RUnlock()

	if len(dropped) > 0 {
		b.mu.Lock()
		for _, id := range dropped {
			if c, ok := b.clients[id]; ok {
				close(c.ch)
				delete(b.clients, id)
			}
		}
		b.mu.Unlock()
	}
}

// clearanceCtxKey carries the subscriber's clearance through the request.
type clearanceCtxKey struct{}

// ContextWithClearance returns r with the subscriber clearance attached; the
// broker's ServeHTTP reads it when subscribing.
func ContextWithClearance(r *http.Request, clearance int) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clearanceCtxKey{}, clearance))
}

// ClearanceFrom returns the clearance attached to r, or the maximum when none
// is set (direct broker use, single-user local mode → receive everything).
func ClearanceFrom(r *http.Request) int {
	if v, ok := r.Context().Value(clearanceCtxKey{}).(int); ok {
		return v
	}
	return int(^uint(0) >> 1) // max int
}

// ServeHTTP handles GET /api/v1/events — the single SSE stream (PRD R10).
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	id := atomic.AddUint64(&b.nextID, 1)
	c := &client{ch: make(chan Event, 256), clearance: ClearanceFrom(r)}
	b.mu.Lock()
	b.clients[id] = c
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.clients, id)
		b.mu.Unlock()
	}()

	ch := c.ch

	// Initial "connected" ping.
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	clientGone := r.Context().Done()
	for {
		select {
		case <-clientGone:
			return
		case ev, ok := <-ch:
			if !ok {
				return // broker dropped us
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, ev.Payload)
			flusher.Flush()
		}
	}
}
