// Package sse is the Server-Sent Events broker: a single fan-out point that
// pushes live events (command output, host state, audit, approvals) to
// browsers without polling (PRD R10, arch §10.2). Slow consumers are dropped
// and must reconnect (SSE retry); they never block the broker.
package sse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
)

// Event is a single SSE message.
type Event struct {
	Kind    string
	Payload json.RawMessage
}

// Broker fans out events to subscribed SSE clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[uint64]chan Event
	nextID  uint64
}

// New returns an empty broker.
func New() *Broker {
	return &Broker{clients: make(map[uint64]chan Event)}
}

// Emit broadcasts an event to all connected clients. It never blocks: each
// client's buffer has capacity; if a client's buffer is full it is dropped
// and re-subscribes via SSE retry.
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

	b.mu.RLock()
	dropped := make([]uint64, 0)
	for id, ch := range b.clients {
		select {
		case ch <- ev:
		default:
			dropped = append(dropped, id)
		}
	}
	b.mu.RUnlock()

	if len(dropped) > 0 {
		b.mu.Lock()
		for _, id := range dropped {
			if ch, ok := b.clients[id]; ok {
				close(ch)
				delete(b.clients, id)
			}
		}
		b.mu.Unlock()
	}
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
	ch := make(chan Event, 256)
	b.mu.Lock()
	b.clients[id] = ch
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.clients, id)
		b.mu.Unlock()
	}()

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
