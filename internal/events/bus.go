// Package events provides a lightweight in-process pub/sub progress bus.
// The desktop server publishes upload/download progress here and fans out
// to browsers over SSE at /api/events.
package events

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Event is a single progress/status update.
type Event struct {
	Type    string    `json:"type"`
	DropID  string    `json:"drop_id,omitempty"`
	Done    int64     `json:"done,omitempty"`
	Total   int64     `json:"total,omitempty"`
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

// Bus fans events out to any number of subscribers.
type Bus struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

// NewBus returns an empty Bus.
func NewBus() *Bus { return &Bus{subs: make(map[chan Event]struct{})} }

// Subscribe returns a channel receiving published events plus an
// unsubscribe func. Buffer controls drop-vs-block behaviour: when a
// subscriber lags and its buffer is full the event is dropped for that
// subscriber so a slow browser can never stall uploads.
func (b *Bus) Subscribe(buffer int) (<-chan Event, func()) {
	if buffer <= 0 {
		buffer = 32
	}
	ch := make(chan Event, buffer)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	once := sync.Once{}
	unsub := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			close(ch)
			b.mu.Unlock()
		})
	}
	return ch, unsub
}

// Publish delivers e to all current subscribers (non-blocking).
func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Progress publishes a progress update for a drop.
func (b *Bus) Progress(dropID string, done, total int64) {
	b.Publish(Event{Type: "progress", DropID: dropID, Done: done, Total: total})
}

// Status publishes a lifecycle message (received, complete, expiring, failed).
func (b *Bus) Status(typ, dropID, msg string) {
	b.Publish(Event{Type: typ, DropID: dropID, Message: msg})
}

// ServeSSE streams events as Server-Sent Events. It flushes headers
// immediately, sends a hello comment, then forwards bus events until the
// client disconnects.
func (b *Bus) ServeSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, ": hello\n\n")
	fl.Flush()
	ch, unsub := b.Subscribe(64)
	defer unsub()
	keep := time.NewTicker(25 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			fmt.Fprintf(w, "event: %s\n", e.Type)
			fmt.Fprintf(w, "data: {\"type\":%q,\"drop_id\":%q,\"done\":%d,\"total\":%d,\"message\":%q}\n\n",
				e.Type, e.DropID, e.Done, e.Total, e.Message)
			fl.Flush()
		case <-keep.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}
