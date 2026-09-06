package events

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublishSubscribe(t *testing.T) {
	b := NewBus()
	ch, unsub := b.Subscribe(8)
	defer unsub()
	b.Publish(Event{Type: "progress", DropID: "GD-X", Done: 1, Total: 2})
	select {
	case e := <-ch:
		if e.Type != "progress" || e.DropID != "GD-X" {
			t.Fatalf("got %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	b := NewBus()
	ch, unsub := b.Subscribe(1)
	defer unsub()
	for i := range 50 {
		b.Progress("GD-Y", int64(i), 50)
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected at least one event")
	}
}
func TestServeSSEHeaders(t *testing.T) {
	b := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("GET", "/api/events", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { b.ServeSSE(w, r); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE handler did not exit on cancel")
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("bad content type %q", ct)
	}
}
