package ui

import (
	"strings"
	"testing"
	"time"
)

func TestGhostdropURL(t *testing.T) {
	if got := GhostdropURL("GD-ABC"); got != "ghostdrop://drop/GD-ABC" {
		t.Fatalf("got %q", got)
	}
}

func TestParseOpenURL(t *testing.T) {
	id, err := ParseOpenURL("ghostdrop://drop/GD-ABC123")
	if err != nil || id != "GD-ABC123" {
		t.Fatalf("got %q %v", id, err)
	}
	if _, err := ParseOpenURL("https://example.com"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseOpenURL("ghostdrop://drop/"); err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestClassifyDrop(t *testing.T) {
	if got := ClassifyDrop(time.Now().Add(-time.Hour), false, false); got != StatusExpired {
		t.Fatalf("got %q", got)
	}
	if got := ClassifyDrop(time.Now().Add(time.Hour), true, false); got != StatusVerified {
		t.Fatalf("got %q", got)
	}
	if got := ClassifyDrop(time.Now().Add(time.Hour), false, true); got != StatusIncoming {
		t.Fatalf("got %q", got)
	}
	if got := ClassifyDrop(time.Now().Add(time.Hour), false, false); got != StatusOutgoing {
		t.Fatalf("got %q", got)
	}
}

func TestClipboardNote(t *testing.T) {
	n := ClipboardNote()
	if !strings.Contains(n, "30s") {
		t.Fatalf("note missing timed-clear: %q", n)
	}
}
