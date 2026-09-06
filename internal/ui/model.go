// Package ui holds the desktop-app view models, URL helpers, and the
// localhost HTTP server shared by cmd/ghostdrop and tests.
package ui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Drop statuses shown in the UI lists.
const (
	StatusIncoming = "incoming"
	StatusOutgoing = "outgoing"
	StatusExpired  = "expired"
	StatusVerified = "verified"
)

// DropInfo is the JSON-safe view model rendered by the web UI.
// Token is NEVER serialized: it is returned once at creation and then
// only via the clipboard endpoint note flow.
type DropInfo struct {
	ID        string    `json:"id"`
	Recipient string    `json:"recipient,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	Expiry    time.Time `json:"expiry,omitempty"`
	Size      int64     `json:"size_bytes"`
	Uploaded  int64     `json:"uploaded_bytes"`
	Status    string    `json:"status"`
	Verified  bool      `json:"verified"`
	Signed    bool      `json:"signed"`
	CreatedAt time.Time `json:"created_at"`
}

// ClassifyDrop derives the list bucket for a drop.
func ClassifyDrop(expiry time.Time, verified, incoming bool) string {
	if !expiry.IsZero() && time.Now().After(expiry) {
		return StatusExpired
	}
	if verified {
		return StatusVerified
	}
	if incoming {
		return StatusIncoming
	}
	return StatusOutgoing
}

// GhostdropURL returns the ghostdrop:// deep link for a drop id.
func GhostdropURL(id string) string { return "ghostdrop://drop/" + id }

// ParseOpenURL parses a ghostdrop://drop/<id> URL, tolerating the OS
// passing it with different case or surrounding quotes/whitespace.
func ParseOpenURL(s string) (string, error) {
	s = strings.TrimSpace(strings.Trim(s, `"'`))
	if s == "" {
		return "", errors.New("empty url")
	}
	lower := strings.ToLower(s)
	const prefix = "ghostdrop://drop/"
	if !strings.HasPrefix(lower, prefix) {
		return "", fmt.Errorf("unsupported url %q", s)
	}
	id := strings.TrimSpace(s[len(prefix):])
	id = strings.Trim(id, "/")
	if id == "" {
		return "", errors.New("missing drop id")
	}
	return id, nil
}

// ClipboardNote is the timed-clear note shown after copying a token/link.
// The client clears the clipboard after ~30s; the server never stores it.
func ClipboardNote() string {
	return "Copied — clipboard clears in 30s. Never share tokens in chat logs."
}

// QR renders a PNG for content (deep link or https URL).
func QR(content string) ([]byte, error) {
	return qrcode.Encode(content, qrcode.Medium, 256)
}
