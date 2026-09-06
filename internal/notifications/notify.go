// Package notifications delivers desktop notices for drop lifecycle events.
// It always writes a console line and additionally invokes the OS-native
// notifier where available (powershell toast on Windows, notify-send on
// Linux, osascript on macOS). Failures of the native path never fail the
// call. Filenames can be redacted via RedactFilenames. Secrets (keys,
// seeds, tokens) MUST NEVER be passed here.
package notifications

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// Kinds of lifecycle notices.
const (
	KindReceived = "DROP RECEIVED"
	KindComplete = "DROP COMPLETE"
	KindExpiring = "DROP EXPIRING"
	KindFailed   = "DROP FAILED"
)

// Notifier sends desktop notifications.
type Notifier struct {
	mu              sync.Mutex
	RedactFilenames bool
	out             io.Writer
}

// New returns a Notifier writing console lines to out (os.Stdout if nil).
// When redact is true, filenames are replaced with "[redacted]".
func New(redact bool, out io.Writer) *Notifier {
	if out == nil {
		out = os.Stdout
	}
	return &Notifier{RedactFilenames: redact, out: out}
}

// DisplayName returns name or "[redacted]" when redaction is on.
func (n *Notifier) DisplayName(name string) string {
	if n.RedactFilenames {
		return "[redacted]"
	}
	return name
}

// Notify emits kind/title/body via console and the OS-native channel.
func (n *Notifier) Notify(kind, title, body string) {
	n.mu.Lock()
	fmt.Fprintf(n.out, "NOTIFY [%s] %s: %s\n", kind, title, body)
	n.mu.Unlock()
	_ = native(title, body)
}

// DropReceived announces an incoming drop.
func (n *Notifier) DropReceived(dropID, filename string) {
	n.Notify(KindReceived, "Ghostdrop", fmt.Sprintf("Incoming drop %s (%s)", dropID, n.DisplayName(filename)))
}

// Complete announces a finished transfer.
func (n *Notifier) Complete(dropID string) {
	n.Notify(KindComplete, "Ghostdrop", fmt.Sprintf("Drop %s complete", dropID))
}

// Expiring warns a drop is near expiry.
func (n *Notifier) Expiring(dropID string) {
	n.Notify(KindExpiring, "Ghostdrop", fmt.Sprintf("Drop %s expiring soon", dropID))
}

// Failed reports a failed transfer. Reason must be sanitized by the caller.
func (n *Notifier) Failed(dropID, reason string) {
	n.Notify(KindFailed, "Ghostdrop", fmt.Sprintf("Drop %s failed: %s", dropID, reason))
}

func native(title, body string) error {
	switch runtime.GOOS {
	case "windows":
		msg := strings.ReplaceAll(title+" "+body, `"`, "")
		ps := `New-BurntToastNotification -Text @("Ghostdrop", "` + msg + `")`
		if _, err := exec.LookPath("powershell"); err == nil {
			return exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Start()
		}
		return nil
	case "darwin":
		if _, err := exec.LookPath("osascript"); err != nil {
			return nil
		}
		s := strings.ReplaceAll(title+": "+body, `"`, "")
		return exec.Command("osascript", "-e", `display notification "`+s+`" with title "Ghostdrop"`).Start()
	default:
		if _, err := exec.LookPath("notify-send"); err != nil {
			return nil
		}
		return exec.Command("notify-send", "Ghostdrop "+title, body).Start()
	}
}
