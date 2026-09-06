// Package storage defines the Provider interface for encrypted-payload
// backends plus the built-in implementations (memory, local filesystem,
// relay) and the name registry.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Backend names accepted by Open (case-insensitive).
const (
	BackendMemory = "memory"
	BackendLocal  = "local"
	BackendRelay  = "relay"
)

// Provider stores opaque encrypted blobs keyed by drop ID.
type Provider interface {
	Put(ctx context.Context, id string, r io.Reader, size int64, expiry time.Time) error
	Get(ctx context.Context, id string, offset int64) (io.ReadCloser, error)
	Delete(ctx context.Context, id string) error
	Exists(ctx context.Context, id string) (bool, error)
	Stat(ctx context.Context, id string) (size int64, expiry time.Time, err error)
	Health(ctx context.Context) error
	Backend() string
}

// Errors returned by providers.
var (
	ErrNotFound = errors.New("storage: not found")
	ErrExpired  = errors.New("storage: expired")
	ErrQuota    = errors.New("storage: quota exceeded")
)

// DefaultQuotaBytes bounds memory/local providers (1 GiB total each).
const DefaultQuotaBytes = int64(1 << 30)

// Options configures Open.
type Options struct {
	// DataDir roots the local provider (<DataDir>/drops).
	DataDir string
	// RelayURL is the relay base URL for the relay provider.
	RelayURL string
	// Token is the per-drop relay token (X-Ghostdrop-Token).
	Token string
	// QuotaBytes caps stored bytes; <=0 selects DefaultQuotaBytes.
	QuotaBytes int64
}

// Open returns the provider named LOCAL, RELAY, or MEMORY.
func Open(name string, opts Options) (Provider, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "MEMORY":
		q := opts.QuotaBytes
		if q <= 0 {
			q = DefaultQuotaBytes
		}
		return NewMemoryProvider(q), nil
	case "LOCAL":
		q := opts.QuotaBytes
		if q <= 0 {
			q = DefaultQuotaBytes
		}
		return NewLocalProvider(opts.DataDir, q)
	case "RELAY":
		if opts.RelayURL == "" {
			return nil, fmt.Errorf("storage: relay provider needs RelayURL")
		}
		return NewRelayClient(opts.RelayURL, opts.Token), nil
	default:
		return nil, fmt.Errorf("storage: unknown provider %q", name)
	}
}

// ValidateID rejects empty IDs and path-traversal attempts.
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("storage: empty id")
	}
	for _, r := range id {
		ok := r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		if !ok {
			return fmt.Errorf("storage: bad id %q", id)
		}
	}
	if id == "." || id == ".." {
		return fmt.Errorf("storage: bad id %q", id)
	}
	return nil
}
