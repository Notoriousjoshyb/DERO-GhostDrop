// Package wallet connects Ghostdrop to the user's DERO wallet over its local
// RPC interface (wallet-RPC / XSWD JSON-RPC envelope, see internal/dero).
//
// Safety rules, enforced by construction:
//
//   - The wallet is never given credentials and no seed/key is persisted here.
//   - Signing only asks the wallet to sign; approval happens wallet-side.
//   - Spending NEVER happens implicitly: Pay requires confirm=true, and
//     without it Pay fails with ErrConfirmRequired (exposing the preview)
//     having sent zero RPC calls. Call Preview first, show it to the user,
//     then call Pay with their explicit confirmation.
package wallet

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ghostdrop/internal/dero"
)

// ErrConfirmRequired is returned by Pay when confirm=false. It wraps as
// *ConfirmError carrying the exact preview the user must approve.
var ErrConfirmRequired = errors.New("wallet: explicit payment confirmation required")

// DefaultFeeAtomic is the fallback fee estimate in atomic units when the
// caller passes fee=0 to Preview/Pay. Informational only; the wallet applies
// its own real fee policy.
const DefaultFeeAtomic uint64 = 1000000000 // 0.001 DERO at 1e12 units/DERO

const defaultTimeout = 10 * time.Second

// Config tunes a Connector.
type Config struct {
	// Endpoint is the wallet-RPC base URL, e.g. "http://127.0.0.1:10103".
	Endpoint string
	// Timeout applies when ctx carries no deadline. Zero selects 10s.
	Timeout time.Duration
}

// Connector talks to one wallet endpoint. It holds no keys and no state
// beyond configuration.
type Connector struct {
	cfg Config
}

// New builds a Connector for endpoint.
func New(endpoint string) *Connector {
	return &Connector{cfg: Config{Endpoint: endpoint}}
}

// NewWithConfig builds a Connector from a full Config.
func NewWithConfig(cfg Config) *Connector {
	return &Connector{cfg: cfg}
}

// Endpoint returns the configured wallet-RPC base URL.
func (c *Connector) Endpoint() string {
	return c.cfg.Endpoint
}

func (c *Connector) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	to := c.cfg.Timeout
	if to <= 0 {
		to = defaultTimeout
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, to)
}

// Status probes the wallet. Transport failure yields (false, ErrOffline).
func (c *Connector) Status(ctx context.Context) (bool, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return dero.WalletStatus(ctx, c.cfg.Endpoint)
}

// Connect verifies the wallet is reachable; offline yields ErrOffline.
func (c *Connector) Connect(ctx context.Context) error {
	online, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !online {
		return fmt.Errorf("wallet: connect %s: %w", c.cfg.Endpoint, dero.ErrOffline)
	}
	return nil
}

// Sign asks the wallet to sign msg and returns (sigHex, pubHex).
// Approval happens wallet-side; nothing is stored here.
func (c *Connector) Sign(ctx context.Context, msg []byte) (sigHex, pubHex string, err error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return dero.SignWithWallet(ctx, c.cfg.Endpoint, msg)
}

// PaymentPreview is the user-facing quote shown BEFORE any spend. Total is
// Amount+Fee; Confirmed echoes whether the user approved it.
type PaymentPreview struct {
	Destination string
	Amount      uint64 // atomic units
	Fee         uint64 // atomic units (estimate)
	Total       uint64 // Amount + Fee
	Confirmed   bool
}

// Preview validates and quotes a payment without any network or spend.
func (c *Connector) Preview(dest string, amount, fee uint64) (PaymentPreview, error) {
	if !dero.ValidateAddress(dest) {
		return PaymentPreview{}, fmt.Errorf("wallet: bad destination: %w", dero.ErrInvalidAddress)
	}
	if amount == 0 {
		return PaymentPreview{}, fmt.Errorf("wallet: amount must be > 0")
	}
	if fee == 0 {
		fee = DefaultFeeAtomic
	}
	if ^uint64(0)-amount < fee {
		return PaymentPreview{}, fmt.Errorf("wallet: amount+fee overflows")
	}
	return PaymentPreview{Destination: dest, Amount: amount, Fee: fee, Total: amount + fee}, nil
}

// ConfirmError is returned by Pay when confirm=false. It carries the preview
// so the UI can present it; no transfer RPC has been sent at that point.
type ConfirmError struct {
	Preview PaymentPreview
}

func (e *ConfirmError) Error() string {
	return fmt.Sprintf("wallet: payment of %d (+%d fee) to %s needs explicit confirmation: %v",
		e.Preview.Amount, e.Preview.Fee, e.Preview.Destination, ErrConfirmRequired)
}

// Unwrap lets errors.Is(err, ErrConfirmRequired) work.
func (e *ConfirmError) Unwrap() error { return ErrConfirmRequired }

// Pay sends amount (+fee) atomic units to dest, but ONLY when confirm=true.
// With confirm=false it returns *ConfirmError and performs zero RPC calls.
// With confirm=true it relays a single explicit transfer to the wallet, which
// applies its own approval policy.
func (c *Connector) Pay(ctx context.Context, dest string, amount, fee uint64, confirm bool) (txid string, err error) {
	pv, err := c.Preview(dest, amount, fee)
	if err != nil {
		return "", err
	}
	if !confirm {
		return "", &ConfirmError{Preview: pv}
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return dero.TransferWithWallet(ctx, c.cfg.Endpoint, dest, amount, pv.Fee)
}
