// Package payments implements the PaidDrop receiver flow: a drop carries a
// price, the payer sends it with their own wallet, and Ghostdrop unlocks the
// wrapped file key only after the chain confirms payment.
//
// Flow: CreateRequest -> AttachTxid -> AwaitPayment (poll) -> Authorize.
// Authorize flips the request to StatusAuthorized; only then may the caller
// unwrap the file key. There is deliberately NO path from this package to a
// spend: it imports internal/dero read-only RPCs only (get_transaction) and
// must never import internal/wallet. AwaitPayment treats "unknown tx" and
// "daemon offline" as pending and keeps polling until ctx ends (graceful
// offline); any other error aborts.
package payments

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"ghostdrop/internal/dero"
)

var (
	// ErrInvalidRequest marks requests that fail validation.
	ErrInvalidRequest = errors.New("payments: invalid request")
	// ErrNoTxid means no payer transaction was attached yet.
	ErrNoTxid = errors.New("payments: no transaction attached")
	// ErrNotPaid means the payment is not (yet) confirmed on chain.
	ErrNotPaid = errors.New("payments: payment not confirmed")
)

// Status is the lifecycle state of a payment request.
type Status string

const (
	// StatusPending awaits chain confirmation.
	StatusPending Status = "pending"
	// StatusAuthorized passed Authorize; the wrapped key may now be released.
	StatusAuthorized Status = "authorized"
)

// DefaultPollInterval paces AwaitPayment when the caller passes interval<=0.
const DefaultPollInterval = 5 * time.Second

// Request tracks one paid-drop expectation. Use CreateRequest to build it.
type Request struct {
	DropID    string
	Amount    uint64 // atomic units expected
	Address   string // receiver address the payer must pay
	CreatedAt time.Time
	Txid      string
	Status    Status

	mu sync.Mutex
}

// CreateRequest validates and records the expectation {dropID, amount,
// address}. Amounts are atomic units; the address must pass dero validation.
func CreateRequest(dropID string, amount uint64, address string) (*Request, error) {
	dropID = strings.TrimSpace(dropID)
	if dropID == "" {
		return nil, fmt.Errorf("%w: empty drop id", ErrInvalidRequest)
	}
	if amount == 0 {
		return nil, fmt.Errorf("%w: amount must be > 0", ErrInvalidRequest)
	}
	if !dero.ValidateAddress(address) {
		return nil, fmt.Errorf("%w: bad address: %v", ErrInvalidRequest, dero.ErrInvalidAddress)
	}
	return &Request{
		DropID:    dropID,
		Amount:    amount,
		Address:   strings.TrimSpace(address),
		CreatedAt: time.Now().UTC(),
		Status:    StatusPending,
	}, nil
}

// AttachTxid records the payer's transaction id (non-empty).
func (r *Request) AttachTxid(txid string) error {
	txid = strings.TrimSpace(txid)
	if txid == "" {
		return fmt.Errorf("%w: empty txid", ErrInvalidRequest)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Txid = txid
	return nil
}

// IsAuthorized reports whether Authorize (or a confirmed AwaitPayment) ran.
func (r *Request) IsAuthorized() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Status == StatusAuthorized
}

func (r *Request) snapshot() (txid, addr string, amount uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Txid, r.Address, r.Amount
}

func (r *Request) markAuthorized() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Status = StatusAuthorized
}

// AwaitPayment polls dero.CheckPayment until the payment confirms or ctx
// ends. Unknown transactions and offline daemons are pending (keeps polling);
// other errors abort. On success the request is authorized.
func (r *Request) AwaitPayment(ctx context.Context, daemonEndpoint string, interval time.Duration) error {
	txid, addr, amount := r.snapshot()
	if txid == "" {
		return ErrNoTxid
	}
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		confirmed, err := dero.CheckPayment(ctx, daemonEndpoint, txid, addr, amount)
		if err == nil && confirmed {
			r.markAuthorized()
			return nil
		}
		if err != nil && !errors.Is(err, dero.ErrTxNotFound) && !dero.IsOffline(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Authorize performs a single confirmation check and, only on success, marks
// the request authorized — the gate for releasing the wrapped file key.
// Unconfirmed or still-unknown payments yield ErrNotPaid; an unreachable
// daemon yields ErrOffline (unknown, never "paid").
func (r *Request) Authorize(ctx context.Context, daemonEndpoint string) error {
	txid, addr, amount := r.snapshot()
	if txid == "" {
		return ErrNoTxid
	}
	confirmed, err := dero.CheckPayment(ctx, daemonEndpoint, txid, addr, amount)
	if err != nil {
		if errors.Is(err, dero.ErrTxNotFound) {
			return fmt.Errorf("%w: drop %s tx unknown", ErrNotPaid, r.DropID)
		}
		return err
	}
	if !confirmed {
		return fmt.Errorf("%w: drop %s", ErrNotPaid, r.DropID)
	}
	r.markAuthorized()
	return nil
}
