package payments

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ghostdrop/internal/dero"
)

const pAddr = "dero1q" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef"

type txRec struct {
	address       string
	amount        uint64
	confirmations uint64
}

type fakeDaemon struct {
	mu     sync.Mutex
	txs    map[string]txRec
	method map[string]int
}

func newFakeDaemon(t *testing.T, txs map[string]txRec) (*fakeDaemon, *httptest.Server) {
	t.Helper()
	fd := &fakeDaemon{txs: txs, method: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		fd.mu.Lock()
		fd.method[req.Method]++
		fd.mu.Unlock()
		ok := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": result})
		}
		fail := func(code int, msg string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": code, "message": msg}})
		}
		var p map[string]any
		_ = json.Unmarshal(req.Params, &p)
		switch req.Method {
		case "get_transaction":
			tx, found := fd.txs[p["txid"].(string)]
			if !found {
				fail(-32004, "tx not found")
				return
			}
			ok(map[string]any{"txid": p["txid"], "address": tx.address, "amount": tx.amount, "confirmations": tx.confirmations})
		default:
			fail(-32601, "unknown method")
		}
	}))
	t.Cleanup(srv.Close)
	return fd, srv
}

func (fd *fakeDaemon) sawSpend() bool {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	for m := range fd.method {
		if m == "transfer" || m == "sign_data" {
			return true
		}
	}
	return false
}

func TestCreateRequestValidation(t *testing.T) {
	if _, err := CreateRequest("", 100, pAddr); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty drop err = %v", err)
	}
	if _, err := CreateRequest("drop1", 0, pAddr); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero amount err = %v", err)
	}
	if _, err := CreateRequest("drop1", 100, "bogus"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad addr err = %v", err)
	}
	r, err := CreateRequest("drop1", 100, pAddr)
	if err != nil || r.Status != StatusPending || r.IsAuthorized() {
		t.Fatalf("new request = %+v,%v", r, err)
	}
	if err := r.AttachTxid(""); err == nil {
		t.Fatal("empty txid must fail")
	}
	if err := r.AttachTxid("tx-paid"); err != nil {
		t.Fatal(err)
	}
}

func TestAwaitPaymentConfirmed(t *testing.T) {
	fd, srv := newFakeDaemon(t, map[string]txRec{
		"tx-paid": {address: pAddr, amount: 1000, confirmations: 25},
	})
	r, _ := CreateRequest("drop1", 1000, pAddr)
	_ = r.AttachTxid("tx-paid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.AwaitPayment(ctx, srv.URL, 5*time.Millisecond); err != nil {
		t.Fatalf("await = %v", err)
	}
	if !r.IsAuthorized() {
		t.Fatal("confirmed payment must authorize")
	}
	if fd.sawSpend() {
		t.Fatal("poller must only read (get_transaction); never spend")
	}
}

func TestAwaitPaymentUnconfirmedTimesOut(t *testing.T) {
	_, srv := newFakeDaemon(t, map[string]txRec{
		"tx-shallow": {address: pAddr, amount: 1000, confirmations: 2},
	})
	r, _ := CreateRequest("drop1", 1000, pAddr)
	_ = r.AttachTxid("tx-shallow")
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := r.AwaitPayment(ctx, srv.URL, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("await err = %v; want context.DeadlineExceeded", err)
	}
	if r.IsAuthorized() {
		t.Fatal("unconfirmed payment must not authorize")
	}
}

func TestAwaitPaymentUnknownTxidKeepsPolling(t *testing.T) {
	_, srv := newFakeDaemon(t, map[string]txRec{})
	r, _ := CreateRequest("drop1", 1000, pAddr)
	_ = r.AttachTxid("tx-future")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := r.AwaitPayment(ctx, srv.URL, 5*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unknown tx must poll till ctx ends, err = %v", err)
	}
}

func TestAwaitPaymentOfflineKeepsPolling(t *testing.T) {
	_, srv := newFakeDaemon(t, map[string]txRec{})
	url := srv.URL
	srv.Close() // daemon gone: graceful offline, poll till ctx ends
	r, _ := CreateRequest("drop1", 1000, pAddr)
	_ = r.AttachTxid("tx-paid")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := r.AwaitPayment(ctx, url, 5*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("offline must poll till ctx ends, err = %v", err)
	}
	if r.IsAuthorized() {
		t.Fatal("offline must never authorize")
	}
}

func TestAwaitPaymentNeedsTxid(t *testing.T) {
	r, _ := CreateRequest("drop1", 1000, pAddr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.AwaitPayment(ctx, "http://127.0.0.1:9", 0); !errors.Is(err, ErrNoTxid) {
		t.Fatalf("err = %v; want ErrNoTxid", err)
	}
}

func TestAuthorizePaths(t *testing.T) {
	_, srv := newFakeDaemon(t, map[string]txRec{
		"tx-paid":    {address: pAddr, amount: 1000, confirmations: 15},
		"tx-shallow": {address: pAddr, amount: 1000, confirmations: 1},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, _ := CreateRequest("drop1", 1000, pAddr)
	_ = r.AttachTxid("tx-paid")
	if err := r.Authorize(ctx, srv.URL); err != nil {
		t.Fatalf("authorize confirmed = %v", err)
	}
	if !r.IsAuthorized() {
		t.Fatal("must be authorized")
	}

	r2, _ := CreateRequest("drop2", 1000, pAddr)
	_ = r2.AttachTxid("tx-shallow")
	if err := r2.Authorize(ctx, srv.URL); !errors.Is(err, ErrNotPaid) {
		t.Fatalf("unconfirmed authorize err = %v; want ErrNotPaid", err)
	}

	r3, _ := CreateRequest("drop3", 1000, pAddr)
	_ = r3.AttachTxid("tx-missing")
	if err := r3.Authorize(ctx, srv.URL); !errors.Is(err, ErrNotPaid) {
		t.Fatalf("unknown tx authorize err = %v; want ErrNotPaid", err)
	}

	r4, _ := CreateRequest("drop4", 1000, pAddr)
	if err := r4.Authorize(ctx, srv.URL); !errors.Is(err, ErrNoTxid) {
		t.Fatalf("no-txid authorize err = %v; want ErrNoTxid", err)
	}
}

func TestAuthorizeOfflineNeverPaid(t *testing.T) {
	_, srv := newFakeDaemon(t, nil)
	url := srv.URL
	srv.Close()
	r, _ := CreateRequest("drop1", 1000, pAddr)
	_ = r.AttachTxid("tx-paid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := r.Authorize(ctx, url)
	if !dero.IsOffline(err) {
		t.Fatalf("offline authorize err = %v; want ErrOffline, never paid", err)
	}
	if r.IsAuthorized() {
		t.Fatal("offline must never authorize")
	}
}

func TestNeverAutoSpendGuard(t *testing.T) {
	// Compile-time proof lives in the import list (dero only, no wallet).
	// Runtime proof: full flow emits zero spend RPCs.
	fd, srv := newFakeDaemon(t, map[string]txRec{
		"tx-paid": {address: pAddr, amount: 500, confirmations: 11},
	})
	r, err := CreateRequest("dropX", 500, pAddr)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.AttachTxid("tx-paid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Authorize(ctx, srv.URL); err != nil {
		t.Fatal(err)
	}
	if fd.sawSpend() {
		t.Fatal("payments flow must never call transfer/sign")
	}
	if !strings.HasPrefix(string(r.Status), "auth") {
		t.Fatalf("status = %q", r.Status)
	}
}
