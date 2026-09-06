package wallet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"ghostdrop/internal/dero"
)

const wAddr = "dero1q" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef"

type fakeWallet struct {
	mu        sync.Mutex
	transfers int
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
}

func newFakeWallet(t *testing.T) (*fakeWallet, *httptest.Server) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fw := &fakeWallet{pub: pub, priv: priv}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		ok := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": result})
		}
		switch req.Method {
		case "get_version":
			ok(map[string]any{"status": "OK", "version": "v-test"})
		case "sign_data":
			var p struct {
				Data string `json:"data"`
			}
			_ = json.Unmarshal(req.Params, &p)
			raw, _ := hex.DecodeString(p.Data)
			ok(map[string]any{
				"signature":  hex.EncodeToString(ed25519.Sign(fw.priv, raw)),
				"public_key": hex.EncodeToString(fw.pub),
			})
		case "transfer":
			fw.mu.Lock()
			fw.transfers++
			fw.mu.Unlock()
			ok(map[string]any{"tx_hash": "wallettx01"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": -32601, "message": "nope"}})
		}
	}))
	t.Cleanup(srv.Close)
	return fw, srv
}

func (fw *fakeWallet) count() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return fw.transfers
}

func TestStatusAndConnect(t *testing.T) {
	_, srv := newFakeWallet(t)
	c := New(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	online, err := c.Status(ctx)
	if err != nil || !online {
		t.Fatalf("status = %v,%v", online, err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect = %v", err)
	}
	if c.Endpoint() != srv.URL {
		t.Fatal("Endpoint mismatch")
	}
}

func TestConnectOffline(t *testing.T) {
	_, srv := newFakeWallet(t)
	url := srv.URL
	srv.Close()
	c := New(url)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); !errors.Is(err, dero.ErrOffline) {
		t.Fatalf("offline connect err = %v; want ErrOffline", err)
	}
}

func TestSignRoundtrip(t *testing.T) {
	_, srv := newFakeWallet(t)
	c := New(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := []byte("ghostdrop auth")
	sigHex, pubHex, err := c.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(sigHex)
	if !dero.VerifyWithPub(pubHex, msg, sig) {
		t.Fatal("wallet signature did not verify")
	}
}

func TestPreview(t *testing.T) {
	c := New("http://127.0.0.1:9")
	pv, err := c.Preview(wAddr, 1000, 50)
	if err != nil {
		t.Fatal(err)
	}
	if pv.Total != 1050 || pv.Confirmed {
		t.Fatalf("preview = %+v", pv)
	}
	if _, err := c.Preview(wAddr, 1000, 0); err != nil {
		t.Fatalf("zero fee should use default: %v", err)
	}
	if _, err := c.Preview("bogus", 1000, 1); !errors.Is(err, dero.ErrInvalidAddress) {
		t.Fatalf("bad dest err = %v", err)
	}
	if _, err := c.Preview(wAddr, 0, 1); err == nil {
		t.Fatal("zero amount must fail")
	}
	if _, err := c.Preview(wAddr, ^uint64(0), 1); err == nil {
		t.Fatal("overflow must fail")
	}
}

func TestPayRequiresExplicitConfirm(t *testing.T) {
	fw, srv := newFakeWallet(t)
	c := New(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.Pay(ctx, wAddr, 1000, 50, false)
	if !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("unconfirmed pay err = %v; want ErrConfirmRequired", err)
	}
	var ce *ConfirmError
	if !errors.As(err, &ce) {
		t.Fatalf("err type = %T; want *ConfirmError", err)
	}
	if ce.Preview.Total != 1050 {
		t.Fatalf("preview in error = %+v", ce.Preview)
	}
	if n := fw.count(); n != 0 {
		t.Fatalf("unconfirmed Pay sent %d transfer RPCs; want 0 (never auto-spend)", n)
	}
}

func TestPayConfirmedSpendsOnce(t *testing.T) {
	fw, srv := newFakeWallet(t)
	c := New(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	txid, err := c.Pay(ctx, wAddr, 1000, 50, true)
	if err != nil || txid != "wallettx01" {
		t.Fatalf("pay = %q,%v", txid, err)
	}
	if n := fw.count(); n != 1 {
		t.Fatalf("transfers = %d; want exactly 1", n)
	}
}
