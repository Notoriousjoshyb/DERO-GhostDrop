package dero

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAddr  = "dero1q" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef"
	testAddr2 = "dero1q" + "0011223344556677889900aabbccddeeff0011223344556677889900aabbcc"
)

type txRec struct {
	address       string
	amount        uint64
	confirmations uint64
}

type fakeBackend struct {
	mu     sync.Mutex
	names  map[string]string
	txs    map[string]txRec
	calls  []string
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	failTx bool
}

func newFake(t *testing.T) (*fakeBackend, *httptest.Server) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBackend{
		names: map[string]string{"captain.dero": testAddr},
		txs: map[string]txRec{
			"tx-confirmed":   {address: testAddr, amount: 5000, confirmations: 12},
			"tx-shallow":     {address: testAddr, amount: 5000, confirmations: 3},
			"tx-wrong-addr":  {address: testAddr2, amount: 5000, confirmations: 30},
			"tx-underpaid":   {address: testAddr, amount: 10, confirmations: 30},
			"tx-edgeexactly": {address: testAddr, amount: 5000, confirmations: 10},
		},
		pub:  pub,
		priv: priv,
	}
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	writeOK := func(w http.ResponseWriter, result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": "ghostdrop", "result": result})
	}
	writeErr := func(w http.ResponseWriter, code int, msg string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": "ghostdrop", "error": map[string]any{"code": code, "message": msg}})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, -32700, "parse error")
			return
		}
		fb.mu.Lock()
		fb.calls = append(fb.calls, req.Method)
		fb.mu.Unlock()
		var p map[string]any
		_ = json.Unmarshal(req.Params, &p)
		str := func(k string) string {
			v, _ := p[k].(string)
			return v
		}
		switch req.Method {
		case "get_info":
			writeOK(w, map[string]any{"status": "OK", "height": uint64(12345)})
		case "resolve_name":
			addr, ok := fb.names[str("name")]
			if !ok {
				writeErr(w, rpcNotFoundCode, "name not found")
				return
			}
			writeOK(w, map[string]any{"address": addr, "verified": true})
		case "get_transaction":
			if fb.failTx {
				writeErr(w, -32000, "boom")
				return
			}
			tx, ok := fb.txs[str("txid")]
			if !ok {
				writeErr(w, rpcNotFoundCode, "tx not found")
				return
			}
			writeOK(w, map[string]any{"txid": str("txid"), "address": tx.address, "amount": tx.amount, "confirmations": tx.confirmations})
		case "get_version":
			writeOK(w, map[string]any{"status": "OK", "version": "v9.9-test"})
		case "sign_data":
			raw, err := hex.DecodeString(str("data"))
			if err != nil {
				writeErr(w, -32602, "bad data")
				return
			}
			sig := ed25519.Sign(fb.priv, raw)
			writeOK(w, map[string]any{"signature": hex.EncodeToString(sig), "public_key": hex.EncodeToString(fb.pub)})
		case "transfer":
			writeOK(w, map[string]any{"tx_hash": "deadbeef01"})
		default:
			writeErr(w, -32601, "unknown method")
		}
	}))
	t.Cleanup(srv.Close)
	return fb, srv
}

func (fb *fakeBackend) methodCount(m string) int {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	n := 0
	for _, c := range fb.calls {
		if c == m {
			n++
		}
	}
	return n
}

func TestValidateAddress(t *testing.T) {
	if !ValidateAddress(testAddr) {
		t.Fatal("valid address rejected")
	}
	for _, bad := range []string{"", "dero1qshort", "bitcoin1q" + strings.Repeat("a", 60), "dero1q" + strings.Repeat("!", 60), "dero1q" + strings.Repeat("a", 200)} {
		if ValidateAddress(bad) {
			t.Fatalf("invalid address accepted: %q", bad)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"captain.dero", "notorious.dero", "a-b-c.dero", "Captain.dero"} {
		if !ValidateName(ok) {
			t.Fatalf("valid name rejected: %q", ok)
		}
	}
	for _, bad := range []string{"", "captain", "captain.derox", ".dero", "CAPTAIN.DERO.TLD", "under_score.dero", "spaces here.dero"} {
		if ValidateName(bad) {
			t.Fatalf("invalid name accepted: %q", bad)
		}
	}
	if NormalizeName("  Captain.DERO ") != "captain.dero" {
		t.Fatal("NormalizeName mismatch")
	}
}

func TestResolveHit(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := NewDaemonClient(srv.URL).ResolveNameOrAddress(ctx, "captain.dero")
	if err != nil {
		t.Fatal(err)
	}
	if addr != testAddr || !verified {
		t.Fatalf("hit = %q,%v; want %q,true", addr, verified, testAddr)
	}
}

func TestResolveMiss(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := NewDaemonClient(srv.URL).ResolveNameOrAddress(ctx, "nobody.dero")
	if !errors.Is(err, ErrNameNotFound) {
		t.Fatalf("miss err = %v; want ErrNameNotFound", err)
	}
	if addr != "" || verified {
		t.Fatalf("miss returned %q,%v; want empty,false", addr, verified)
	}
}

func TestResolvePassthroughUnverified(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := NewDaemonClient(srv.URL).ResolveNameOrAddress(ctx, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	if addr != testAddr || verified {
		t.Fatalf("passthrough = %q,%v; want addr,false (never fabricated)", addr, verified)
	}
}

func TestResolveInvalidInput(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := NewDaemonClient(srv.URL).ResolveNameOrAddress(ctx, "not a name!!"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("err = %v; want ErrInvalidName", err)
	}
}

func TestResolveOffline(t *testing.T) {
	_, srv := newFake(t)
	url := srv.URL
	srv.Close() // kill it: everything after is offline
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := NewDaemonClient(url).ResolveNameOrAddress(ctx, "captain.dero")
	if !errors.Is(err, ErrOffline) {
		t.Fatalf("offline err = %v; want ErrOffline", err)
	}
	if addr != "" || verified {
		t.Fatal("offline must return zero values (caller-safe)")
	}
	if !IsOffline(err) {
		t.Fatal("IsOffline must detect wrapped ErrOffline")
	}
}

func TestPackageResolveNameUsesDefault(t *testing.T) {
	_, srv := newFake(t)
	old := DefaultDaemonEndpoint
	DefaultDaemonEndpoint = srv.URL
	defer func() { DefaultDaemonEndpoint = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := ResolveName(ctx, "captain.dero")
	if err != nil || addr != testAddr || !verified {
		t.Fatalf("ResolveName = %q,%v,%v", addr, verified, err)
	}
}

func TestGetInfo(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := NewDaemonClient(srv.URL).GetInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Status != "OK" || info.Height != 12345 {
		t.Fatalf("info = %+v", info)
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := []byte("ghostdrop drop GD-ABC123 authorize")
	sigHex, pubHex, err := SignWithWallet(ctx, srv.URL, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyWithPub(pubHex, msg, sig) {
		t.Fatal("valid signature did not verify")
	}
	if VerifyWithPub(pubHex, []byte("tampered"), sig) {
		t.Fatal("tampered message verified (must not)")
	}
	if VerifyWithPub("00", msg, sig) || VerifyWithPub(pubHex, msg, []byte("short")) {
		t.Fatal("malformed inputs must verify as false")
	}
}

func TestSignEmptyRejected(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := SignWithWallet(ctx, srv.URL, nil); err == nil {
		t.Fatal("empty message must be rejected")
	}
}

func TestWalletStatus(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	online, err := WalletStatus(ctx, srv.URL)
	if err != nil || !online {
		t.Fatalf("status = %v,%v; want true,nil", online, err)
	}
	srv.Close()
	if online, err := WalletStatus(ctx, srv.URL); !errors.Is(err, ErrOffline) || online {
		t.Fatalf("offline status = %v,%v; want false,ErrOffline", online, err)
	}
}

func TestTransfer(t *testing.T) {
	fb, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	txid, err := TransferWithWallet(ctx, srv.URL, testAddr, 1000, 1)
	if err != nil || txid != "deadbeef01" {
		t.Fatalf("transfer = %q,%v", txid, err)
	}
	if fb.methodCount("transfer") != 1 {
		t.Fatal("expected exactly one transfer call")
	}
	if _, err := TransferWithWallet(ctx, srv.URL, "bogus", 1000, 1); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("bad dest err = %v; want ErrInvalidAddress", err)
	}
}

func TestCheckPaymentPaths(t *testing.T) {
	_, srv := newFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := CheckPayment(ctx, srv.URL, "tx-confirmed", testAddr, 5000)
	if err != nil || !ok {
		t.Fatalf("confirmed = %v,%v; want true,nil", ok, err)
	}
	ok, err = CheckPayment(ctx, srv.URL, "tx-edgeexactly", testAddr, 5000)
	if err != nil || !ok {
		t.Fatalf("exactly-10 confirmations must count: %v,%v", ok, err)
	}
	for tx, want := range map[string]string{"tx-shallow": "unconfirmed", "tx-wrong-addr": "wrong addr", "tx-underpaid": "underpaid"} {
		ok, err := CheckPayment(ctx, srv.URL, tx, testAddr, 5000)
		if err != nil || ok {
			t.Fatalf("%s: got %v,%v; want false,nil", want, ok, err)
		}
	}
	if ok, err := CheckPayment(ctx, srv.URL, "tx-nope", testAddr, 1); !errors.Is(err, ErrTxNotFound) || ok {
		t.Fatalf("unknown tx = %v,%v; want false,ErrTxNotFound", ok, err)
	}
}

func TestCheckPaymentOffline(t *testing.T) {
	_, srv := newFake(t)
	url := srv.URL
	srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ok, err := CheckPayment(ctx, url, "tx-confirmed", testAddr, 1); !errors.Is(err, ErrOffline) || ok {
		t.Fatalf("offline = %v,%v; want false,ErrOffline", ok, err)
	}
}
