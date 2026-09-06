// Integration coverage for the DERO-backed Ghostdrop flows: name resolve
// hit+miss, offline caller-safety, wallet sign/verify roundtrip, payment
// confirmed/unconfirmed paths, and blocked-identity rejection.
package tests_test

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
	"ghostdrop/internal/identity"
	"ghostdrop/internal/payments"
)

const deroTestAddr = "dero1q" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef"

type deroFake struct {
	mu   sync.Mutex
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func deroFakeServer(t *testing.T) (*httptest.Server, *deroFake) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &deroFake{priv: priv, pub: pub}
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
		fail := func(code int, msg string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": code, "message": msg}})
		}
		var p map[string]any
		_ = json.Unmarshal(req.Params, &p)
		s, _ := p["name"].(string)
		tx, _ := p["txid"].(string)
		data, _ := p["data"].(string)
		switch req.Method {
		case "resolve_name":
			if s == "captain.dero" {
				ok(map[string]any{"address": deroTestAddr, "verified": true})
			} else {
				fail(-32004, "name not found")
			}
		case "get_transaction":
			switch tx {
			case "tx-paid":
				ok(map[string]any{"txid": tx, "address": deroTestAddr, "amount": uint64(2000), "confirmations": uint64(14)})
			case "tx-pending":
				ok(map[string]any{"txid": tx, "address": deroTestAddr, "amount": uint64(2000), "confirmations": uint64(1)})
			default:
				fail(-32004, "tx not found")
			}
		case "get_version":
			ok(map[string]any{"status": "OK", "version": "v-test"})
		case "sign_data":
			raw, _ := hex.DecodeString(data)
			f.mu.Lock()
			sig := ed25519.Sign(f.priv, raw)
			f.mu.Unlock()
			ok(map[string]any{"signature": hex.EncodeToString(sig), "public_key": hex.EncodeToString(f.pub)})
		default:
			fail(-32601, "unknown")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

func TestDeroResolveHitAndMiss(t *testing.T) {
	srv, _ := deroFakeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := dero.NewDaemonClient(srv.URL)
	addr, verified, err := c.ResolveNameOrAddress(ctx, "captain.dero")
	if err != nil || addr != deroTestAddr || !verified {
		t.Fatalf("hit = %q,%v,%v", addr, verified, err)
	}
	if _, _, err := c.ResolveNameOrAddress(ctx, "nobody.dero"); !errors.Is(err, dero.ErrNameNotFound) {
		t.Fatalf("miss err = %v", err)
	}
}

func TestDeroOfflineCallerSafe(t *testing.T) {
	srv, _ := deroFakeServer(t)
	url := srv.URL
	srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := dero.NewDaemonClient(url).ResolveNameOrAddress(ctx, "captain.dero")
	if !errors.Is(err, dero.ErrOffline) || addr != "" || verified {
		t.Fatalf("offline = %q,%v,%v; want empty,false,ErrOffline", addr, verified, err)
	}
}

func TestDeroSignVerifyRoundtrip(t *testing.T) {
	srv, _ := deroFakeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := []byte("ghostdrop paid drop authorize")
	sigHex, pubHex, err := dero.SignWithWallet(ctx, srv.URL, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(sigHex)
	if !dero.VerifyWithPub(pubHex, msg, sig) {
		t.Fatal("roundtrip failed")
	}
	online, err := dero.WalletStatus(ctx, srv.URL)
	if err != nil || !online {
		t.Fatalf("wallet status = %v,%v", online, err)
	}
}

func TestDeroPaymentConfirmedUnconfirmed(t *testing.T) {
	srv, _ := deroFakeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := dero.CheckPayment(ctx, srv.URL, "tx-paid", deroTestAddr, 2000)
	if err != nil || !ok {
		t.Fatalf("confirmed = %v,%v", ok, err)
	}
	ok, err = dero.CheckPayment(ctx, srv.URL, "tx-pending", deroTestAddr, 2000)
	if err != nil || ok {
		t.Fatalf("unconfirmed = %v,%v; want false,nil", ok, err)
	}
	r, err := payments.CreateRequest("GD-TEST01", 2000, deroTestAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AttachTxid("tx-paid"); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize(ctx, srv.URL); err != nil || !r.IsAuthorized() {
		t.Fatalf("paid authorize = %v authorized=%v", err, r.IsAuthorized())
	}
}

func TestDeroBlockedIdentityRejected(t *testing.T) {
	srv, _ := deroFakeServer(t)
	s := identity.NewStore()
	s.Block(deroTestAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lookup := dero.NewDaemonClient(srv.URL).ResolveNameOrAddress
	if _, _, err := s.Resolve(ctx, lookup, deroTestAddr); !errors.Is(err, identity.ErrBlocked) {
		t.Fatalf("blocked resolve err = %v; want ErrBlocked", err)
	}
	if err := s.Add(identity.Contact{Name: "Blocked", Address: deroTestAddr}); !errors.Is(err, identity.ErrBlocked) {
		t.Fatalf("blocked add err = %v; want ErrBlocked", err)
	}
}
