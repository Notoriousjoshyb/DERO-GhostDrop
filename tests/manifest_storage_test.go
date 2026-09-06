// Package tests exercises the manifest/storage/database/drops stack
// end to end: sign/verify, put/get/delete/expiry, relay client against a
// fake relay, db migrate+CRUD, and manager create→retrieve→revoke.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ghostdrop/internal/crypto"
	"ghostdrop/internal/database"
	"ghostdrop/internal/drops"
	"ghostdrop/internal/manifest"
	"ghostdrop/internal/storage"
)

func ctx() context.Context { return context.Background() }

// fakeRelay implements the relay HTTP API in memory for client tests.
type fakeRelay struct {
	mu     sync.Mutex
	data   map[string][]byte
	total  map[string]int64
	expiry map[string]time.Time
}

func newFakeRelay() *fakeRelay {
	return &fakeRelay{data: map[string][]byte{}, total: map[string]int64{}, expiry: map[string]time.Time{}}
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/api/v1/health":
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true}`)
	case r.Method == http.MethodPost && p == "/api/v1/drops":
		var req struct {
			ID            string `json:"id"`
			SizeBytes     int64  `json:"size_bytes"`
			ExpiryRFC3339 string `json:"expiry_rfc3339"`
			OneTime       bool   `json:"one_time"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		if _, ok := f.data[req.ID]; ok {
			f.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			return
		}
		exp, _ := time.Parse(time.RFC3339, req.ExpiryRFC3339)
		f.data[req.ID] = []byte{}
		f.total[req.ID] = req.SizeBytes
		f.expiry[req.ID] = exp
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ok":true}`)
	case strings.HasSuffix(p, "/meta"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/drops/"), "/meta")
		f.mu.Lock()
		d, ok := f.data[id]
		exp := f.expiry[id]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Meta reports even expired drops; the client enforces expiry.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "size_bytes": f.total[id], "uploaded_bytes": int64(len(d)),
			"expiry_rfc3339": exp.Format(time.RFC3339),
		})
	case strings.HasSuffix(p, "/data"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/drops/"), "/data")
		f.mu.Lock()
		d, ok := f.data[id]
		exp := f.expiry[id]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Writes always succeed; only data GETs see 410 Gone.
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			if cr := r.Header.Get("Content-Range"); cr != "" {
				var off int64
				fmt.Sscanf(cr, "bytes %d-", &off)
				if need := int(off) + len(body); need > len(f.data[id]) {
					grown := make([]byte, need)
					copy(grown, f.data[id])
					f.data[id] = grown
				}
				copy(f.data[id][off:], body)
			} else {
				f.data[id] = append(f.data[id][:0], body...)
			}
			f.mu.Unlock()
			_ = d
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		if !exp.IsZero() && time.Now().After(exp) {
			w.WriteHeader(http.StatusGone)
			return
		}
		var off int64
		if rg := r.Header.Get("Range"); rg != "" {
			fmt.Sscanf(rg, "bytes=%d-", &off)
		}
		if off > 0 {
			w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(off, 10)+"-")
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = w.Write(d[off:])
	case strings.HasPrefix(p, "/api/v1/drops/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(p, "/api/v1/drops/")
		f.mu.Lock()
		delete(f.data, id)
		delete(f.total, id)
		delete(f.expiry, id)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestManifestSignVerify(t *testing.T) {
	m := manifest.New(crypto.GenerateDropID(), "anonymous", time.Now().Add(24*time.Hour))
	var key [32]byte
	k, err := crypto.GenerateFileKey()
	if err != nil {
		t.Fatal(err)
	}
	key = k
	if err := m.EncryptFilenames([]string{"report.pdf"}, key); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	_, priv, err := crypto.GenerateSignKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sign(priv, "e2e"); err != nil {
		t.Fatal(err)
	}
	if !m.Verify() {
		t.Fatal("must verify")
	}
	names, err := m.DecryptFilenames(key)
	if err != nil || len(names) != 1 || names[0] != "report.pdf" {
		t.Fatalf("filenames: %v,%v", names, err)
	}
	// Canonical bytes exclude the signature.
	m2 := manifest.New(m.DropID, m.Mode, m.ExpiresAt)
	if string(m2.CanonicalBytes()) == "" {
		t.Fatal("empty canonical bytes")
	}
}

func TestLocalPutGetDeleteExpiry(t *testing.T) {
	p, err := storage.Open("local", storage.Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if p.Backend() != "local" {
		t.Fatalf("backend = %q", p.Backend())
	}
	payload := []byte("local-e2e-bytes")
	id := crypto.GenerateDropID()
	if err := p.Put(ctx(), id, bytes.NewReader(payload), int64(len(payload)), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rc, err := p.Get(ctx(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("mismatch")
	}
	// Resume offset = full size.
	if n, _, err := p.Stat(ctx(), id); err != nil || n != int64(len(payload)) {
		t.Fatalf("Stat = %d,%v", n, err)
	}
	if err := p.Delete(ctx(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx(), id, 0); err != storage.ErrNotFound {
		t.Fatalf("expected not found, got %v", err)
	}
	// Expiry.
	exp := id + "-x"
	_ = exp
	id2 := crypto.GenerateDropID()
	if err := p.Put(ctx(), id2, bytes.NewReader(payload), int64(len(payload)), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx(), id2, 0); err != storage.ErrExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestRelayClientAgainstFake(t *testing.T) {
	srv := httptest.NewServer(newFakeRelay())
	defer srv.Close()
	p, err := storage.Open("relay", storage.Options{RelayURL: srv.URL, Token: "drop-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx()); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("relay-e2e-"), 20000)
	id := crypto.GenerateDropID()
	if err := p.Put(ctx(), id, bytes.NewReader(payload), int64(len(payload)), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rc, err := p.Get(ctx(), id, 7)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload[7:]) {
		t.Fatal("resume mismatch")
	}
	if err := p.Delete(ctx(), id); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseMigrateCRUD(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "ghostdrop.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	d := database.Drop{ID: crypto.GenerateDropID(), Mode: "paid", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Status: "READY", Size: 42}
	if err := db.UpsertDrop(d); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetDrop(d.ID)
	if err != nil || got.Size != 42 {
		t.Fatalf("GetDrop: %+v,%v", got, err)
	}
	if err := db.PutContact(database.Contact{Name: "n", Address: "dero1q1", Trust: database.TrustTrusted}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddEvent(d.ID, "created", ""); err != nil {
		t.Fatal(err)
	}
	if evs, err := db.ListEvents(d.ID); err != nil || len(evs) != 1 {
		t.Fatalf("events: %d,%v", len(evs), err)
	}
}

func TestManagerCreateRetrieveRevoke(t *testing.T) {
	store := storage.NewMemoryProvider(1 << 30)
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mgr := drops.NewManager(store, db, false, t.TempDir())

	plain := bytes.Repeat([]byte("manager-e2e-payload-"), 9000)
	src := filepath.Join(t.TempDir(), "in.dat")
	if err := os.WriteFile(src, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	wantHash, _, err := crypto.Sha256HexFile(src)
	if err != nil {
		t.Fatal(err)
	}
	man, key, err := mgr.Create(ctx(), src, drops.CreateOpts{Mode: "anonymous", Expiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if off, err := mgr.ResumeOffset(ctx(), man.DropID); err != nil || off != man.PayloadSize {
		t.Fatalf("resume = %d,%v", off, err)
	}
	dst := filepath.Join(t.TempDir(), "out.dat")
	if err := mgr.Retrieve(ctx(), man.DropID, dst, drops.RetrieveOpts{Key: &key}); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	gotHash, _, err := crypto.Sha256HexFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != wantHash {
		t.Fatal("hash mismatch: retrieve corrupted payload")
	}
	if st, _ := mgr.Status(ctx(), man.DropID); st != drops.StatusVerified {
		t.Fatalf("status = %v", st)
	}
	if err := mgr.Revoke(ctx(), man.DropID); err != nil {
		t.Fatal(err)
	}
	if st, _ := mgr.Status(ctx(), man.DropID); st != drops.StatusRevoked {
		t.Fatalf("status = %v", st)
	}
}
