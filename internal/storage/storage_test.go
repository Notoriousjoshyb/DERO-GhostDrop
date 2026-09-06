package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func ctx() context.Context { return context.Background() }

func putGetRoundtrip(t *testing.T, p Provider, id string) {
	t.Helper()
	payload := bytes.Repeat([]byte("ghostdrop-payload-1234567890-"), 4000) // ~112KB
	exp := time.Now().Add(2 * time.Hour)
	if err := p.Put(ctx(), id, bytes.NewReader(payload), int64(len(payload)), exp); err != nil {
		t.Fatalf("Put: %v", err)
	}
	ok, err := p.Exists(ctx(), id)
	if err != nil || !ok {
		t.Fatalf("Exists = %v,%v", ok, err)
	}
	size, _, err := p.Stat(ctx(), id)
	if err != nil || size != int64(len(payload)) {
		t.Fatalf("Stat = %d,%v", size, err)
	}
	// Full read.
	rc, err := p.Get(ctx(), id, 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch on full read")
	}
	// Offset read (resume).
	rc, err = p.Get(ctx(), id, 100)
	if err != nil {
		t.Fatalf("Get offset: %v", err)
	}
	got, err = io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("ReadAll offset: %v", err)
	}
	if !bytes.Equal(got, payload[100:]) {
		t.Fatal("payload mismatch on offset read")
	}
	if err := p.Delete(ctx(), id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	ok, err = p.Exists(ctx(), id)
	if err != nil || ok {
		t.Fatalf("Exists after delete = %v,%v", ok, err)
	}
	if _, err := p.Get(ctx(), id, 0); err == nil {
		t.Fatal("Get after delete must fail")
	}
}

func TestMemoryRoundtrip(t *testing.T) {
	putGetRoundtrip(t, NewMemoryProvider(1<<20), "GD-ABCDEF123456")
}

func TestMemoryExpiry(t *testing.T) {
	p := NewMemoryProvider(1 << 20)
	payload := []byte("expired")
	if err := p.Put(ctx(), "GD-EXP000000001", bytes.NewReader(payload), int64(len(payload)), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx(), "GD-EXP000000001", 0); err != ErrExpired {
		t.Fatalf("Get expired = %v", err)
	}
	if _, _, err := p.Stat(ctx(), "GD-EXP000000001"); err == nil {
		t.Fatal("Stat expired must fail")
	}
	_ = p
}

func TestMemoryQuota(t *testing.T) {
	p := NewMemoryProvider(16)
	if err := p.Put(ctx(), "GD-BIG000000001", bytes.NewReader(make([]byte, 64)), 64, time.Now().Add(time.Hour)); err != ErrQuota {
		t.Fatalf("expected quota error, got %v", err)
	}
}

func TestLocalRoundtrip(t *testing.T) {
	p, err := NewLocalProvider(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	putGetRoundtrip(t, p, "GD-LOCAL0000001")
	if err := p.Health(ctx()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestLocalExpiry(t *testing.T) {
	p, err := NewLocalProvider(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("stale")
	if err := p.Put(ctx(), "GD-STALE0000001", bytes.NewReader(payload), int64(len(payload)), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx(), "GD-STALE0000001", 0); err != ErrExpired {
		t.Fatalf("Get expired = %v", err)
	}
	if ok, _ := p.Exists(ctx(), "GD-STALE0000001"); ok {
		t.Fatal("expired must not exist")
	}
}

// fakeRelay is a minimal in-memory relay implementing the contract API.
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
		return
	case r.Method == http.MethodPost && p == "/api/v1/drops":
		var req struct {
			ID           string `json:"id"`
			SizeBytes    int64  `json:"size_bytes"`
			ExpiryRFC3339 string `json:"expiry_rfc3339"`
			OneTime      bool   `json:"one_time"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		if _, ok := f.data[req.ID]; ok {
			f.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"ok":false}`)
			return
		}
		exp, _ := time.Parse(time.RFC3339, req.ExpiryRFC3339)
		f.data[req.ID] = []byte{}
		f.total[req.ID] = req.SizeBytes
		f.expiry[req.ID] = exp
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ok":true}`)
		return
	case strings.HasSuffix(p, "/meta") && r.Method == http.MethodGet:
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/drops/"), "/meta")
		f.mu.Lock()
		d, ok := f.data[id]
		exp := f.expiry[id]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Meta reports even expired drops (with their expiry); the client
		// enforces expiry. Only data reads return 410 Gone.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "size_bytes": f.total[id], "uploaded_bytes": int64(len(d)),
			"expiry_rfc3339": exp.Format(time.RFC3339),
		})
		return
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
		// Writes always succeed (mirrors memory/local semantics: Put
		// accepts, reads enforce expiry). Only GETs see 410 Gone.
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			cr := r.Header.Get("Content-Range")
			f.mu.Lock()
			if cr != "" {
				// "bytes off-end/total"
				var off, end, total int64
				fmt.Sscanf(cr, "bytes %d-%d/%d", &off, &end, &total)
				need := int(off) + len(body)
				if need > len(f.data[id]) {
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
		if r.Method == http.MethodGet {
			if !exp.IsZero() && time.Now().After(exp) {
				w.WriteHeader(http.StatusGone)
				return
			}
			var off int64
			if rg := r.Header.Get("Range"); rg != "" {
				fmt.Sscanf(rg, "bytes=%d-", &off)
			}
			if off > int64(len(d)) {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			if off > 0 {
				w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(off, 10)+"-"+strconv.FormatInt(int64(len(d))-1, 10)+"/"+strconv.FormatInt(int64(len(d)), 10))
				w.WriteHeader(http.StatusPartialContent)
			}
			_, _ = w.Write(d[off:])
			return
		}
	case strings.HasPrefix(p, "/api/v1/drops/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(p, "/api/v1/drops/")
		f.mu.Lock()
		delete(f.data, id)
		delete(f.total, id)
		delete(f.expiry, id)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func TestRelayRoundtrip(t *testing.T) {
	srv := httptest.NewServer(newFakeRelay())
	defer srv.Close()
	c := NewRelayClient(srv.URL, "tok-123")
	if err := c.Health(ctx()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	putGetRoundtrip(t, c, "GD-RELAY0000001")
}

func TestRelayExpiry(t *testing.T) {
	srv := httptest.NewServer(newFakeRelay())
	defer srv.Close()
	c := NewRelayClient(srv.URL, "tok-123")
	payload := []byte("gone")
	if err := c.Put(ctx(), "GD-GONE00000001", bytes.NewReader(payload), int64(len(payload)), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx(), "GD-GONE00000001", 0); err != ErrExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestRelayChunkedLarge(t *testing.T) {
	srv := httptest.NewServer(newFakeRelay())
	defer srv.Close()
	c := NewRelayClient(srv.URL, "tok-abc")
	c.chunk = 64 << 10
	payload := bytes.Repeat([]byte("0123456789abcdef"), 30000) // ~480KB → multi-chunk
	exp := time.Now().Add(time.Hour)
	if err := c.Put(ctx(), "GD-CHUNK0000001", bytes.NewReader(payload), int64(len(payload)), exp); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rc, err := c.Get(ctx(), "GD-CHUNK0000001", 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("chunked payload mismatch")
	}
}

func TestRegistry(t *testing.T) {
	for _, name := range []string{"memory", "LOCAL", "Memory"} {
		p, err := Open(name, Options{DataDir: t.TempDir()})
		if err != nil {
			t.Fatalf("Open(%s): %v", name, err)
		}
		if p.Backend() == "" {
			t.Fatalf("empty backend for %s", name)
		}
	}
	if _, err := Open("nope", Options{}); err == nil {
		t.Fatal("unknown provider must fail")
	}
	if _, err := Open("local", Options{}); err == nil {
		t.Fatal("local without DataDir must fail")
	}
}

func TestValidateID(t *testing.T) {
	for _, bad := range []string{"", "../x", "a/b", "a b", ".."} {
		if ValidateID(bad) == nil {
			t.Fatalf("bad id %q accepted", bad)
		}
	}
	if ValidateID("GD-ABCDEF123456") != nil {
		t.Fatal("good id rejected")
	}
}
