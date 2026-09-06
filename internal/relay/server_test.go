package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testServer(t *testing.T, quota int64) (*Server, *Client) {
	t.Helper()
	s, err := New(Config{Addr: "127.0.0.1:0", DataDir: t.TempDir(), QuotaBytes: quota})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, &Client{Base: ts.URL, HTTP: ts.Client()}
}

func getJSON(base, path string) (map[string]any, int, error) {
	resp, err := http.Get(base + path) //nolint:gosec,noctx
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}

func future(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

func mkPayload(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestPutGetDelete(t *testing.T) {
	_, c := testServer(t, 0)
	ctx := context.Background()
	payload := mkPayload(4096)
	if err := c.Create(ctx, CreateRequest{ID: "GD-ABCDEF123456", SizeBytes: int64(len(payload)), ExpiryRFC3339: future(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if c.Token == "" {
		t.Fatal("no token issued")
	}
	if err := c.Put(ctx, "GD-ABCDEF123456", payload); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(ctx, "GD-ABCDEF123456", 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("round-trip mismatch")
	}
	m, err := c.Meta(ctx, "GD-ABCDEF123456")
	if err != nil {
		t.Fatal(err)
	}
	if int64(m["uploaded_bytes"].(float64)) != int64(len(payload)) {
		t.Fatalf("bad meta %+v", m)
	}
	if err := c.Delete(ctx, "GD-ABCDEF123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "GD-ABCDEF123456", 0); err == nil {
		t.Fatal("expected not-found after delete")
	}
}

func TestAuthRequired(t *testing.T) {
	_, c := testServer(t, 0)
	ctx := context.Background()
	payload := mkPayload(16)
	if err := c.Create(ctx, CreateRequest{ID: "GD-AUTH00000001", SizeBytes: 16, ExpiryRFC3339: future(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	bad := &Client{Base: c.Base, HTTP: c.HTTP, Token: "wrong"}
	if err := bad.Put(ctx, "GD-AUTH00000001", payload); err == nil {
		t.Fatal("expected unauthorized PUT")
	}
	if _, err := bad.Get(ctx, "GD-AUTH00000001", 0); err == nil {
		t.Fatal("expected unauthorized GET")
	}
	if err := bad.Delete(ctx, "GD-AUTH00000001"); err == nil {
		t.Fatal("expected unauthorized DELETE")
	}
	// Owner still works.
	if err := c.Put(ctx, "GD-AUTH00000001", payload); err != nil {
		t.Fatal(err)
	}
}

func TestResume(t *testing.T) {
	_, c := testServer(t, 0)
	ctx := context.Background()
	payload := mkPayload(1000)
	total := int64(len(payload))
	if err := c.Create(ctx, CreateRequest{ID: "GD-RESUME000001", SizeBytes: total, ExpiryRFC3339: future(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutResume(ctx, "GD-RESUME000001", total, 0, payload[:400]); err != nil {
		t.Fatal(err)
	}
	// Wrong offset must conflict, not corrupt.
	if err := c.PutResume(ctx, "GD-RESUME000001", total, 100, payload[100:500]); err == nil {
		t.Fatal("expected offset conflict")
	}
	// Range read of the partial prefix.
	resp, err := c.Get(ctx, "GD-RESUME000001", 0)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(part, payload[:400]) {
		t.Fatal("partial prefix mismatch")
	}
	// Finish.
	if err := c.PutResume(ctx, "GD-RESUME000001", total, 400, payload[400:]); err != nil {
		t.Fatal(err)
	}
	resp, err = c.Get(ctx, "GD-RESUME000001", 350)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("want 206 got %d", resp.StatusCode)
	}
	tail, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(tail, payload[350:]) {
		t.Fatal("resume tail mismatch")
	}
}

func TestOneTime(t *testing.T) {
	_, c := testServer(t, 0)
	ctx := context.Background()
	payload := mkPayload(64)
	if err := c.Create(ctx, CreateRequest{ID: "GD-ONETIME00001", SizeBytes: 64, ExpiryRFC3339: future(time.Hour), OneTime: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "GD-ONETIME00001", payload); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(ctx, "GD-ONETIME00001", 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("one-time payload mismatch")
	}
	if _, err := c.Get(ctx, "GD-ONETIME00001", 0); err == nil {
		t.Fatal("expected one-time drop to vanish after first GET")
	}
}

func TestExpiry(t *testing.T) {
	s, c := testServer(t, 0)
	ctx := context.Background()
	if err := c.Create(ctx, CreateRequest{ID: "GD-EXPIRE000001", SizeBytes: 8, ExpiryRFC3339: future(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "GD-EXPIRE000001", mkPayload(8)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		_, err := c.Get(ctx, "GD-EXPIRE000001", 0)
		if err != nil {
			break // expired + swept on access
		}
		if time.Now().After(deadline) {
			t.Fatal("drop never expired")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if n, err := s.SweepNow(); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("sweeper should find nothing, removed %d", n)
	}
	// Expired meta file must be gone from disk.
	if _, err := os.Stat(filepath.Join(s.cfg.DataDir, "GD-EXPIRE000001.meta.json")); !os.IsNotExist(err) {
		t.Fatal("expired meta not removed")
	}
}

func TestQuota(t *testing.T) {
	_, c := testServer(t, 32)
	ctx := context.Background()
	if err := c.Create(ctx, CreateRequest{ID: "GD-QUOTA0000001", SizeBytes: 64, ExpiryRFC3339: future(time.Hour)}); err == nil {
		t.Fatal("expected quota rejection")
	}
	if err := c.Create(ctx, CreateRequest{ID: "GD-QUOTA0000002", SizeBytes: 16, ExpiryRFC3339: future(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "GD-QUOTA0000002", mkPayload(16)); err != nil {
		t.Fatal(err)
	}
	// 16 stored + 32 new > 32 quota.
	if err := c.Create(ctx, CreateRequest{ID: "GD-QUOTA0000003", SizeBytes: 32, ExpiryRFC3339: future(time.Hour)}); err == nil {
		t.Fatal("expected quota rejection after partial fill")
	}
}

func TestHealthStats(t *testing.T) {
	_, c := testServer(t, 0)
	ctx := context.Background()
	health, code, err := getJSON(c.Base, "/api/v1/health")
	if err != nil || code != 200 || health["ok"] != true {
		t.Fatalf("bad health %+v code=%d err=%v", health, code, err)
	}
	payload := mkPayload(128)
	if err := c.Create(ctx, CreateRequest{ID: "GD-STATS0000001", SizeBytes: 128, ExpiryRFC3339: future(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "GD-STATS0000001", payload); err != nil {
		t.Fatal(err)
	}
	stats, code, err := getJSON(c.Base, "/api/v1/stats")
	if err != nil || code != 200 {
		t.Fatal(err)
	}
	if int(stats["drops"].(float64)) != 1 || int64(stats["bytes_stored"].(float64)) != 128 {
		t.Fatalf("bad stats %+v", stats)
	}
}
