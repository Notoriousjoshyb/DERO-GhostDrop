// End-to-end relay tests over real HTTP (httptest server + relay client).
package tests_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ghostdrop/internal/relay"
)

func gdRelayServer(t *testing.T, quota int64) (string, *relay.Client) {
	t.Helper()
	s, err := relay.New(relay.Config{Addr: "127.0.0.1:0", DataDir: t.TempDir(), QuotaBytes: quota})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts.URL, &relay.Client{Base: ts.URL, HTTP: ts.Client()}
}

func gdRelayPayload(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestRelay_EndToEnd(t *testing.T) {
	_, c := gdRelayServer(t, 0)
	ctx := context.Background()
	payload := gdRelayPayload(2048)
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := c.Create(ctx, relay.CreateRequest{ID: "GD-E2E000000001", SizeBytes: int64(len(payload)), ExpiryRFC3339: exp}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "GD-E2E000001", payload); err == nil {
		t.Fatal("expected wrong-id PUT to fail")
	}
	if err := c.Put(ctx, "GD-E2E000000001", payload); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(ctx, "GD-E2E000000001", 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	meta, err := c.Meta(ctx, "GD-E2E000000001")
	if err != nil {
		t.Fatal(err)
	}
	if meta["id"] != "GD-E2E000000001" || int64(meta["uploaded_bytes"].(float64)) != int64(len(payload)) {
		t.Fatalf("bad meta %+v", meta)
	}
	if err := c.Delete(ctx, "GD-E2E000000001"); err != nil {
		t.Fatal(err)
	}
}

func TestRelay_HealthAndStats(t *testing.T) {
	base, _ := gdRelayServer(t, 0)
	resp, err := http.Get(base + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"ok":true`)) {
		t.Fatalf("bad health %d %s", resp.StatusCode, body)
	}
	resp, err = http.Get(base + "/api/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"drops"`)) {
		t.Fatalf("bad stats %d %s", resp.StatusCode, body)
	}
}

func TestRelay_ResumeUpload(t *testing.T) {
	_, c := gdRelayServer(t, 0)
	ctx := context.Background()
	payload := gdRelayPayload(512)
	total := int64(len(payload))
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := c.Create(ctx, relay.CreateRequest{ID: "GD-E2ERESUME0001", SizeBytes: total, ExpiryRFC3339: exp}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutResume(ctx, "GD-E2ERESUME0001", total, 0, payload[:200]); err != nil {
		t.Fatal(err)
	}
	if err := c.PutResume(ctx, "GD-E2ERESUME0001", total, 200, payload[200:]); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(ctx, "GD-E2ERESUME0001", 200)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("want 206 got %d", resp.StatusCode)
	}
	tail, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(tail, payload[200:]) {
		t.Fatal("resumed tail mismatch")
	}
}
