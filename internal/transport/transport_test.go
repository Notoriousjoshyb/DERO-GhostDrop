package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCopyWithProgress(t *testing.T) {
	src := strings.NewReader("hello world, this is a test payload")
	var dst strings.Builder
	var calls []int64
	n, err := CopyWithProgress(&writerFunc{fn: dst.WriteString}, src, func(w int64) { calls = append(calls, w) })
	if err != nil {
		t.Fatal(err)
	}
	if dst.String() != "hello world, this is a test payload" {
		t.Fatalf("bad copy %q", dst.String())
	}
	if n != int64(len("hello world, this is a test payload")) {
		t.Fatalf("bad count %d", n)
	}
	if len(calls) == 0 || calls[len(calls)-1] != n {
		t.Fatalf("bad progress calls %v", calls)
	}
}

type writerFunc struct{ fn func(string) (int, error) }

func (w *writerFunc) Write(p []byte) (int, error) { return w.fn(string(p)) }

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	payload := []byte("ghostdrop transport hashing")
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := HashFile(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(payload)) {
		t.Fatalf("bad size %d", size)
	}
	if len(sum) != 64 {
		t.Fatalf("bad sum %q", sum)
	}
	sum2, _, err := HashFile(p, func(int64) {})
	if err != nil || sum2 != sum {
		t.Fatalf("unstable hash %q vs %q err=%v", sum, sum2, err)
	}
}

func TestBackoffBounds(t *testing.T) {
	for i := 0; i < 6; i++ {
		d := Backoff(i, time.Millisecond)
		if d <= 0 || d > time.Second<<uint(i+1) {
			t.Fatalf("attempt %d: bad backoff %v", i, d)
		}
	}
	if got := Backoff(0, 0); got <= 0 || got > 400*time.Millisecond {
		t.Fatalf("default base bad: %v", got)
	}
}

func TestRetry(t *testing.T) {
	ctx := context.Background()
	tries := 0
	err := Retry(ctx, 3, time.Millisecond, func() error {
		tries++
		if tries < 3 {
			return errors.New("boom")
		}
		return nil
	})
	if err != nil || tries != 3 {
		t.Fatalf("retry got tries=%d err=%v", tries, err)
	}
	if err := Retry(ctx, 2, time.Millisecond, func() error { return errors.New("always") }); err == nil {
		t.Fatal("expected error")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Retry(cancelled, 3, time.Millisecond, func() error { return errors.New("x") }); err == nil {
		t.Fatal("expected ctx error")
	}
}

func TestContentRangeRoundTrip(t *testing.T) {
	s := FormatContentRange(100, 199, 1000)
	if s != "bytes 100-199/1000" {
		t.Fatalf("bad format %q", s)
	}
	cr, err := ParseContentRange(s)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Start != 100 || cr.End != 199 || cr.Total != 1000 {
		t.Fatalf("bad parse %+v", cr)
	}
	for _, bad := range []string{"", "bytes 5-3/10", "bytes 0-9/9", "octets 0-1/10", "bytes 0-1"} {
		if _, err := ParseContentRange(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	r, err := ParseRange("bytes=50-", 100)
	if err != nil || r.Start != 50 || r.End != 99 {
		t.Fatalf("bad range %+v err=%v", r, err)
	}
	if _, err := ParseRange("bytes=100-", 100); err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestFetchRangeAndPutChunk(t *testing.T) {
	payload := []byte("0123456789abcdef")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Accept-Ranges", "bytes")
			http.ServeContent(w, r, "f", time.Time{}, strings.NewReader(string(payload)))
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			if r.Header.Get("Content-Range") != "bytes 0-3/16" || string(body) != "0123" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if err := PutChunk(ctx, nil, srv.URL, 0, 16, []byte("0123"), "tok"); err != nil {
		t.Fatal(err)
	}
	resp, err := FetchRange(ctx, nil, srv.URL, 4, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("want 206 got %d", resp.StatusCode)
	}
	rest, _ := io.ReadAll(resp.Body)
	if string(rest) != "456789abcdef" {
		t.Fatalf("bad range body %q", rest)
	}
}
