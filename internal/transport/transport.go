// Package transport provides shared transfer helpers for Ghostdrop V1:
// progress-reporting copies, hashing readers, retry/backoff, and HTTP
// range-request client helpers used by both the relay and p2p paths.
//
// The relay never decrypts payloads; everything here is content-opaque.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultChunkSize is the 1MiB chunk size used across relay and p2p transfers.
const DefaultChunkSize = 1 << 20

// CopyWithProgress copies src to dst, invoking fn after each write with the
// running total of bytes written. A nil fn disables callbacks.
func CopyWithProgress(dst io.Writer, src io.Reader, fn func(written int64)) (int64, error) {
	var written int64
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if fn != nil {
				fn(written)
			}
			if ew != nil {
				return written, ew
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

// HashingReader wraps r and accumulates SHA-256 over every byte read.
type HashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

// NewHashingReader returns a HashingReader over r.
func NewHashingReader(r io.Reader) *HashingReader {
	return &HashingReader{r: r, h: sha256.New()}
}

func (hr *HashingReader) Read(p []byte) (int, error) {
	n, err := hr.r.Read(p)
	if n > 0 {
		hr.h.Write(p[:n])
		hr.n += int64(n)
	}
	return n, err
}

// Sum returns the hex SHA-256 of bytes read so far.
func (hr *HashingReader) Sum() string { return hex.EncodeToString(hr.h.Sum(nil)) }

// N returns the number of bytes read so far.
func (hr *HashingReader) N() int64 { return hr.n }

// HashFile streams path and returns hex(sha256(content)) and size.
// It never loads the whole file into memory.
func HashFile(path string, fn func(written int64)) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	hr := NewHashingReader(f)
	n, err := CopyWithProgress(io.Discard, hr, fn)
	if err != nil {
		return "", 0, err
	}
	return hr.Sum(), n, nil
}

// Backoff returns the delay before attempt (0-based): base*2^attempt with
// up to 25% jitter, capped at 30s. base <= 0 defaults to 200ms.
func Backoff(attempt int, base time.Duration) time.Duration {
	if base <= 0 {
		base = 200 * time.Millisecond
	}
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 10 {
		attempt = 10
	}
	d := base << attempt
	if d > 30*time.Second || d <= 0 {
		d = 30 * time.Second
	}
	// Full jitter: uniform in [d/2, d].
	half := int64(d) / 2
	return time.Duration(half + rand.Int64N(half+1))
}

// Retry runs fn up to attempts times (attempts < 1 means 1) with exponential
// backoff between failures. It aborts early if ctx is cancelled and returns
// the last error from fn.
func Retry(ctx context.Context, attempts int, base time.Duration, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err = fn(); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(Backoff(i, base)):
		}
	}
	return err
}

// FormatContentRange renders "bytes off-end/total" for resumable PUTs.
func FormatContentRange(off, end, total int64) string {
	return "bytes " + strconv.FormatInt(off, 10) + "-" + strconv.FormatInt(end, 10) + "/" + strconv.FormatInt(total, 10)
}

// ContentRange describes a parsed Content-Range or Range header value.
type ContentRange struct {
	Start int64 // first byte offset
	End   int64 // last byte offset, inclusive; -1 if open-ended (Range only)
	Total int64 // total size; -1 if unknown (Range only)
}

// ParseContentRange parses "bytes off-end/total" (PUT resume header).
func ParseContentRange(v string) (ContentRange, error) {
	var cr ContentRange
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "bytes ") {
		return cr, fmt.Errorf("transport: bad Content-Range %q", v)
	}
	rest := strings.TrimPrefix(v, "bytes ")
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return cr, fmt.Errorf("transport: bad Content-Range %q", v)
	}
	dash := strings.IndexByte(rest[:slash], '-')
	if dash < 0 {
		return cr, fmt.Errorf("transport: bad Content-Range %q", v)
	}
	start, err1 := strconv.ParseInt(rest[:dash], 10, 64)
	end, err2 := strconv.ParseInt(rest[dash+1:slash], 10, 64)
	total, err3 := strconv.ParseInt(rest[slash+1:], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || start < 0 || end < start || total <= 0 || end >= total {
		return cr, fmt.Errorf("transport: bad Content-Range %q", v)
	}
	return ContentRange{Start: start, End: end, Total: total}, nil
}

// ParseRange parses "bytes=off-" (GET resume header). Open-ended only.
func ParseRange(v string, size int64) (ContentRange, error) {
	var cr ContentRange
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "bytes=") {
		return cr, fmt.Errorf("transport: bad Range %q", v)
	}
	rest := strings.TrimPrefix(v, "bytes=")
	if strings.Contains(rest, ",") {
		return cr, fmt.Errorf("transport: multipart ranges unsupported")
	}
	dash := strings.IndexByte(rest, '-')
	if dash < 0 {
		return cr, fmt.Errorf("transport: bad Range %q", v)
	}
	if dash == 0 {
		return cr, fmt.Errorf("transport: suffix ranges unsupported")
	}
	start, err := strconv.ParseInt(rest[:dash], 10, 64)
	if err != nil || start < 0 {
		return cr, fmt.Errorf("transport: bad Range %q", v)
	}
	end := size - 1
	if len(rest) > dash+1 {
		e, err := strconv.ParseInt(rest[dash+1:], 10, 64)
		if err != nil || e < start {
			return cr, fmt.Errorf("transport: bad Range %q", v)
		}
		if e < end {
			end = e
		}
	}
	if start >= size {
		return cr, fmt.Errorf("transport: range start beyond size")
	}
	return ContentRange{Start: start, End: end, Total: size}, nil
}

// FetchRange performs a GET with "Range: bytes=off-" and an optional
// X-Ghostdrop-Token. It returns the response (caller closes Body) for the
// caller to stream; 200 (full) and 206 (partial) are both accepted.
func FetchRange(ctx context.Context, client *http.Client, url string, offset int64, token string) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	if token != "" {
		req.Header.Set("X-Ghostdrop-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("transport: GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

// PutChunk performs a single resumable PUT of exactly buf (len(buf) bytes)
// at offset off of a total-byte object, with an optional token.
func PutChunk(ctx context.Context, client *http.Client, url string, off int64, total int64, buf []byte, token string) error {
	if client == nil {
		client = http.DefaultClient
	}
	end := off + int64(len(buf)) - 1
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", FormatContentRange(off, end, total))
	req.ContentLength = int64(len(buf))
	if token != "" {
		req.Header.Set("X-Ghostdrop-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("transport: PUT %s: %s", url, resp.Status)
	}
	return nil
}
