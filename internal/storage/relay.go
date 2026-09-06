package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Relay API paths.
const (
	relayAPIBase   = "/api/v1"
	relayHealth    = relayAPIBase + "/health"
	relayDrops     = relayAPIBase + "/drops"
	relayChunkSize = 1 << 20 // 1 MiB streaming chunks
)

// RelayClient implements Provider over the Ghostdrop relay HTTP API.
// Payloads stream in 1 MiB Content-Range chunks; the client never retains
// plaintext beyond the in-flight chunk.
type RelayClient struct {
	base   string
	token  string
	http   *http.Client
	chunk  int
}

// NewRelayClient returns a relay provider for baseURL (e.g.
// http://127.0.0.1:8080) with the per-drop token.
func NewRelayClient(baseURL, token string) *RelayClient {
	return &RelayClient{
		base:  strings.TrimSuffix(strings.TrimSpace(baseURL), "/"),
		token: token,
		http:  &http.Client{Timeout: 60 * time.Second},
		chunk: relayChunkSize,
	}
}

// SetToken replaces the per-drop token.
func (c *RelayClient) SetToken(token string) { c.token = token }

// Backend implements Provider.
func (c *RelayClient) Backend() string { return BackendRelay }

func (c *RelayClient) req(ctx context.Context, method, path string, body io.Reader, hdr map[string]string) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		r.Header.Set("X-Ghostdrop-Token", c.token)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r, nil
}

// relayMeta is the tolerant decode of GET .../meta responses.
type relayMeta struct {
	Size   int64
	Expiry time.Time
}

func parseMeta(raw []byte) (relayMeta, error) {
	var m relayMeta
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return m, err
	}
	num := func(keys ...string) int64 {
		for _, k := range keys {
			if v, ok := obj[k]; ok {
				var n json.Number
				if err := json.Unmarshal(v, &n); err == nil {
					if i, err := n.Int64(); err == nil {
						return i
					}
				}
				var f float64
				if err := json.Unmarshal(v, &f); err == nil {
					return int64(f)
				}
			}
		}
		return -1
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := obj[k]; ok {
				var s string
				if err := json.Unmarshal(v, &s); err == nil {
					return s
				}
			}
		}
		return ""
	}
	// Prefer uploaded_bytes when the server reports partial progress, so
	// Stat reflects bytes actually held (resume offset source).
	if n := num("uploaded_bytes", "uploaded", "offset"); n >= 0 {
		m.Size = n
	} else {
		m.Size = num("size_bytes", "size", "total", "length")
	}
	if s := str("expiry_rfc3339", "expiry", "expires_at"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			m.Expiry = t
		}
	}
	return m, nil
}

func statusErr(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusGone:
		return ErrExpired
	case http.StatusInsufficientStorage, http.StatusForbidden:
		return ErrQuota
	default:
		return fmt.Errorf("storage: relay status %s", resp.Status)
	}
}

// create announces the drop; 409 Conflict means it already exists (resume).
func (c *RelayClient) create(ctx context.Context, id string, size int64, expiry time.Time) error {
	body, _ := json.Marshal(map[string]any{
		"id":             id,
		"size_bytes":     size,
		"expiry_rfc3339": expiry.UTC().Format(time.RFC3339),
		"one_time":       false,
	})
	r, err := c.req(ctx, http.MethodPost, relayDrops, bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return err
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusConflict:
		return nil
	default:
		return statusErr(resp)
	}
}

// uploaded queries the server-side offset via the meta endpoint.
// Unknown (−1) means "start at 0".
func (c *RelayClient) uploaded(ctx context.Context, id string) int64 {
	meta, err := c.stat(ctx, id)
	if err != nil {
		return 0
	}
	return meta.Size
}

// stat fetches and parses the meta endpoint.
func (c *RelayClient) stat(ctx context.Context, id string) (relayMeta, error) {
	var m relayMeta
	r, err := c.req(ctx, http.MethodGet, relayDrops+"/"+id+"/meta", nil, nil)
	if err != nil {
		return m, err
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return m, statusErr(resp)
	}
	return parseMeta(raw)
}

// Put implements Provider with 1 MiB Content-Range chunked resume.
func (c *RelayClient) Put(ctx context.Context, id string, r io.Reader, size int64, expiry time.Time) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("storage: negative size")
	}
	if err := c.create(ctx, id, size, expiry); err != nil {
		return err
	}
	off := c.uploaded(ctx, id)
	if off < 0 {
		off = 0
	}
	if off > size {
		return fmt.Errorf("storage: server offset %d beyond size %d", off, size)
	}
	// Discard already-uploaded prefix for resume.
	if off > 0 {
		if _, err := io.CopyN(io.Discard, r, off); err != nil {
			return fmt.Errorf("storage: resume skip: %w", err)
		}
	}
	if size == 0 {
		pr, err := c.req(ctx, http.MethodPut, relayDrops+"/"+id+"/data", http.NoBody,
			map[string]string{"Content-Type": "application/octet-stream"})
		if err != nil {
			return err
		}
		resp, err := c.http.Do(pr)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return statusErr(resp)
		}
		return nil
	}
	buf := make([]byte, c.chunk)
	for off < size {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := int64(len(buf))
		if size-off < want {
			want = size - off
		}
		n, err := io.ReadFull(r, buf[:want])
		if err != nil {
			return fmt.Errorf("storage: short read: got %d want %d", off+int64(n), size)
		}
		end := off + int64(n) - 1
		var lastErr error
		for range 3 {
			pr, err := c.req(ctx, http.MethodPut, relayDrops+"/"+id+"/data", bytes.NewReader(buf[:n]),
				map[string]string{
					"Content-Type":  "application/octet-stream",
					"Content-Range": "bytes " + strconv.FormatInt(off, 10) + "-" + strconv.FormatInt(end, 10) + "/" + strconv.FormatInt(size, 10),
				})
			if err != nil {
				return err
			}
			resp, err := c.http.Do(pr)
			if err != nil {
				lastErr = err
				continue
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK, http.StatusCreated, http.StatusPartialContent:
				lastErr = nil
			default:
				lastErr = statusErr(resp)
			}
			if lastErr == nil {
				break
			}
		}
		if lastErr != nil {
			return lastErr
		}
		off += int64(n)
	}
	return nil
}

// Get implements Provider with Range resume.
func (c *RelayClient) Get(ctx context.Context, id string, offset int64) (io.ReadCloser, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, fmt.Errorf("storage: negative offset")
	}
	hdr := map[string]string{}
	if offset > 0 {
		hdr["Range"] = "bytes=" + strconv.FormatInt(offset, 10) + "-"
	}
	r, err := c.req(ctx, http.MethodGet, relayDrops+"/"+id+"/data", nil, hdr)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		return resp.Body, nil
	default:
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, statusErr(resp)
	}
}

// Delete implements Provider (idempotent).
func (c *RelayClient) Delete(ctx context.Context, id string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	r, err := c.req(ctx, http.MethodDelete, relayDrops+"/"+id, nil, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return statusErr(resp)
	}
	return nil
}

// Exists implements Provider. Past-expiry drops report false.
func (c *RelayClient) Exists(ctx context.Context, id string) (bool, error) {
	if err := ValidateID(id); err != nil {
		return false, err
	}
	meta, err := c.stat(ctx, id)
	if err == ErrNotFound || err == ErrExpired {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !meta.Expiry.IsZero() && time.Now().After(meta.Expiry) {
		return false, nil
	}
	return true, nil
}

// Stat implements Provider. Past-expiry drops report ErrExpired.
func (c *RelayClient) Stat(ctx context.Context, id string) (int64, time.Time, error) {
	if err := ValidateID(id); err != nil {
		return 0, time.Time{}, err
	}
	m, err := c.stat(ctx, id)
	if err != nil {
		return 0, time.Time{}, err
	}
	if !m.Expiry.IsZero() && time.Now().After(m.Expiry) {
		return 0, time.Time{}, ErrExpired
	}
	return m.Size, m.Expiry, nil
}

// Health implements Provider.
func (c *RelayClient) Health(ctx context.Context) error {
	r, err := c.req(ctx, http.MethodGet, relayHealth, nil, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return statusErr(resp)
	}
	return nil
}
