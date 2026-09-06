package app

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

// Relay wire shapes (match the relay HTTP API contract).
type relayCreateReq struct {
	ID         string `json:"id"`
	SizeBytes  int64  `json:"size_bytes"`
	ExpiryRFC  string `json:"expiry_rfc3339"`
	OneTime    bool   `json:"one_time"`
}

type relayCreateResp struct {
	OK bool `json:"ok"`
}

type relayMeta struct {
	ID            string `json:"id"`
	SizeBytes     int64  `json:"size_bytes"`
	ExpiryRFC3339 string `json:"expiry_rfc3339"`
	OneTime       bool   `json:"one_time"`
	UploadedBytes int64  `json:"uploaded_bytes"`
}

// RelayClient speaks to a ghostdrop relay over HTTP.
type RelayClient struct {
	base  string
	token string
	http  *http.Client
}

// NewRelayClient builds a client for base (e.g. http://127.0.0.1:8080).
func NewRelayClient(base, token string) *RelayClient {
	return &RelayClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *RelayClient) req(ctx context.Context, method, path string, body io.Reader, hdr map[string]string) (*http.Response, error) {
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
	return c.http.Do(r)
}

// Create announces a drop.
func (c *RelayClient) Create(ctx context.Context, id string, size int64, expiry time.Time, oneTime bool) error {
	payload, _ := json.Marshal(relayCreateReq{ID: id, SizeBytes: size, ExpiryRFC: expiry.UTC().Format(time.RFC3339), OneTime: oneTime})
	resp, err := c.req(ctx, http.MethodPost, "/api/v1/drops", bytes.NewReader(payload),
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("relay create: %s", resp.Status)
	}
	return nil
}

// PutData uploads payload bytes with a single PUT (servers also accept
// Content-Range chunked PUTs; single-shot carries the full range).
func (c *RelayClient) PutData(ctx context.Context, id string, r io.Reader, size int64) error {
	hdr := map[string]string{"Content-Type": "application/octet-stream"}
	if size >= 0 {
		hdr["Content-Range"] = "bytes 0-" + strconv.FormatInt(size-1, 10) + "/" + strconv.FormatInt(size, 10)
	}
	resp, err := c.req(ctx, http.MethodPut, "/api/v1/drops/"+id+"/data", r, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("relay put: %s", resp.Status)
	}
	return nil
}

// Meta fetches drop metadata.
func (c *RelayClient) Meta(ctx context.Context, id string) (relayMeta, error) {
	var m relayMeta
	resp, err := c.req(ctx, http.MethodGet, "/api/v1/drops/"+id+"/meta", nil, nil)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return m, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return m, fmt.Errorf("relay meta: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return m, err
	}
	return m, nil
}

// GetDataRange fetches payload bytes from offset (Range resume).
func (c *RelayClient) GetDataRange(ctx context.Context, id string, offset int64) (io.ReadCloser, error) {
	hdr := map[string]string{}
	if offset > 0 {
		hdr["Range"] = "bytes=" + strconv.FormatInt(offset, 10) + "-"
	}
	resp, err := c.req(ctx, http.MethodGet, "/api/v1/drops/"+id+"/data", nil, hdr)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("relay get: %s", resp.Status)
	}
	return resp.Body, nil
}

// DeleteDrop removes a drop from the relay.
func (c *RelayClient) DeleteDrop(ctx context.Context, id string) error {
	resp, err := c.req(ctx, http.MethodDelete, "/api/v1/drops/"+id, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("relay delete: %s", resp.Status)
	}
	return nil
}

// Health pings the relay health endpoint.
func (c *RelayClient) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := c.req(ctx, http.MethodGet, "/api/v1/health", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relay health: %s", resp.Status)
	}
	return nil
}
