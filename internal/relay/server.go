// Package relay implements the Ghostdrop V1 relay server.
//
// The relay stores opaque ciphertext blobs on disk and serves them over HTTP.
// It never decrypts, inspects, or logs payload content, keys, or tokens:
// only drop IDs, byte counts, and offsets ever appear in responses or logs.
package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ghostdrop/internal/transport"
)

// TokenHeader is the per-drop auth header.
const TokenHeader = "X-Ghostdrop-Token"

// Config configures a Server.
type Config struct {
	// Addr is the TCP address to listen on, e.g. "127.0.0.1:8080".
	Addr string
	// DataDir holds {id}.bin + {id}.meta.json files. Created if missing.
	DataDir string
	// QuotaBytes caps total stored bytes across all live drops. <=0 = unlimited.
	QuotaBytes int64
	// RateLimit caps requests per second globally. <=0 = unlimited.
	RateLimit float64
	// SweepInterval controls the expiry sweeper tick. <=0 defaults to 1 minute.
	SweepInterval time.Duration
}

// CreateRequest is POST /api/v1/drops.
type CreateRequest struct {
	ID           string `json:"id"`
	SizeBytes    int64  `json:"size_bytes"`
	ExpiryRFC3339 string `json:"expiry_rfc3339"`
	OneTime      bool   `json:"one_time"`
}

// meta is the on-disk record for a drop ({id}.meta.json).
type meta struct {
	ID            string `json:"id"`
	SizeBytes     int64  `json:"size_bytes"`
	ExpiryRFC3339 string `json:"expiry_rfc3339"`
	OneTime       bool   `json:"one_time"`
	TokenHash     string `json:"token_hash"` // hex(sha256(token)); token itself never persisted
	UploadedBytes int64  `json:"uploaded_bytes"`
	CreatedAt     string `json:"created_at"`
	ServedFull    bool   `json:"served_full,omitempty"`
}

func (m *meta) expiry() (time.Time, error) {
	return time.Parse(time.RFC3339, m.ExpiryRFC3339)
}

func (m *meta) expired(now time.Time) bool {
	t, err := m.expiry()
	if err != nil {
		return true
	}
	return !now.Before(t)
}

// Server is a Ghostdrop relay: content-opaque blob store over HTTP.
type Server struct {
	cfg Config

	mu      sync.Mutex
	tokens  map[string]string // id -> tokenHash (memory mirror of meta files)
	locks   map[string]*sync.Mutex
	limiter *tokenBucket

	mux *http.ServeMux
	srv *http.Server

	startTime  time.Time
	bytesUp    int64
	bytesDown  int64
	sweepStop  chan struct{}
	sweepDone  chan struct{}
	sweepOnce  sync.Once
}

// tokenBucket is a minimal global rate limiter.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate float64) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	return &tokenBucket{rate: rate, burst: rate, tokens: rate, last: time.Now()}
}

func (b *tokenBucket) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// New creates a Server. DataDir is created if missing.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	if cfg.DataDir == "" {
		return nil, errors.New("relay: DataDir required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("relay: data dir: %w", err)
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = time.Minute
	}
	s := &Server{
		cfg:       cfg,
		tokens:    make(map[string]string),
		locks:     make(map[string]*sync.Mutex),
		limiter:   newBucket(cfg.RateLimit),
		sweepStop: make(chan struct{}),
		sweepDone: make(chan struct{}),
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("POST /api/v1/drops", s.handleCreate)
	s.mux.HandleFunc("PUT /api/v1/drops/{id}/data", s.handlePut)
	s.mux.HandleFunc("GET /api/v1/drops/{id}/data", s.handleGet)
	s.mux.HandleFunc("GET /api/v1/drops/{id}/meta", s.handleMeta)
	s.mux.HandleFunc("DELETE /api/v1/drops/{id}", s.handleDelete)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	s.srv = &http.Server{Addr: cfg.Addr, Handler: s.logWrap(s.mux)}
	if err := s.reloadTokens(); err != nil {
		return nil, err
	}
	return s, nil
}

// Handler exposes the routes for embedding/testing.
func (s *Server) Handler() http.Handler { return s.mux }

// Start serves until ctx is cancelled or Stop is called. It runs the expiry
// sweeper and shuts the listener down gracefully on context cancel.
func (s *Server) Start(ctx context.Context) error {
	s.startTime = time.Now()
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("relay: listen: %w", err)
	}
	go s.sweepLoop()
	go func() {
		<-ctx.Done()
		_ = s.srv.Shutdown(context.Background())
	}()
	err = s.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Stop shuts the server down gracefully and stops the sweeper.
func (s *Server) Stop(ctx context.Context) error {
	s.sweepOnce.Do(func() { close(s.sweepStop) })
	select {
	case <-s.sweepDone:
	case <-ctx.Done():
	}
	return s.srv.Shutdown(ctx)
}

// SweepNow deletes expired drops immediately. Used by tests and admin.
func (s *Server) SweepNow() (int, error) {
	return s.sweep(time.Now())
}

// ---- paths ----

func validID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	if id == "." || id == ".." || strings.Contains(id, "..") {
		return false
	}
	return true
}

func (s *Server) binPath(id string) string  { return filepath.Join(s.cfg.DataDir, id+".bin") }
func (s *Server) metaPath(id string) string { return filepath.Join(s.cfg.DataDir, id+".meta.json") }

func (s *Server) lockFor(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.locks[id]
	if !ok {
		l = &sync.Mutex{}
		s.locks[id] = l
	}
	return l
}

func (s *Server) loadMeta(id string) (*meta, error) {
	raw, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNotFound
		}
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Server) saveMeta(m *meta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := s.metaPath(m.ID) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.metaPath(m.ID))
}

// reloadTokens rebuilds the in-memory token index from meta files on disk.
func (s *Server) reloadTokens() error {
	ents, err := os.ReadDir(s.cfg.DataDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".meta.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, name))
		if err != nil {
			continue
		}
		var m meta
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		s.tokens[m.ID] = m.TokenHash
	}
	return nil
}

var errNotFound = errors.New("not found")

// storedBytes sums live .bin sizes for quota checks.
func (s *Server) storedBytes() int64 {
	var total int64
	ents, err := os.ReadDir(s.cfg.DataDir)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// checkToken constant-time compares the request token against the stored hash.
func (s *Server) checkToken(r *http.Request, wantHash string) bool {
	got := r.Header.Get(TokenHeader)
	if got == "" || wantHash == "" {
		return false
	}
	sum := sha256.Sum256([]byte(got))
	gotHash := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(gotHash), []byte(wantHash)) == 1
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func tokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

// logWrap enforces the global rate limit. It never logs tokens or content.
func (s *Server) logWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow() {
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- handlers ----

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "unreadable body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !validID(req.ID) {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if req.SizeBytes <= 0 {
		writeErr(w, http.StatusBadRequest, "size_bytes must be positive")
		return
	}
	exp, err := time.Parse(time.RFC3339, req.ExpiryRFC3339)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expiry_rfc3339 must be RFC3339")
		return
	}
	if !time.Now().Before(exp) {
		writeErr(w, http.StatusBadRequest, "expiry must be in the future")
		return
	}
	if s.cfg.QuotaBytes > 0 && s.storedBytes()+req.SizeBytes > s.cfg.QuotaBytes {
		writeErr(w, http.StatusInsufficientStorage, "quota exceeded")
		return
	}
	l := s.lockFor(req.ID)
	l.Lock()
	defer l.Unlock()
	if _, err := os.Stat(s.metaPath(req.ID)); err == nil {
		writeErr(w, http.StatusConflict, "drop exists")
		return
	}
	tok, err := newToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token failure")
		return
	}
	m := &meta{
		ID:            req.ID,
		SizeBytes:     req.SizeBytes,
		ExpiryRFC3339: req.ExpiryRFC3339,
		OneTime:       req.OneTime,
		TokenHash:     tokenHash(tok),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.saveMeta(m); err != nil {
		writeErr(w, http.StatusInternalServerError, "persist failure")
		return
	}
	f, err := os.OpenFile(s.binPath(req.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.Remove(s.metaPath(req.ID))
		writeErr(w, http.StatusInternalServerError, "persist failure")
		return
	}
	_ = f.Close()
	s.mu.Lock()
	s.tokens[req.ID] = m.TokenHash
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": req.ID, "token": tok})
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	l := s.lockFor(id)
	l.Lock()
	defer l.Unlock()
	m, err := s.loadMeta(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.checkToken(r, m.TokenHash) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if m.expired(time.Now()) {
		s.deleteLocked(m)
		writeErr(w, http.StatusGone, "expired")
		return
	}
	// Determine write offset: Content-Range for resume, else single-shot at 0.
	var off int64
	if cr := strings.TrimSpace(r.Header.Get("Content-Range")); cr != "" {
		parsed, err := transport.ParseContentRange(cr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid Content-Range")
			return
		}
		if parsed.Total != m.SizeBytes {
			writeErr(w, http.StatusBadRequest, "Content-Range total mismatch")
			return
		}
		off = parsed.Start
		if off != m.UploadedBytes {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "error": "offset mismatch", "uploaded_bytes": m.UploadedBytes,
			})
			return
		}
	} else if m.UploadedBytes != 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "error": "resume with Content-Range", "uploaded_bytes": m.UploadedBytes,
		})
		return
	}
	remain := m.SizeBytes - off
	if remain <= 0 {
		writeErr(w, http.StatusBadRequest, "drop already complete")
		return
	}
	f, err := os.OpenFile(s.binPath(id), os.O_WRONLY, 0o600)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, "seek failure")
		return
	}
	// Stream to disk, capped at the declared remainder. Never fully buffered.
	written, err := io.CopyN(f, r.Body, remain+1)
	if err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "truncated body")
		return
	}
	if written > remain {
		// Client sent more than declared: roll back to the prior offset
		// and reject; uploaded_bytes stays unchanged.
		_ = f.Truncate(off)
		writeErr(w, http.StatusBadRequest, "body exceeds declared size")
		return
	}
	m.UploadedBytes = off + written
	if err := s.saveMeta(m); err != nil {
		writeErr(w, http.StatusInternalServerError, "persist failure")
		return
	}
	s.mu.Lock()
	s.bytesUp += written
	s.mu.Unlock()
	complete := m.UploadedBytes == m.SizeBytes
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "uploaded_bytes": m.UploadedBytes, "complete": complete,
	})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	l := s.lockFor(id)
	l.Lock()
	m, err := s.loadMeta(id)
	if err != nil {
		l.Unlock()
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.checkToken(r, m.TokenHash) {
		l.Unlock()
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if m.expired(time.Now()) {
		s.deleteLocked(m)
		l.Unlock()
		writeErr(w, http.StatusGone, "expired")
		return
	}
	// One-time drops vanish after the first full GET.
	if m.OneTime && m.ServedFull {
		s.deleteLocked(m)
		l.Unlock()
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	f, err := os.Open(s.binPath(id))
	if err != nil {
		l.Unlock()
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	oneTime := m.OneTime
	fullRead := strings.TrimSpace(r.Header.Get("Range")) == ""
	l.Unlock()

	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", "application/octet-stream")
	// http.ServeContent handles Range (206 + Content-Range) and full (200)
	// delivery straight from disk with zero in-memory buffering.
	http.ServeContent(w, r, id+".bin", time.Time{}, &countingSeeker{ReadSeeker: f, n: &s.bytesDown, mu: &s.mu})
	// Close before any delete: Windows cannot remove an open file.
	_ = f.Close()

	if oneTime && fullRead {
		l := s.lockFor(id)
		l.Lock()
		if cur, err := s.loadMeta(id); err == nil && !cur.ServedFull {
			cur.ServedFull = true
			// Delete payload + record after the first full GET completes.
			s.deleteLocked(cur)
		}
		l.Unlock()
	}
}

// countingSeeker counts bytes served without buffering.
type countingSeeker struct {
	io.ReadSeeker
	n  *int64
	mu *sync.Mutex
}

func (c *countingSeeker) Read(p []byte) (int, error) {
	n, err := c.ReadSeeker.Read(p)
	if n > 0 {
		c.mu.Lock()
		*c.n += int64(n)
		c.mu.Unlock()
	}
	return n, err
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	m, err := s.loadMeta(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.checkToken(r, m.TokenHash) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if m.expired(time.Now()) {
		l := s.lockFor(id)
		l.Lock()
		s.deleteLocked(m)
		l.Unlock()
		writeErr(w, http.StatusGone, "expired")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"id": m.ID,
		"size_bytes": m.SizeBytes,
		"expiry_rfc3339": m.ExpiryRFC3339,
		"one_time": m.OneTime,
		"uploaded_bytes": m.UploadedBytes,
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	l := s.lockFor(id)
	l.Lock()
	defer l.Unlock()
	m, err := s.loadMeta(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.checkToken(r, m.TokenHash) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.deleteLocked(m)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// deleteLocked removes payload + meta. Caller holds lockFor(id).
func (s *Server) deleteLocked(m *meta) {
	_ = os.Remove(s.binPath(m.ID))
	_ = os.Remove(s.metaPath(m.ID))
	s.mu.Lock()
	delete(s.tokens, m.ID)
	s.mu.Unlock()
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "online"})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	ents, _ := os.ReadDir(s.cfg.DataDir)
	drops := 0
	var stored int64
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".bin")
		if _, err := os.Stat(s.metaPath(id)); err != nil {
			continue
		}
		drops++
		if fi, err := e.Info(); err == nil {
			stored += fi.Size()
		}
	}
	s.mu.Lock()
	up, down := s.bytesUp, s.bytesDown
	s.mu.Unlock()
	uptime := int64(0)
	if !s.startTime.IsZero() {
		uptime = int64(time.Since(s.startTime).Seconds())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"drops": drops,
		"bytes_stored": stored,
		"bytes_received": up,
		"bytes_served": down,
		"uptime_seconds": uptime,
	})
}

// sweep deletes expired drops; returns the count removed.
func (s *Server) sweep(now time.Time) (int, error) {
	ents, err := os.ReadDir(s.cfg.DataDir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".meta.json") {
			continue
		}
		id := strings.TrimSuffix(name, ".meta.json")
		if !validID(id) {
			continue
		}
		l := s.lockFor(id)
		l.Lock()
		m, err := s.loadMeta(id)
		if err == nil && m.expired(now) {
			s.deleteLocked(m)
			removed++
		}
		l.Unlock()
	}
	return removed, nil
}

func (s *Server) sweepLoop() {
	defer close(s.sweepDone)
	t := time.NewTicker(s.cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-s.sweepStop:
			return
		case <-t.C:
			_, _ = s.sweep(time.Now())
		}
	}
}

// Client is a minimal relay client used by tests and tooling.
type Client struct {
	Base   string
	HTTP   *http.Client
	Token  string
}

// url builds a path URL.
func (c *Client) url(p string) string { return strings.TrimSuffix(c.Base, "/") + p }

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// Create registers a drop and stores the returned per-drop token.
func (c *Client) Create(ctx context.Context, req CreateRequest) error {
	raw, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/v1/drops"), strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		OK    bool   `json:"ok"`
		ID    string `json:"id"`
		Token string `json:"token"`
		Err   string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != http.StatusCreated || !out.OK {
		if out.Err == "" {
			out.Err = resp.Status
		}
		return errors.New("relay create: " + out.Err)
	}
	c.Token = out.Token
	return nil
}

// Put uploads the full payload (single-shot, no Content-Range).
func (c *Client) Put(ctx context.Context, id string, payload []byte) error {
	return c.putRange(ctx, id, 0, int64(len(payload)), payload, false)
}

// PutResume uploads payload[off:] with Content-Range resume headers.
func (c *Client) PutResume(ctx context.Context, id string, total int64, off int64, chunk []byte) error {
	return c.putRange(ctx, id, off, total, chunk, true)
}

func (c *Client) putRange(ctx context.Context, id string, off, total int64, chunk []byte, ranged bool) error {
	end := off + int64(len(chunk)) - 1
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, c.url("/api/v1/drops/"+id+"/data"), bytes.NewReader(chunk))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/octet-stream")
	if ranged {
		r.Header.Set("Content-Range", transport.FormatContentRange(off, end, total))
	}
	r.ContentLength = int64(len(chunk))
	r.Header.Set(TokenHeader, c.Token)
	resp, err := c.http().Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return errors.New("relay put: " + resp.Status + " (" + id + " off=" + strconv.FormatInt(off, 10) + ")")
	}
	return nil
}

// Get downloads from offset (0 = full). Caller closes Body; 200 and 206 both
// accepted. Streams; never buffers fully.
func (c *Client) Get(ctx context.Context, id string, offset int64) (*http.Response, error) {
	return transport.FetchRange(ctx, c.http(), c.url("/api/v1/drops/"+id+"/data"), offset, c.Token)
}

// Meta fetches drop metadata.
func (c *Client) Meta(ctx context.Context, id string) (map[string]any, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/api/v1/drops/"+id+"/meta"), nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(TokenHeader, c.Token)
	resp, err := c.http().Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("relay meta: " + resp.Status)
	}
	return out, nil
}

// Delete removes a drop.
func (c *Client) Delete(ctx context.Context, id string) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url("/api/v1/drops/"+id), nil)
	if err != nil {
		return err
	}
	r.Header.Set(TokenHeader, c.Token)
	resp, err := c.http().Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return errors.New("relay delete: " + resp.Status)
	}
	return nil
}
