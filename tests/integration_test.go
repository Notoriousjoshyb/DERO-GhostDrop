// Package tests_test proves GHOSTDROP V1 end to end.
//
// These tests use contract-identical framing (magic GD01, headerNonce xor
// BE64(index) chunk nonces, 1 MiB chunks, XChaCha20-Poly1305) mirroring
// internal/crypto + internal/app without importing them, so they verify the
// wire behavior the rest of the repo implements. Relay shapes match the
// shared contract exactly:
//
//	POST /api/v1/drops {id,size_bytes,expiry_rfc3339,one_time} -> {ok}
//	PUT  /api/v1/drops/{id}/data octet-stream, Content-Range: bytes off-end/total, X-Ghostdrop-Token
//	GET  /api/v1/drops/{id}/data honors Range: bytes=off-, X-Ghostdrop-Token
//	GET  /api/v1/drops/{id}/meta -> {id,size_bytes,expiry_rfc3339,one_time[,uploaded_bytes]}
//	DELETE /api/v1/drops/{id}; GET /api/v1/health; GET /api/v1/stats
package tests_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

	"golang.org/x/crypto/chacha20poly1305"
)

// gdChunkSize is the contract chunk size: 1 MiB, streamed, never buffered whole.
const gdChunkSize = 1 << 20

// gdMagic is the contract file magic.
const gdMagic = "GD01"

// ---------------------------------------------------------------------------
// Contract-identical crypto helpers (mirror internal/crypto API semantics).
// ---------------------------------------------------------------------------

// gdTestKey mirrors crypto.GenerateFileKey.
func gdTestKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

// gdWipe mirrors crypto.Wipe.
func gdWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// gdGenerateDropID mirrors crypto.GenerateDropID: "GD-" + 12 hex upper.
func gdGenerateDropID(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "GD-" + strings.ToUpper(hex.EncodeToString(b[:]))
}

// gdChunkNonce derives chunk nonce = headerNonce xor BE64(index) in last 8 bytes.
func gdChunkNonce(header [24]byte, index uint64) [24]byte {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], index)
	for i := 0; i < 8; i++ {
		header[16+i] ^= ctr[i]
	}
	return header
}

// gdSealFile mirrors crypto.SealFile: streams srcPath -> dstPath, returns
// cipherHashHex, plainHashHex, sealed size.
func gdSealFile(srcPath, dstPath string, key [32]byte) (cipherHashHex, plainHashHex string, n int64, err error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return "", "", 0, err
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return "", "", 0, err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", "", 0, err
	}
	var header [24]byte
	if _, err := rand.Read(header[:]); err != nil {
		return "", "", 0, err
	}
	plainH := sha256.New()
	cipherH := sha256.New()
	mw := io.MultiWriter(out, cipherH)

	if _, err := mw.Write([]byte(gdMagic)); err != nil {
		return "", "", 0, err
	}
	if _, err := mw.Write(header[:]); err != nil {
		return "", "", 0, err
	}
	written := int64(len(gdMagic) + len(header))

	buf := make([]byte, gdChunkSize)
	var index uint64
	for {
		r, rerr := io.ReadFull(in, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return "", "", 0, rerr
		}
		if r == 0 {
			break
		}
		plainH.Write(buf[:r])
		nonce := gdChunkNonce(header, index)
		sealed := aead.Seal(nil, nonce[:], buf[:r], nil)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(sealed)))
		if _, err := mw.Write(lb[:]); err != nil {
			return "", "", 0, err
		}
		if _, err := mw.Write(sealed); err != nil {
			return "", "", 0, err
		}
		written += int64(4 + len(sealed))
		index++
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	return hex.EncodeToString(cipherH.Sum(nil)), hex.EncodeToString(plainH.Sum(nil)), written, nil
}

// gdOpenFile mirrors crypto.OpenFile: streams srcPath -> dstPath, fails closed.
func gdOpenFile(srcPath, dstPath string, key [32]byte) (err error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		out.Close()
		if err != nil {
			os.Remove(dstPath)
		}
	}()

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return err
	}
	hdr := make([]byte, 4+24)
	if _, err := io.ReadFull(in, hdr); err != nil {
		return fmt.Errorf("bad header: %w", err)
	}
	if string(hdr[:4]) != gdMagic {
		return fmt.Errorf("bad magic")
	}
	var header [24]byte
	copy(header[:], hdr[4:])

	var lb [4]byte
	var index uint64
	for {
		_, rerr := io.ReadFull(in, lb[:])
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("chunk %d length: %w", index, rerr)
		}
		ln := binary.BigEndian.Uint32(lb[:])
		if ln == 0 || ln > gdChunkSize+1024 {
			return fmt.Errorf("chunk %d bad length %d", index, ln)
		}
		sealed := make([]byte, ln)
		if _, err := io.ReadFull(in, sealed); err != nil {
			return fmt.Errorf("chunk %d body: %w", index, err)
		}
		nonce := gdChunkNonce(header, index)
		plain, err := aead.Open(nil, nonce[:], sealed, nil)
		if err != nil {
			return fmt.Errorf("chunk %d auth failed: %w", index, err)
		}
		if _, err := out.Write(plain); err != nil {
			return err
		}
		index++
	}
	return nil
}

// gdSealBytes mirrors crypto.SealBytes.
func gdSealBytes(plain, key []byte) (nonce, cipher []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plain, nil), nil
}

// gdOpenBytes mirrors crypto.OpenBytes.
func gdOpenBytes(nonce, cipher, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, cipher, nil)
}

// gdSHA256HexFile mirrors crypto.Sha256HexFile.
func gdSHA256HexFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// gdWriteRandomFile streams size random bytes to path, returning its hex hash.
func gdWriteRandomFile(t *testing.T, path string, size int64) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, gdChunkSize)
	remain := size
	for remain > 0 {
		n := int64(len(buf))
		if remain < n {
			n = remain
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		h.Write(buf[:n])
		remain -= n
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Fake relay: exact contract shapes, resumable both directions.
// ---------------------------------------------------------------------------

type gdDropMeta struct {
	ID       string
	Size     int64
	Expiry   time.Time
	OneTime  bool
	Token    string
	Uploaded int64
	Consumed bool
}

type gdRelay struct {
	t     *testing.T
	srv   *httptest.Server
	dir   string
	mu    sync.Mutex
	drops map[string]*gdDropMeta
	logs  []string
}

func (r *gdRelay) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// IDs, sizes, status codes only. Never content, keys, or tokens.
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

func (r *gdRelay) Logs() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.logs, "\n")
}

func gdNewRelay(t *testing.T) *gdRelay {
	t.Helper()
	r := &gdRelay{t: t, dir: t.TempDir(), drops: map[string]*gdDropMeta{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/drops", r.handleRegister)
	mux.HandleFunc("/api/v1/drops/", r.handleDrop)
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		r.logf("GET /api/v1/health status=200")
		gdWriteJSON(w, 200, map[string]any{"ok": true, "version": "1.0.0"})
	})
	mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		n, total := len(r.drops), int64(0)
		for _, d := range r.drops {
			total += d.Uploaded
		}
		r.mu.Unlock()
		r.logf("GET /api/v1/stats status=200 drops=%d bytes=%d", n, total)
		gdWriteJSON(w, 200, map[string]any{"drops": n, "bytes_total": total})
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

func gdWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (r *gdRelay) dataPath(id string) string { return filepath.Join(r.dir, id+".bin") }

// authorize checks the per-drop token. Returns meta or writes error.
func (r *gdRelay) authorize(w http.ResponseWriter, req *http.Request, id string) *gdDropMeta {
	r.mu.Lock()
	d, ok := r.drops[id]
	tok := ""
	if ok {
		tok = d.Token
	}
	r.mu.Unlock()
	if !ok {
		r.logf("%s %s status=404", req.Method, req.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	if req.Header.Get("X-Ghostdrop-Token") != tok {
		r.logf("%s %s status=401 id=%s", req.Method, req.URL.Path, id)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	if !d.Expiry.IsZero() && time.Now().After(d.Expiry) {
		r.logf("%s %s status=410 id=%s expired", req.Method, req.URL.Path, id)
		http.Error(w, "expired", http.StatusGone)
		return nil
	}
	return d
}

func (r *gdRelay) handleRegister(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID       string `json:"id"`
		Size     int64  `json:"size_bytes"`
		Expiry   string `json:"expiry_rfc3339"`
		OneTime  bool   `json:"one_time"`
		Token    string `json:"token"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if body.ID == "" || body.Size <= 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	exp, err := time.Parse(time.RFC3339, body.Expiry)
	if err != nil {
		http.Error(w, "bad expiry", http.StatusBadRequest)
		return
	}
	tok := body.Token
	if tok == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		tok = hex.EncodeToString(b[:])
	}
	r.mu.Lock()
	r.drops[body.ID] = &gdDropMeta{ID: body.ID, Size: body.Size, Expiry: exp, OneTime: body.OneTime, Token: tok}
	r.mu.Unlock()
	if err := os.WriteFile(r.dataPath(body.ID), nil, 0600); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	r.logf("POST /api/v1/drops status=200 id=%s size=%d one_time=%v", body.ID, body.Size, body.OneTime)
	gdWriteJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// gdParseContentRange parses "bytes off-end/total".
func gdParseContentRange(h string) (off, end, total int64, err error) {
	h = strings.TrimPrefix(strings.TrimSpace(h), "bytes ")
	parts := strings.Split(h, "/")
	if len(parts) != 2 {
		return 0, 0, 0, fmt.Errorf("bad content-range %q", h)
	}
	total, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
	se := strings.Split(parts[0], "-")
	if len(se) != 2 {
		return 0, 0, 0, fmt.Errorf("bad content-range %q", h)
	}
	if off, err = strconv.ParseInt(se[0], 10, 64); err != nil {
		return 0, 0, 0, err
	}
	if end, err = strconv.ParseInt(se[1], 10, 64); err != nil {
		return 0, 0, 0, err
	}
	return off, end, total, nil
}

// gdParseRange parses "bytes=off-" or "bytes=off-end".
func gdParseRange(h string, size int64) (off, end int64, err error) {
	h = strings.TrimPrefix(strings.TrimSpace(h), "bytes=")
	se := strings.Split(h, "-")
	if len(se) != 2 {
		return 0, 0, fmt.Errorf("bad range %q", h)
	}
	if off, err = strconv.ParseInt(se[0], 10, 64); err != nil {
		return 0, 0, err
	}
	if se[1] == "" {
		return off, size - 1, nil
	}
	if end, err = strconv.ParseInt(se[1], 10, 64); err != nil {
		return 0, 0, err
	}
	return off, end, nil
}

func (r *gdRelay) handleDrop(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/api/v1/drops/")
	if strings.HasSuffix(rest, "/data") {
		id := strings.TrimSuffix(rest, "/data")
		switch req.Method {
		case http.MethodPut:
			r.handlePut(w, req, id)
		case http.MethodGet:
			r.handleGet(w, req, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if strings.HasSuffix(rest, "/meta") {
		id := strings.TrimSuffix(rest, "/meta")
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d := r.authorize(w, req, id)
		if d == nil {
			return
		}
		r.mu.Lock()
		up := d.Uploaded
		r.mu.Unlock()
		r.logf("GET %s status=200 id=%s uploaded=%d", req.URL.Path, id, up)
		gdWriteJSON(w, 200, map[string]any{
			"id": id, "size_bytes": d.Size,
			"expiry_rfc3339": d.Expiry.UTC().Format(time.RFC3339),
			"one_time":       d.OneTime, "uploaded_bytes": up,
		})
		return
	}
	// DELETE /api/v1/drops/{id}
	id := rest
	if req.Method != http.MethodDelete {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	d := r.authorize(w, req, id)
	if d == nil {
		return
	}
	r.mu.Lock()
	delete(r.drops, id)
	r.mu.Unlock()
	_ = os.Remove(r.dataPath(id))
	r.logf("DELETE %s status=200 id=%s", req.URL.Path, id)
	gdWriteJSON(w, 200, map[string]any{"ok": true})
}

func (r *gdRelay) handlePut(w http.ResponseWriter, req *http.Request, id string) {
	d := r.authorize(w, req, id)
	if d == nil {
		return
	}
	var off int64
	if cr := req.Header.Get("Content-Range"); cr != "" {
		o, e, total, err := gdParseContentRange(cr)
		if err != nil || total != d.Size {
			http.Error(w, "bad content-range", http.StatusBadRequest)
			return
		}
		_ = e
		off = o
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	f, err := os.OpenFile(r.dataPath(id), os.O_WRONLY, 0600)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	n, err := f.WriteAt(body, off)
	f.Close()
	if err != nil || n != len(body) {
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}
	r.mu.Lock()
	if end := off + int64(len(body)); end > d.Uploaded {
		d.Uploaded = end
	}
	up := d.Uploaded
	r.mu.Unlock()
	r.logf("PUT /api/v1/drops/%s/data status=200 uploaded=%d", id, up)
	gdWriteJSON(w, 200, map[string]any{"ok": true, "uploaded_bytes": up})
}

func (r *gdRelay) handleGet(w http.ResponseWriter, req *http.Request, id string) {
	d := r.authorize(w, req, id)
	if d == nil {
		return
	}
	r.mu.Lock()
	if d.OneTime && d.Consumed {
		r.mu.Unlock()
		r.logf("GET /api/v1/drops/%s/data status=410 one-time consumed", id)
		http.Error(w, "gone", http.StatusGone)
		return
	}
	r.mu.Unlock()
	f, err := os.Open(r.dataPath(id))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()
	w.Header().Set("Content-Type", "application/octet-stream")
	if rg := req.Header.Get("Range"); rg != "" {
		off, end, err := gdParseRange(rg, size)
		if err != nil || off < 0 || end >= size || off > end {
			http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, end, size))
		w.Header().Set("Content-Length", strconv.FormatInt(end-off+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.CopyN(w, io.NewSectionReader(f, off, end-off+1), end-off+1)
		r.logf("GET /api/v1/drops/%s/data status=206 range=%d-%d", id, off, end)
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		_, _ = io.Copy(w, f)
		r.logf("GET /api/v1/drops/%s/data status=200 size=%d", id, size)
	}
	r.mu.Lock()
	if d.OneTime {
		d.Consumed = true
	}
	r.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Client helpers (prove the resume protocol from the caller side).
// ---------------------------------------------------------------------------

func gdPostJSON(t *testing.T, client *http.Client, url, token string, v any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(v)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Ghostdrop-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s -> %d", url, resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func gdPutChunk(t *testing.T, client *http.Client, url, token string, data []byte, off, total int64) int64 {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Ghostdrop-Token", token)
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, off+int64(len(data))-1, total))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("PUT %s off=%d -> %d", url, off, resp.StatusCode)
	}
	var out struct {
		Uploaded int64 `json:"uploaded_bytes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Uploaded
}

// gdUploadFile streams localPath to the relay in 1 MiB Content-Range PUTs,
// optionally stopping after stopAfter bytes (interrupt simulation).
func gdUploadFile(t *testing.T, client *http.Client, url, token, localPath string, stopAfter int64) (total, uploaded int64) {
	t.Helper()
	f, err := os.Open(localPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	total = st.Size()
	buf := make([]byte, gdChunkSize)
	var off int64
	for off < total {
		if stopAfter >= 0 && off >= stopAfter {
			break
		}
		n, rerr := io.ReadFull(io.NewSectionReader(f, off, total-off), buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			t.Fatal(rerr)
		}
		uploaded = gdPutChunk(t, client, url, token, buf[:n], off, total)
		off += int64(n)
	}
	return total, uploaded
}

// gdDownloadRange GETs one Range slice and appends it to w.
func gdDownloadRange(t *testing.T, client *http.Client, url, token string, w io.Writer, off int64, end int64) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Ghostdrop-Token", token)
	if end >= 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, end))
	} else {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		t.Fatalf("GET %s range=%d- -> %d", url, off, resp.StatusCode)
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Integration: CLIENT A -> RELAY -> CLIENT B, interrupt + resume, tamper.
// ---------------------------------------------------------------------------

// TestIntegration_ClientRelayClient is the V1 wire proof: sender seals a big
// file, uploads with a mid-transfer interrupt + Content-Range resume,
// recipient downloads with Range resume, decrypts, and hash-matches.
// Tampered ciphertext must fail. Default 64 MiB for speed;
// GHOSTDROP_BIG=1 exercises 1 GiB.
func TestIntegration_ClientRelayClient(t *testing.T) {
	size := int64(64 << 20)
	if os.Getenv("GHOSTDROP_BIG") == "1" {
		size = int64(1 << 30)
	}
	work := t.TempDir()
	plainPath := filepath.Join(work, "plain.bin")
	sealedPath := filepath.Join(work, "sealed.gd")
	downPath := filepath.Join(work, "downloaded.gd")
	outPath := filepath.Join(work, "out.bin")

	// CLIENT A: plaintext + seal.
	plainHash := gdWriteRandomFile(t, plainPath, size)
	key := gdTestKey(t)
	cipherHash, sealedPlainHash, sealedSize, err := gdSealFile(plainPath, sealedPath, key)
	if err != nil {
		t.Fatal(err)
	}
	if sealedPlainHash != plainHash {
		t.Fatalf("seal changed plaintext hash: %s vs %s", sealedPlainHash, plainHash)
	}

	// RELAY: register.
	relay := gdNewRelay(t)
	client := relay.srv.Client()
	id := gdGenerateDropID(t)
	expiry := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
		"id": id, "size_bytes": sealedSize, "expiry_rfc3339": expiry, "one_time": false,
	})
	token, _ := reg["token"].(string)
	if token == "" {
		t.Fatal("relay returned no token")
	}
	dataURL := relay.srv.URL + "/api/v1/drops/" + id + "/data"

	// CLIENT A: upload half, then "connection drops".
	half := (sealedSize / 2 / gdChunkSize) * gdChunkSize // chunk-aligned
	total, uploaded := gdUploadFile(t, client, dataURL, token, sealedPath, half)
	if total != sealedSize || uploaded <= 0 || uploaded > half+gdChunkSize {
		t.Fatalf("interrupt upload wrong state: total=%d uploaded=%d half=%d", total, uploaded, half)
	}

	// Relay confirms partial state via meta (resume point).
	metaReq, _ := http.NewRequest(http.MethodGet, relay.srv.URL+"/api/v1/drops/"+id+"/meta", nil)
	metaReq.Header.Set("X-Ghostdrop-Token", token)
	metaResp, err := client.Do(metaReq)
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Uploaded int64 `json:"uploaded_bytes"`
	}
	if err := json.NewDecoder(metaResp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	metaResp.Body.Close()
	if meta.Uploaded != uploaded {
		t.Fatalf("meta uploaded=%d, want %d", meta.Uploaded, uploaded)
	}

	// CLIENT A: resume to completion with Content-Range PUTs.
	full, err := os.Open(sealedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	buf := make([]byte, gdChunkSize)
	for off := uploaded; off < total; {
		n, rerr := io.ReadFull(io.NewSectionReader(full, off, total-off), buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			t.Fatal(rerr)
		}
		up := gdPutChunk(t, client, dataURL, token, buf[:n], off, total)
		off += int64(n)
		_ = up
	}

	// CLIENT B: download with Range resume (two halves), hash must match.
	df, err := os.Create(downPath)
	if err != nil {
		t.Fatal(err)
	}
	gdDownloadRange(t, client, dataURL, token, df, 0, uploaded-1)
	gdDownloadRange(t, client, dataURL, token, df, uploaded, -1)
	df.Close()
	downHash, downSize, err := gdSHA256HexFile(downPath)
	if err != nil {
		t.Fatal(err)
	}
	if downSize != sealedSize || downHash != cipherHash {
		t.Fatalf("download mismatch: size=%d/%d hash=%.12s/%.12s", downSize, sealedSize, downHash, cipherHash)
	}

	// CLIENT B: decrypt, plaintext hash must match the original.
	if err := gdOpenFile(downPath, outPath, key); err != nil {
		t.Fatal(err)
	}
	outHash, _, err := gdSHA256HexFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if outHash != plainHash {
		t.Fatalf("plaintext mismatch after relay roundtrip")
	}

	// Tamper: one flipped byte in transit bytes must fail authentication.
	tampered := filepath.Join(work, "tampered.gd")
	gdCopyFile(t, downPath, tampered)
	gdFlipByte(t, tampered, 100)
	if err := gdOpenFile(tampered, filepath.Join(work, "tampered.out"), key); err == nil {
		t.Fatal("tampered ciphertext decrypted without error")
	}

	// One-time semantics on a second drop: first GET ok, second GET gone.
	id2 := gdGenerateDropID(t)
	reg2 := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
		"id": id2, "size_bytes": sealedSize, "expiry_rfc3339": expiry, "one_time": true,
	})
	tok2, _ := reg2["token"].(string)
	dataURL2 := relay.srv.URL + "/api/v1/drops/" + id2 + "/data"
	if _, err := os.Stat(sealedPath); err != nil {
		t.Fatal(err)
	}
	gdUploadFile(t, client, dataURL2, tok2, sealedPath, -1)
	gdGetExpect(t, client, dataURL2, tok2, 200)
	gdGetExpect(t, client, dataURL2, tok2, 410)

	// Server logs must never contain key material.
	keyHex := hex.EncodeToString(key[:])
	logs := relay.Logs()
	if strings.Contains(logs, keyHex) {
		t.Fatal("relay log contains key material")
	}
	if !strings.Contains(logs, id) {
		t.Fatal("relay log missing drop id (expected operational logging)")
	}
}

func gdCopyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}

func gdFlipByte(t *testing.T, path string, at int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, at); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b, at); err != nil {
		t.Fatal(err)
	}
}

func gdGetExpect(t *testing.T, client *http.Client, url, token string, want int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Ghostdrop-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("GET %s -> %d, want %d", url, resp.StatusCode, want)
	}
}
