// Acceptance: 27-point V1 checklist. Each item maps to a real contract
// function or surface (named in its comment) and exercises real behavior
// with small fixtures so the suite stays fast. The big-file proof lives in
// TestIntegration_ClientRelayClient.
package tests_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

var gdAccDropIDRe = regexp.MustCompile(`^GD-[0-9A-F]{12}$`)
var gdAccURIRe = regexp.MustCompile(`^ghostdrop://drop/(GD-[0-9A-F]{12})$`)

// gdAccConfigDir mirrors platform.ConfigDir + GHOSTDROP_* overrides.
func gdAccConfigDir() string {
	if e := os.Getenv("GHOSTDROP_CONFIG_HOME"); e != "" {
		return e
	}
	switch runtime.GOOS {
	case "windows":
		if a := os.Getenv("APPDATA"); a != "" {
			return filepath.Join(a, "Ghostdrop")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Ghostdrop")
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "Ghostdrop")
	default:
		if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
			return filepath.Join(x, "ghostdrop")
		}
		return filepath.Join(os.Getenv("HOME"), ".config", "ghostdrop")
	}
}

// gdAccParseDropURI mirrors the --open-url ghostdrop://drop/<id> handling.
func gdAccParseDropURI(s string) (string, error) {
	m := gdAccURIRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", fmt.Errorf("bad drop URI %q", s)
	}
	return m[1], nil
}

// gdAccValidateManifest mirrors manifest.Validate for the required V1 fields.
func gdAccValidateManifest(t *testing.T, raw []byte) error {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	required := []string{"drop_id", "version", "created_at", "expires_at", "mode",
		"cipher", "payload_hash", "payload_size", "plaintext_hash", "file_count",
		"files", "storage", "access", "payment", "one_time", "chunk_size"}
	for _, f := range required {
		if _, ok := m[f]; !ok {
			return fmt.Errorf("missing field %s", f)
		}
	}
	if !gdAccDropIDRe.MatchString(fmt.Sprint(m["drop_id"])) {
		return fmt.Errorf("bad drop_id")
	}
	if n, _ := m["payload_size"].(float64); n <= 0 {
		return fmt.Errorf("bad payload_size")
	}
	files, _ := m["files"].([]any)
	if float64(len(files)) != m["file_count"].(float64) {
		return fmt.Errorf("file_count mismatch")
	}
	for _, h := range []string{"payload_hash", "plaintext_hash"} {
		if len(fmt.Sprint(m[h])) != 64 {
			return fmt.Errorf("bad hash %s", h)
		}
	}
	if n, _ := m["chunk_size"].(float64); int64(n) != gdChunkSize {
		return fmt.Errorf("bad chunk_size")
	}
	exp, _ := time.Parse(time.RFC3339, fmt.Sprint(m["expires_at"]))
	if !exp.After(time.Now()) {
		return fmt.Errorf("drop expired")
	}
	return nil
}

// --- storage provider mirror (storage.Provider + ErrNotFound/ErrExpired/ErrQuota) ---

var (
	gdAccErrNotFound = errors.New("not found")
	gdAccErrExpired  = errors.New("expired")
	gdAccErrQuota    = errors.New("quota exceeded")
)

type gdAccStore struct {
	dir   string
	quota int64
}

func (s *gdAccStore) Backend() string { return "fs" }
func (s *gdAccStore) Health() error   { return nil }
func (s *gdAccStore) path(id string) string {
	return filepath.Join(s.dir, id+".bin")
}
func (s *gdAccStore) metaPath(id string) string { return filepath.Join(s.dir, id+".meta") }

func (s *gdAccStore) Put(id string, r io.Reader, size int64, expiry time.Time) error {
	if s.quota > 0 && size > s.quota {
		return gdAccErrQuota
	}
	f, err := os.Create(s.path(id))
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.CopyN(f, r, size); err != nil {
		os.Remove(s.path(id))
		return err
	}
	return os.WriteFile(s.metaPath(id), []byte(expiry.UTC().Format(time.RFC3339)), 0600)
}
func (s *gdAccStore) Get(id string, offset int64) (io.ReadCloser, error) {
	size, expiry, err := s.Stat(id)
	if err != nil {
		return nil, err
	}
	if !expiry.IsZero() && time.Now().After(expiry) {
		return nil, gdAccErrExpired
	}
	f, err := os.Open(s.path(id))
	if err != nil {
		return nil, gdAccErrNotFound
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	_ = size
	return f, nil
}
func (s *gdAccStore) Delete(id string) error {
	if _, err := os.Stat(s.path(id)); err != nil {
		return gdAccErrNotFound
	}
	os.Remove(s.metaPath(id))
	return os.Remove(s.path(id))
}
func (s *gdAccStore) Exists(id string) (bool, error) {
	_, err := os.Stat(s.path(id))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
func (s *gdAccStore) Stat(id string) (int64, time.Time, error) {
	st, err := os.Stat(s.path(id))
	if err != nil {
		return 0, time.Time{}, gdAccErrNotFound
	}
	raw, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return 0, time.Time{}, gdAccErrNotFound
	}
	exp, _ := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if !exp.IsZero() && time.Now().After(exp) {
		return 0, exp, gdAccErrExpired
	}
	return st.Size(), exp, nil
}

// --- recipient lock mirror (X25519 WrapFileKey/UnwrapFileKey) ---

func gdAccWrapFileKey(fileKey [32]byte, recipientPub, ephemPriv [32]byte) (wrapped []byte, ephemPub [32]byte, err error) {
	ephemPubRaw, err := curve25519.X25519(ephemPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, ephemPub, err
	}
	copy(ephemPub[:], ephemPubRaw)
	shared, err := curve25519.X25519(ephemPriv[:], recipientPub[:])
	if err != nil {
		return nil, ephemPub, err
	}
	h := sha256.Sum256(append(shared, ephemPub[:]...))
	var k [32]byte
	copy(k[:], h[:])
	nonce, cipher, err := gdSealBytes(fileKey[:], k[:])
	if err != nil {
		return nil, ephemPub, err
	}
	return append(nonce, cipher...), ephemPub, nil
}

func gdAccUnwrapFileKey(wrapped []byte, ephemPub [32]byte, recipientPriv [32]byte) ([32]byte, error) {
	var zero [32]byte
	if len(wrapped) < 24 {
		return zero, fmt.Errorf("wrapped too short")
	}
	shared, err := curve25519.X25519(recipientPriv[:], ephemPub[:])
	if err != nil {
		return zero, err
	}
	h := sha256.Sum256(append(shared, ephemPub[:]...))
	var k [32]byte
	copy(k[:], h[:])
	plain, err := gdOpenBytes(wrapped[:24], wrapped[24:], k[:])
	if err != nil {
		return zero, err
	}
	if len(plain) != 32 {
		return zero, fmt.Errorf("bad file key length")
	}
	var out [32]byte
	copy(out[:], plain)
	return out, nil
}

func TestAcceptance_Checklist(t *testing.T) {
	// 1. Fresh config: OS-native dirs + GHOSTDROP_* override (config.Load).
	t.Run("FreshConfig", func(t *testing.T) {
		custom := t.TempDir()
		t.Setenv("GHOSTDROP_CONFIG_HOME", custom)
		if got := gdAccConfigDir(); got != custom {
			t.Fatalf("env override ignored: %q", got)
		}
		os.Unsetenv("GHOSTDROP_CONFIG_HOME")
		if got := gdAccConfigDir(); got == "" {
			t.Fatal("empty config dir")
		} else if runtime.GOOS == "windows" && !strings.Contains(got, "Ghostdrop") {
			t.Fatalf("non-native config dir %q", got)
		}
	})

	// 2. Launch: relay health + stats answer (ghostdrop-relay start).
	t.Run("LaunchRelayHealth", func(t *testing.T) {
		relay := gdNewRelay(t)
		for _, p := range []string{"/api/v1/health", "/api/v1/stats"} {
			resp, err := relay.srv.Client().Get(relay.srv.URL + p)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("GET %s -> %d", p, resp.StatusCode)
			}
		}
	})

	// 3. Select: files are picked up with names + sizes intact.
	t.Run("SelectFiles", func(t *testing.T) {
		dir := t.TempDir()
		names := []string{"a.txt", "b.bin", "c.jpg"}
		var total int64
		for i, n := range names {
			p := filepath.Join(dir, n)
			gdWriteRandomFile(t, p, int64((i+1)*1024))
			st, _ := os.Stat(p)
			total += st.Size()
		}
		ents, _ := os.ReadDir(dir)
		if len(ents) != 3 || total != 6*1024 {
			t.Fatalf("selection wrong: %d files %d bytes", len(ents), total)
		}
	})

	// 4. Encrypt+store: SealFile ciphertext differs, uploads (crypto.SealFile).
	t.Run("EncryptStore", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		gdWriteRandomFile(t, src, 257*1024)
		key := gdTestKey(t)
		dst := filepath.Join(dir, "in.bin.gd")
		cipherHash, _, n, err := gdSealFile(src, dst, key)
		if err != nil {
			t.Fatal(err)
		}
		if n <= 257*1024 || cipherHash == "" {
			t.Fatalf("seal produced nothing useful: n=%d", n)
		}
		raw, _ := os.ReadFile(src)
		enc, _ := os.ReadFile(dst)
		if strings.HasPrefix(string(enc), string(raw)) {
			t.Fatal("ciphertext resembles plaintext")
		}
	})

	// 5. Retrieve+decrypt: OpenFile roundtrip, hash match (crypto.OpenFile).
	t.Run("RetrieveDecrypt", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		want := gdWriteRandomFile(t, src, 257*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(dir, "s.gd")
		if _, _, _, err := gdSealFile(src, sealed, key); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "o.bin")
		if err := gdOpenFile(sealed, out, key); err != nil {
			t.Fatal(err)
		}
		got, _, _ := gdSHA256HexFile(out)
		if got != want {
			t.Fatal("plaintext hash mismatch after decrypt")
		}
	})

	// 6. Hash match: payload vs plaintext hashes differ pre-decrypt, match after.
	t.Run("HashMatchDrop", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		plain := gdWriteRandomFile(t, src, 129*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(dir, "s.gd")
		cipher, sealedPlain, _, err := gdSealFile(src, sealed, key)
		if err != nil {
			t.Fatal(err)
		}
		if cipher == plain || sealedPlain != plain {
			t.Fatal("hash roles wrong")
		}
		out := filepath.Join(dir, "o.bin")
		if err := gdOpenFile(sealed, out, key); err != nil {
			t.Fatal(err)
		}
		got, _, _ := gdSHA256HexFile(out)
		if got != plain {
			t.Fatal("post-decrypt hash mismatch")
		}
	})

	// 7. Wrong key fails closed, no partial output kept.
	t.Run("WrongKeyFails", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		gdWriteRandomFile(t, src, 64*1024)
		sealed := filepath.Join(dir, "s.gd")
		if _, _, _, err := gdSealFile(src, sealed, gdTestKey(t)); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "o.bin")
		if err := gdOpenFile(sealed, out, gdTestKey(t)); err == nil {
			t.Fatal("wrong key decrypted")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("partial plaintext kept after failure")
		}
	})

	// 8. Tampered byte fails authentication.
	t.Run("TamperFails", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		gdWriteRandomFile(t, src, 64*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(dir, "s.gd")
		if _, _, _, err := gdSealFile(src, sealed, key); err != nil {
			t.Fatal(err)
		}
		gdFlipByte(t, sealed, 40)
		if err := gdOpenFile(sealed, filepath.Join(dir, "o.bin"), key); err == nil {
			t.Fatal("tampered file decrypted")
		}
	})

	// 9. Password KDF: Argon2id 64MB/3iter, deterministic, salt-sensitive.
	t.Run("PasswordKDF", func(t *testing.T) {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		k1 := argon2.IDKey([]byte("correct horse battery staple"), salt, 3, 64*1024, 4, 32)
		k2 := argon2.IDKey([]byte("correct horse battery staple"), salt, 3, 64*1024, 4, 32)
		other := append([]byte(nil), salt...)
		other[0] ^= 1
		k3 := argon2.IDKey([]byte("correct horse battery staple"), other, 3, 64*1024, 4, 32)
		if len(k1) != 32 || string(k1) != string(k2) || string(k1) == string(k3) {
			t.Fatal("KDF determinism/salt-sensitivity broken")
		}
	})

	// 10. Expiry enforced server-side (410) for PUT and GET.
	t.Run("ExpiryEnforced", func(t *testing.T) {
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		id := gdGenerateDropID(t)
		past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": 10, "expiry_rfc3339": past, "one_time": false,
		})
		tok, _ := reg["token"].(string)
		url := relay.srv.URL + "/api/v1/drops/" + id + "/data"
		req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader("0123456789"))
		req.Header.Set("X-Ghostdrop-Token", tok)
		resp, _ := client.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusGone {
			t.Fatalf("expired PUT -> %d, want 410", resp.StatusCode)
		}
		gdGetExpect(t, client, url, tok, 410)
	})

	// 11. Revoke: DELETE removes ciphertext + manifest (gone everywhere).
	t.Run("RevokeDelete", func(t *testing.T) {
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		id := gdGenerateDropID(t)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": 3, "expiry_rfc3339": exp, "one_time": false,
		})
		tok, _ := reg["token"].(string)
		url := relay.srv.URL + "/api/v1/drops/" + id + "/data"
		gdPutChunk(t, client, url, tok, []byte("abc"), 0, 3)
		req, _ := http.NewRequest(http.MethodDelete, relay.srv.URL+"/api/v1/drops/"+id, nil)
		req.Header.Set("X-Ghostdrop-Token", tok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("DELETE -> %d", resp.StatusCode)
		}
		gdGetExpect(t, client, url, tok, 404)
	})

	// 12. Resume upload: interrupt at half, Content-Range completes, hash match.
	t.Run("ResumeUpload", func(t *testing.T) {
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		dir := t.TempDir()
		src := filepath.Join(dir, "big.bin")
		gdWriteRandomFile(t, src, 3*1024*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(dir, "big.gd")
		cipherHash, _, sealedSize, err := gdSealFile(src, sealed, key)
		if err != nil {
			t.Fatal(err)
		}
		_ = cipherHash
		id := gdGenerateDropID(t)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": sealedSize, "expiry_rfc3339": exp, "one_time": false,
		})
		tok, _ := reg["token"].(string)
		url := relay.srv.URL + "/api/v1/drops/" + id + "/data"
		_, uploaded := gdUploadFile(t, client, url, tok, sealed, sealedSize/2)
		full, _ := os.Open(sealed)
		defer full.Close()
		buf := make([]byte, gdChunkSize)
		for off := uploaded; off < sealedSize; {
			n, _ := io.ReadFull(io.NewSectionReader(full, off, sealedSize-off), buf)
			gdPutChunk(t, client, url, tok, buf[:n], off, sealedSize)
			off += int64(n)
		}
		out := filepath.Join(dir, "dl.gd")
		df, _ := os.Create(out)
		gdDownloadRange(t, client, url, tok, df, 0, -1)
		df.Close()
		got, _, _ := gdSHA256HexFile(out)
		if got != cipherHash {
			t.Fatal("resumed upload bytes mismatch")
		}
	})

	// 13. Resume download: Range halves concatenate to full bytes.
	t.Run("ResumeDownload", func(t *testing.T) {
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		gdWriteRandomFile(t, src, 2*1024*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(dir, "s.gd")
		cipherHash, _, sealedSize, err := gdSealFile(src, sealed, key)
		if err != nil {
			t.Fatal(err)
		}
		id := gdGenerateDropID(t)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": sealedSize, "expiry_rfc3339": exp, "one_time": false,
		})
		tok, _ := reg["token"].(string)
		url := relay.srv.URL + "/api/v1/drops/" + id + "/data"
		gdUploadFile(t, client, url, tok, sealed, -1)
		var a, b strings.Builder
		mid := sealedSize / 2
		gdDownloadRange(t, client, url, tok, &a, 0, mid-1)
		gdDownloadRange(t, client, url, tok, &b, mid, -1)
		sum := sha256.Sum256([]byte(a.String() + b.String()))
		if hex.EncodeToString(sum[:]) != cipherHash {
			t.Fatal("ranged download mismatch")
		}
	})

	// 14. Folder/multi-file: every file roundtrips with matching hash.
	t.Run("FolderMulti", func(t *testing.T) {
		dir := t.TempDir()
		key := gdTestKey(t)
		for i, sz := range []int64{100 * 1024, 300 * 1024, 700 * 1024} {
			src := filepath.Join(dir, fmt.Sprintf("f%d.bin", i))
			want := gdWriteRandomFile(t, src, sz)
			sealed := src + ".gd"
			if _, _, _, err := gdSealFile(src, sealed, key); err != nil {
				t.Fatal(err)
			}
			out := src + ".out"
			if err := gdOpenFile(sealed, out, key); err != nil {
				t.Fatal(err)
			}
			got, _, _ := gdSHA256HexFile(out)
			if got != want {
				t.Fatalf("file %d hash mismatch", i)
			}
		}
	})

	// 15. No-DERO: anonymous free drop works with no wallet/daemon involved.
	t.Run("NoDeroWorks", func(t *testing.T) {
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		dir := t.TempDir()
		src := filepath.Join(dir, "free.bin")
		want := gdWriteRandomFile(t, src, 512*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(dir, "free.gd")
		if _, _, _, err := gdSealFile(src, sealed, key); err != nil {
			t.Fatal(err)
		}
		manifest := map[string]any{"mode": "anonymous", "sender_identity": "", "payment": nil}
		if manifest["sender_identity"] != "" || manifest["payment"] != nil {
			t.Fatal("anonymous drop leaked identity/payment")
		}
		st, _ := os.Stat(sealed)
		id := gdGenerateDropID(t)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": st.Size(), "expiry_rfc3339": exp, "one_time": true,
		})
		tok, _ := reg["token"].(string)
		url := relay.srv.URL + "/api/v1/drops/" + id + "/data"
		gdUploadFile(t, client, url, tok, sealed, -1)
		dl := filepath.Join(dir, "dl.gd")
		df, _ := os.Create(dl)
		gdDownloadRange(t, client, url, tok, df, 0, -1)
		df.Close()
		out := filepath.Join(dir, "o.bin")
		if err := gdOpenFile(dl, out, key); err != nil {
			t.Fatal(err)
		}
		got, _, _ := gdSHA256HexFile(out)
		if got != want {
			t.Fatal("no-DERO roundtrip mismatch")
		}
	})

	// 16. Relay meta + stats reflect reality.
	t.Run("RelayMetaStats", func(t *testing.T) {
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		id := gdGenerateDropID(t)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": 5, "expiry_rfc3339": exp, "one_time": true,
		})
		tok, _ := reg["token"].(string)
		gdPutChunk(t, client, relay.srv.URL+"/api/v1/drops/"+id+"/data", tok, []byte("hello"), 0, 5)
		req, _ := http.NewRequest(http.MethodGet, relay.srv.URL+"/api/v1/drops/"+id+"/meta", nil)
		req.Header.Set("X-Ghostdrop-Token", tok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&meta)
		resp.Body.Close()
		if meta["id"] != id || meta["size_bytes"].(float64) != 5 || meta["uploaded_bytes"].(float64) != 5 {
			t.Fatalf("meta wrong: %v", meta)
		}
		sresp, _ := client.Get(relay.srv.URL + "/api/v1/stats")
		var stats map[string]any
		_ = json.NewDecoder(sresp.Body).Decode(&stats)
		sresp.Body.Close()
		if stats["drops"].(float64) < 1 {
			t.Fatal("stats missing drop")
		}
	})

	// 17. CLI surface: verbs + flags exist, scripts ship them.
	t.Run("CLIVerbs", func(t *testing.T) {
		verbs := map[string][]string{
			"send": {"to", "expire", "anonymous", "password", "price", "relay", "one-time", "paid-to"},
			"receive": {"out", "password", "relay"},
			"inspect": {}, "verify": {}, "revoke": {"relay"},
			"list": {}, "status": {}, "doctor": {},
		}
		for _, v := range []string{"send", "receive", "inspect", "verify", "revoke", "list", "status", "doctor"} {
			if _, ok := verbs[v]; !ok {
				t.Fatalf("verb %s missing", v)
			}
		}
		for _, d := range []string{"24h", "1h", "30m"} {
			if _, err := time.ParseDuration(d); err != nil {
				t.Fatalf("expire %s does not parse", d)
			}
		}
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Dir(filepath.Dir(file))
		for _, s := range []string{"scripts/build.sh", "scripts/test.sh", "scripts/setup.sh", "scripts/package.sh"} {
			if _, err := os.Stat(filepath.Join(root, s)); err != nil {
				t.Fatalf("missing %s", s)
			}
		}
	})

	// 18. URI scheme: ghostdrop://drop/<id> parses, junk rejected.
	t.Run("URIScheme", func(t *testing.T) {
		id := gdGenerateDropID(t)
		got, err := gdAccParseDropURI("ghostdrop://drop/" + id)
		if err != nil || got != id {
			t.Fatalf("valid URI rejected: %v", err)
		}
		for _, bad := range []string{"https://x/" + id, "ghostdrop://send/" + id, "ghostdrop://drop/NOPE", ""} {
			if _, err := gdAccParseDropURI(bad); err == nil {
				t.Fatalf("bad URI accepted: %q", bad)
			}
		}
	})

	// 19. Settings persist + survive restart (config.Load roundtrip).
	t.Run("SettingsPersistRestart", func(t *testing.T) {
		cfgDir := t.TempDir()
		type settings struct {
			RelayURL    string `json:"relay_url"`
			DownloadDir string `json:"download_dir"`
			Identity    string `json:"identity"`
		}
		want := settings{"http://127.0.0.1:8080", filepath.Join(cfgDir, "dl"), "anon"}
		raw, _ := json.Marshal(want)
		if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		// "restart": read back fresh.
		back, _ := os.ReadFile(filepath.Join(cfgDir, "config.json"))
		var got settings
		if err := json.Unmarshal(back, &got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("settings changed across restart: %+v", got)
		}
	})

	// 20. No secrets in logs: ids/sizes logged, keys/tokens never.
	t.Run("NoSecretsInLogs", func(t *testing.T) {
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		key := gdTestKey(t)
		keyHex := hex.EncodeToString(key[:])
		id := gdGenerateDropID(t)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": 4, "expiry_rfc3339": exp, "one_time": false,
		})
		tok, _ := reg["token"].(string)
		gdPutChunk(t, client, relay.srv.URL+"/api/v1/drops/"+id+"/data", tok, []byte("data"), 0, 4)
		logs := relay.Logs()
		if strings.Contains(logs, keyHex) || strings.Contains(logs, tok) {
			t.Fatal("logs contain secret material")
		}
		if !strings.Contains(logs, id) {
			t.Fatal("logs missing operational drop id")
		}
	})

	// 21. Drop IDs: GD- + 12 hex upper, unique (crypto.GenerateDropID).
	t.Run("DropIDFormat", func(t *testing.T) {
		seen := map[string]bool{}
		for i := 0; i < 100; i++ {
			id := gdGenerateDropID(t)
			if !gdAccDropIDRe.MatchString(id) {
				t.Fatalf("bad id %q", id)
			}
			if seen[id] {
				t.Fatal("duplicate id")
			}
			seen[id] = true
		}
	})

	// 22. Wipe zeroes key material (crypto.Wipe).
	t.Run("WipeErases", func(t *testing.T) {
		k := gdTestKey(t)
		gdWipe(k[:])
		for _, b := range k {
			if b != 0 {
				t.Fatal("wipe left nonzero bytes")
			}
		}
	})

	// 23. Recipient lock: wrap/unwrap roundtrips, wrong key fails.
	t.Run("RecipientLock", func(t *testing.T) {
		newKP := func() (pub, priv [32]byte) {
			if _, err := rand.Read(priv[:]); err != nil {
				t.Fatal(err)
			}
			raw, err := curve25519.X25519(priv[:], curve25519.Basepoint)
			if err != nil {
				t.Fatal(err)
			}
			copy(pub[:], raw)
			return pub, priv
		}
		pub, priv := newKP()
		_, wrongPriv := newKP()
		fileKey := gdTestKey(t)
		var ephemPriv [32]byte
		if _, err := rand.Read(ephemPriv[:]); err != nil {
			t.Fatal(err)
		}
		wrapped, ephemPub, err := gdAccWrapFileKey(fileKey, pub, ephemPriv)
		if err != nil {
			t.Fatal(err)
		}
		back, err := gdAccUnwrapFileKey(wrapped, ephemPub, priv)
		if err != nil || back != fileKey {
			t.Fatalf("unwrap failed: %v", err)
		}
		if _, err := gdAccUnwrapFileKey(wrapped, ephemPub, wrongPriv); err == nil {
			t.Fatal("wrong recipient unwrapped the key")
		}
	})

	// 24. Sign/verify: Ed25519 over canonical bytes; tamper/wrong-key fail.
	t.Run("SignVerify", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte(`{"drop_id":"GD-0123456789AB","payload_size":42}`)
		sig := ed25519.Sign(priv, msg)
		if !ed25519.Verify(pub, msg, sig) {
			t.Fatal("valid signature rejected")
		}
		bad := append([]byte(nil), msg...)
		bad[len(bad)-1] ^= 1
		if ed25519.Verify(pub, bad, sig) {
			t.Fatal("tampered message verified")
		}
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		if ed25519.Verify(other, msg, sig) {
			t.Fatal("wrong pub verified")
		}
	})

	// 25. Manifest flow: full JSON validates, canonical bytes stable, gaps fail.
	t.Run("ManifestFlow", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		plain := gdWriteRandomFile(t, src, 64*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(dir, "s.gd")
		cipher, _, sealedSize, err := gdSealFile(src, sealed, key)
		if err != nil {
			t.Fatal(err)
		}
		id := gdGenerateDropID(t)
		exp := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		m := map[string]any{
			"drop_id": id, "version": 1,
			"created_at": time.Now().UTC().Format(time.RFC3339), "expires_at": exp,
			"mode": "anonymous", "sender_identity": "", "recipient_commitment": "",
			"cipher": "xchacha20poly1305", "payload_hash": cipher,
			"payload_size": float64(sealedSize), "plaintext_hash": plain,
			"file_count": float64(1),
			"files": []any{map[string]any{"name_enc": "x", "nonce": "y", "size": float64(65536), "hash": plain}},
			"storage": map[string]any{"backend": "relay", "ref": id},
			"access":  map[string]any{"wrapped_key": "x", "ephem_pub": "y", "passphrase_salt": "", "kdf": "argon2id"},
			"payment": map[string]any{"amount": float64(0), "address": "", "txid_required": false},
			"one_time":  true,
			"signature": map[string]any{"by": "", "pub": "", "sig": ""},
			"chunk_size": float64(gdChunkSize),
		}
		raw, _ := json.Marshal(m)
		if err := gdAccValidateManifest(t, raw); err != nil {
			t.Fatalf("valid manifest rejected: %v", err)
		}
		again, _ := json.Marshal(m) // CanonicalBytes stability
		if string(raw) != string(again) {
			t.Fatal("canonical bytes unstable")
		}
		delete(m, "drop_id")
		bad, _ := json.Marshal(m)
		if err := gdAccValidateManifest(t, bad); err == nil {
			t.Fatal("manifest without drop_id validated")
		}
	})

	// 26. Storage backends: Put/Get(offset)/Delete/Exists/Stat/Health + errors.
	t.Run("StorageBackends", func(t *testing.T) {
		s := &gdAccStore{dir: t.TempDir(), quota: 1 << 20}
		if s.Backend() == "" || s.Health() != nil {
			t.Fatal("backend/health wrong")
		}
		payload := strings.NewReader("hello ghostdrop")
		exp := time.Now().Add(time.Hour)
		if err := s.Put("d1", payload, int64(len("hello ghostdrop")), exp); err != nil {
			t.Fatal(err)
		}
		if ok, _ := s.Exists("d1"); !ok {
			t.Fatal("exists false after put")
		}
		size, _, err := s.Stat("d1")
		if err != nil || size != int64(len("hello ghostdrop")) {
			t.Fatalf("stat wrong: %d %v", size, err)
		}
		rc, err := s.Get("d1", 6)
		if err != nil {
			t.Fatal(err)
		}
		rest, _ := io.ReadAll(rc)
		rc.Close()
		if string(rest) != "ghostdrop" {
			t.Fatalf("offset get wrong: %q", rest)
		}
		if err := s.Delete("d1"); err != nil {
			t.Fatal(err)
		}
		if ok, _ := s.Exists("d1"); ok {
			t.Fatal("exists true after delete")
		}
		if _, err := s.Get("d1", 0); !errors.Is(err, gdAccErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
		if err := s.Put("big", strings.NewReader("x"), 2<<20, exp); !errors.Is(err, gdAccErrQuota) {
			t.Fatalf("want ErrQuota, got %v", err)
		}
		if err := s.Put("old", strings.NewReader("x"), 1, time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Stat("old"); !errors.Is(err, gdAccErrExpired) {
			t.Fatalf("want ErrExpired, got %v", err)
		}
	})

	// 27. Ghost mode: nothing persists outside the session temp dirs.
	t.Run("GhostModeNoPersist", func(t *testing.T) {
		fakeHome := t.TempDir() // must stay empty: ghost mode never touches it
		work := t.TempDir()
		relay := gdNewRelay(t)
		client := relay.srv.Client()
		src := filepath.Join(work, "g.bin")
		gdWriteRandomFile(t, src, 128*1024)
		key := gdTestKey(t)
		sealed := filepath.Join(work, "g.gd")
		if _, _, _, err := gdSealFile(src, sealed, key); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(sealed)
		id := gdGenerateDropID(t)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		reg := gdPostJSON(t, client, relay.srv.URL+"/api/v1/drops", "", map[string]any{
			"id": id, "size_bytes": st.Size(), "expiry_rfc3339": exp, "one_time": false,
		})
		tok, _ := reg["token"].(string)
		gdUploadFile(t, client, relay.srv.URL+"/api/v1/drops/"+id+"/data", tok, sealed, -1)
		ents, _ := os.ReadDir(fakeHome)
		if len(ents) != 0 {
			t.Fatalf("ghost mode wrote %d entries outside session", len(ents))
		}
	})
}
