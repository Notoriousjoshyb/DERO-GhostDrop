package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

// Options configures an App.
type Options struct {
	DataDir  string
	RelayURL string
}

// App wires local storage, drop metadata, and relay transfer.
type App struct {
	dataDir    string
	dropsDir   string
	payloadDir string
	relayURL   string
	store      *FSStore
}

// New builds an App, creating OS-native data directories.
func New(o Options) (*App, error) {
	dataDir := o.DataDir
	if dataDir == "" {
		dataDir = ResolveDataDir()
	}
	drops := filepath.Join(dataDir, "drops")
	payloads := filepath.Join(dataDir, "payloads")
	for _, d := range []string{drops, payloads} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	store, err := NewFSStore(payloads)
	if err != nil {
		return nil, err
	}
	return &App{dataDir: dataDir, dropsDir: drops, payloadDir: payloads, relayURL: o.RelayURL, store: store}, nil
}

// ResolveDataDir honors GHOSTDROP_DATA_DIR, else OS-native config dir.
func ResolveDataDir() string {
	if v := os.Getenv("GHOSTDROP_DATA_DIR"); v != "" {
		return v
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "ghostdrop")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".ghostdrop")
	}
	return filepath.Join(".", ".ghostdrop")
}

// DataDir returns the app data directory.
func (a *App) DataDir() string { return a.dataDir }

// RelayURL returns the configured default relay.
func (a *App) RelayURL() string { return a.relayURL }

// SendOpts controls a send. Progress, when set, receives (written, total)
// plaintext bytes during sealing and (sent, total) during upload.
type SendOpts struct {
	Paths     []string
	To        string
	Expire    string
	Mode      string
	Anonymous bool
	Password  string
	Price     uint64
	PaidTo    string
	Relay     string
	OneTime   bool
	Demo      bool
	Progress  func(written, total int64)
}

// SendResult describes a created drop.
type SendResult struct {
	DropID   string
	Link     string
	QRpng    []byte
	Size     int64
	Manifest *Manifest
}

// ParseExpiry maps ""/duration/"7d"/RFC3339/date to an absolute expiry.
func ParseExpiry(s string) (time.Time, error) {
	now := time.Now().UTC()
	s = strings.TrimSpace(s)
	if s == "" {
		return now.Add(24 * time.Hour), nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("expiry must be positive")
		}
		return now.Add(d), nil
	}
	if m := regexp.MustCompile(`^(\d+)d$`).FindStringSubmatch(s); m != nil {
		var days int
		fmt.Sscanf(m[1], "%d", &days)
		if days <= 0 || days > 365 {
			return time.Time{}, fmt.Errorf("day expiry out of range 1-365")
		}
		return now.Add(time.Duration(days) * 24 * time.Hour), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		if !t.After(now) {
			return time.Time{}, fmt.Errorf("expiry must be in the future")
		}
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		if !t.After(now) {
			return time.Time{}, fmt.Errorf("expiry must be in the future")
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("bad --expire %q: want 10m/1h/24h/7d, RFC3339, or YYYY-MM-DD", s)
}

func username() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	for _, k := range []string{"USERNAME", "USER"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "local-user"
}

func randToken() string {
	var b [16]byte
	if _, err := io.ReadFull(randReader(), b[:]); err != nil {
		panic(err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Send encrypts paths into a new drop. Never logs secrets.
func (a *App) Send(ctx context.Context, o SendOpts) (*SendResult, error) {
	if len(o.Paths) == 0 {
		return nil, fmt.Errorf("no paths to send")
	}
	for _, p := range o.Paths {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("stat input: %w", err)
		}
	}
	expiry, err := ParseExpiry(o.Expire)
	if err != nil {
		return nil, err
	}
	if o.Price > 0 && o.PaidTo == "" {
		return nil, fmt.Errorf("--price requires --paid-to address")
	}
	id := GenerateDropID()
	token := randToken()
	stage, err := os.MkdirTemp("", "ghostdrop-send-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)

	// Build plaintext payload: single file flows directly, anything else
	// (folders, multi-file) is auto-zipped with streaming.
	var plainPath string
	var names []string
	var sizes []int64
	var hashes []string
	var plainHash string
	archived := false
	if len(o.Paths) == 1 {
		fi, err := os.Stat(o.Paths[0])
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			plainPath = o.Paths[0]
			h, _, err := Sha256HexFile(plainPath)
			if err != nil {
				return nil, err
			}
			plainHash = h
			names = []string{filepath.Base(plainPath)}
			sizes = []int64{fi.Size()}
			hashes = []string{h}
		}
	}
	if plainPath == "" {
		plainPath = filepath.Join(stage, "payload.zip")
		entries, zh, err := ZipSources(o.Paths, plainPath)
		if err != nil {
			return nil, err
		}
		archived = true
		plainHash = zh
		for _, e := range entries {
			names = append(names, e.Name)
			sizes = append(sizes, e.Size)
			hashes = append(hashes, e.Hash)
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("nothing to send: empty selection")
		}
		_ = archived
	}

	fileKey, err := GenerateFileKey()
	if err != nil {
		return nil, err
	}
	defer Wipe(fileKey[:])
	sealedPath := filepath.Join(stage, "payload.gd")
	cipherHash, _, n, err := sealWithProgress(plainPath, sealedPath, fileKey, o.Progress)
	if err != nil {
		return nil, err
	}

	mode := "open"
	switch {
	case o.Demo:
		mode = "demo"
	case o.Password != "":
		mode = "password"
	case o.Price > 0:
		mode = "paid"
	case o.To != "":
		mode = "recipient"
	}
	if o.Mode != "" {
		mode = o.Mode
	}
	sender := username()
	if o.Anonymous {
		sender = "anonymous"
	}
	if o.Demo {
		sender = "DEMO"
	}
	m := NewManifest(id, mode, expiry)
	m.SenderIdentity = sender
	if o.To != "" {
		m.RecipientCommitment = o.To
	}
	m.PayloadHash = cipherHash
	m.PlaintextHash = plainHash
	sealedFi, err := os.Stat(sealedPath)
	if err != nil {
		return nil, err
	}
	m.PayloadSize = sealedFi.Size()
	if err := m.EncryptFilenames(&fileKey, names, sizes, hashes); err != nil {
		return nil, err
	}
	if err := lockAccess(m, &fileKey, o.Password, o.To); err != nil {
		return nil, err
	}
	if o.Price > 0 {
		m.Payment = PaymentRef{Amount: o.Price, Address: o.PaidTo, TxidRequired: true}
	}
	m.OneTime = o.OneTime

	relayAddr := strings.TrimSpace(o.Relay)
	if relayAddr == "" {
		relayAddr = strings.TrimSpace(a.relayURL)
	}
	useRelay := relayAddr != "" && relayAddr != "local"
	if useRelay {
		m.Storage = StorageRef{Backend: "relay", Ref: id}
	} else {
		m.Storage = StorageRef{Backend: "local", Ref: id}
	}

	signPub, signPriv, err := GenerateSignKeypair()
	if err != nil {
		return nil, err
	}
	_ = signPub
	if err := m.Sign(signPriv); err != nil {
		return nil, err
	}
	Wipe(signPriv)
	if err := m.Validate(); err != nil {
		return nil, err
	}

	if useRelay {
		rc := NewRelayClient(relayAddr, token)
		if err := rc.Create(ctx, id, sealedFi.Size(), expiry, o.OneTime); err != nil {
			return nil, fmt.Errorf("relay create failed: %w", err)
		}
		envPath := filepath.Join(stage, "envelope.bin")
		if err := writeEnvelope(m, sealedPath, envPath); err != nil {
			return nil, err
		}
		envFi, _ := os.Stat(envPath)
		f, err := os.Open(envPath)
		if err != nil {
			return nil, err
		}
		uerr := rc.PutData(ctx, id, &progressReader{r: f, total: envFi.Size(), fn: o.Progress}, envFi.Size())
		f.Close()
		if uerr != nil {
			return nil, fmt.Errorf("relay upload failed: %w", uerr)
		}
	} else {
		f, err := os.Open(sealedPath)
		if err != nil {
			return nil, err
		}
		perr := a.store.Put(ctx, id, &progressReader{r: f, total: sealedFi.Size(), fn: o.Progress}, sealedFi.Size(), expiry)
		f.Close()
		if perr != nil {
			return nil, perr
		}
	}

	if err := a.saveDrop(id, token, m); err != nil {
		return nil, err
	}
	a.appendHistory("send", m)

	linkRelay := ""
	if useRelay {
		linkRelay = relayAddr
	}
	link := FormatDropURI(id, linkRelay, token)
	qr, err := qrcode.Encode(link, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	if o.Progress != nil {
		o.Progress(n, n)
	}
	return &SendResult{DropID: id, Link: link, QRpng: qr, Size: m.PayloadSize, Manifest: m}, nil
}

// lockAccess wraps fileKey into m.Access per mode. Plaintext payloads are
// never stored; open/demo drops use a public derivation, documented here.
func lockAccess(m *Manifest, fileKey *[32]byte, password, to string) error {
	switch {
	case password != "":
		salt, err := NewSalt()
		if err != nil {
			return err
		}
		kek := DeriveKeyFromPassphrase(password, salt)
		defer Wipe(kek[:])
		nonce, sealed, err := SealBytes(fileKey[:], kek[:])
		if err != nil {
			return err
		}
		m.Access = AccessRef{
			WrappedKey:     base64.StdEncoding.EncodeToString(append(nonce, sealed...)),
			PassphraseSalt: base64.StdEncoding.EncodeToString(salt),
			KDF:            "argon2id",
		}
	case isPubHex(to):
		raw, _ := hex.DecodeString(to)
		var pub [32]byte
		copy(pub[:], raw)
		var epriv [32]byte
		if _, err := io.ReadFull(randReader(), epriv[:]); err != nil {
			return err
		}
		wrapped, epub, err := WrapFileKey(*fileKey, pub, epriv)
		Wipe(epriv[:])
		if err != nil {
			return err
		}
		m.Access = AccessRef{
			WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
			EphemPub:   base64.StdEncoding.EncodeToString(epub[:]),
			KDF:        "x25519",
		}
	case to != "":
		// Named/address recipient: commitment-labeled; the commitment is
		// public in the manifest so any holder of the link can open it.
		ck := sha256.Sum256([]byte("ghostdrop:commit:" + to))
		nonce, sealed, err := SealBytes(fileKey[:], ck[:])
		if err != nil {
			return err
		}
		m.Access = AccessRef{WrappedKey: base64.StdEncoding.EncodeToString(append(nonce, sealed...)), KDF: "commitment"}
	default:
		ck := sha256.Sum256([]byte("ghostdrop:open:" + m.DropID))
		nonce, sealed, err := SealBytes(fileKey[:], ck[:])
		if err != nil {
			return err
		}
		m.Access = AccessRef{WrappedKey: base64.StdEncoding.EncodeToString(append(nonce, sealed...)), KDF: "none"}
	}
	return nil
}

// unlockAccess recovers the file key. For x25519 drops the secret must be a
// 64-hex recipient private key; commitment/open drops need no secret.
func unlockAccess(m *Manifest, secret string) ([32]byte, error) {
	var zero [32]byte
	raw, err := base64.StdEncoding.DecodeString(m.Access.WrappedKey)
	if err != nil || len(raw) < NonceSize {
		return zero, fmt.Errorf("corrupt access block")
	}
	open := func(kek []byte) ([32]byte, error) {
		plain, err := OpenBytes(raw[:NonceSize], raw[NonceSize:], kek)
		if err != nil {
			return zero, fmt.Errorf("wrong secret or corrupt key block")
		}
		var k [32]byte
		copy(k[:], plain)
		Wipe(plain)
		return k, nil
	}
	switch m.Access.KDF {
	case "argon2id":
		if secret == "" {
			return zero, fmt.Errorf("password required")
		}
		salt, err := base64.StdEncoding.DecodeString(m.Access.PassphraseSalt)
		if err != nil {
			return zero, fmt.Errorf("corrupt salt")
		}
		kek := DeriveKeyFromPassphrase(secret, salt)
		defer Wipe(kek[:])
		return open(kek[:])
	case "x25519":
		privRaw, err := hex.DecodeString(strings.TrimSpace(secret))
		if err != nil || len(privRaw) != 32 {
			return zero, fmt.Errorf("recipient private key (64 hex chars) required")
		}
		var priv [32]byte
		copy(priv[:], privRaw)
		epubRaw, err := base64.StdEncoding.DecodeString(m.Access.EphemPub)
		if err != nil || len(epubRaw) != 32 {
			return zero, fmt.Errorf("corrupt ephemeral key")
		}
		var epub [32]byte
		copy(epub[:], epubRaw)
		k, err := UnwrapFileKey(raw, epub, priv)
		Wipe(priv[:])
		return k, err
	case "commitment":
		ck := sha256.Sum256([]byte("ghostdrop:commit:" + m.RecipientCommitment))
		return open(ck[:])
	default: // "none", "" — open/demo drops
		ck := sha256.Sum256([]byte("ghostdrop:open:" + m.DropID))
		return open(ck[:])
	}
}

func isPubHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// Receive downloads, decrypts, and hash-verifies a drop into outDir.
func (a *App) Receive(ctx context.Context, dropURL, secret, outDir string, progress func(written, total int64)) error {
	ref, err := ParseDropURI(dropURL)
	if err != nil {
		return err
	}
	m, sealedPath, cleanup, err := a.fetchPayload(ctx, ref)
	if err != nil {
		return err
	}
	defer cleanup()
	if exp, err := time.Parse(time.RFC3339, m.ExpiresAt); err == nil && time.Now().After(exp) {
		return fmt.Errorf("drop expired")
	}
	fileKey, err := unlockAccess(m, secret)
	if err != nil {
		return err
	}
	defer Wipe(fileKey[:])

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "ghostdrop-recv-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	plainPath := filepath.Join(stage, "plain.bin")
	if err := OpenFile(sealedPath, plainPath, fileKey); err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}
	got, _, err := Sha256HexFile(plainPath)
	if err != nil {
		return err
	}
	if got != m.PlaintextHash {
		return fmt.Errorf("plaintext hash mismatch")
	}
	plainF, err := os.Open(plainPath)
	if err != nil {
		return err
	}
	defer plainF.Close()
	if IsZipStream(plainF) {
		plainF.Close()
		fi, _ := os.Stat(plainPath)
		rf, err := os.Open(plainPath)
		if err != nil {
			return err
		}
		defer rf.Close()
		got, err := UnzipSafe(rf, fi.Size(), outDir)
		_ = got
		if err != nil {
			return err
		}
		// Verify recorded per-file hashes.
		for i := range m.Files {
			name, err := m.DecryptFilename(&fileKey, i)
			if err != nil {
				continue
			}
			p := filepath.Join(outDir, filepath.FromSlash(name))
			h, _, err := Sha256HexFile(p)
			if err != nil || h != m.Files[i].Hash {
				// Directories and non-extracted entries are skipped silently;
				// a present file with a wrong hash is fatal.
				if err == nil {
					return fmt.Errorf("file hash mismatch for %q", name)
				}
			}
		}
	} else {
		name := ref.ID + ".bin"
		if len(m.Files) == 1 {
			if dn, err := m.DecryptFilename(&fileKey, 0); err == nil {
				name = dn
			}
		}
		name = filepath.Base(filepath.FromSlash(name))
		dst := filepath.Join(outDir, name)
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, plainF); err != nil {
			out.Close()
			return err
		}
		out.Close()
		h, _, err := Sha256HexFile(dst)
		if err != nil {
			return err
		}
		if len(m.Files) == 1 && h != m.Files[0].Hash {
			os.Remove(dst)
			return fmt.Errorf("file hash mismatch")
		}
	}
	if progress != nil {
		progress(m.PayloadSize, m.PayloadSize)
	}
	if m.OneTime {
		_ = a.Revoke(ctx, ref.ID)
	}
	a.appendHistory("receive", m)
	return nil
}

// fetchPayload resolves a manifest + sealed payload file for ref, downloading
// with resume into a temp staging file. Returns cleanup for temp files.
func (a *App) fetchPayload(ctx context.Context, ref DropRef) (*Manifest, string, func(), error) {
	nop := func() {}
	if ref.Relay == "" {
		m, err := a.loadDrop(ref.ID)
		if err != nil {
			return nil, "", nop, err
		}
		if exp, err := time.Parse(time.RFC3339, m.ExpiresAt); err == nil && time.Now().After(exp) {
			return nil, "", nop, fmt.Errorf("drop expired")
		}
		size, _, err := a.store.Stat(ctx, ref.ID)
		if err != nil {
			return nil, "", nop, err
		}
		if size != m.PayloadSize {
			return nil, "", nop, fmt.Errorf("payload size mismatch")
		}
		got, _, err := Sha256HexFile(a.store.dataPath(ref.ID))
		if err != nil {
			return nil, "", nop, err
		}
		if got != m.PayloadHash {
			return nil, "", nop, fmt.Errorf("payload hash mismatch")
		}
		return m, a.store.dataPath(ref.ID), nop, nil
	}
	rc := NewRelayClient(ref.Relay, ref.Token)
	meta, err := rc.Meta(ctx, ref.ID)
	if err != nil {
		return nil, "", nop, err
	}
	_ = meta
	stage, err := os.MkdirTemp("", "ghostdrop-dl-*")
	if err != nil {
		return nil, "", nop, err
	}
	cleanup := func() { os.RemoveAll(stage) }
	part := filepath.Join(stage, "envelope.part")
	var offset int64
	if fi, err := os.Stat(part); err == nil {
		offset = fi.Size()
	}
	body, err := rc.GetDataRange(ctx, ref.ID, offset)
	if err != nil {
		return nil, "", cleanup, err
	}
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|(map[bool]int{true: os.O_APPEND, false: os.O_TRUNC}[offset > 0]), 0o644)
	if err != nil {
		body.Close()
		return nil, "", cleanup, err
	}
	if _, err := io.Copy(f, body); err != nil {
		body.Close()
		f.Close()
		return nil, "", cleanup, err
	}
	body.Close()
	f.Close()
	m, sealed, err := splitEnvelope(part, stage)
	if err != nil {
		return nil, "", cleanup, err
	}
	got, _, err := Sha256HexFile(sealed)
	if err != nil {
		return nil, "", cleanup, err
	}
	if got != m.PayloadHash {
		return nil, "", cleanup, fmt.Errorf("payload hash mismatch")
	}
	return m, sealed, cleanup, nil
}

// Inspect loads a manifest by bare ID or full URI (fetching remote head).
func (a *App) Inspect(ctx context.Context, idOrURL string) (*Manifest, error) {
	ref, err := ParseDropURI(idOrURL)
	if err != nil {
		return nil, err
	}
	if ref.Relay == "" {
		return a.loadDrop(ref.ID)
	}
	m, _, cleanup, err := a.fetchPayload(ctx, ref)
	defer cleanup()
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Verify re-checks manifest validity, signature, expiry, and payload hashes.
func (a *App) Verify(ctx context.Context, idOrURL string) error {
	m, err := a.Inspect(ctx, idOrURL)
	if err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("manifest invalid: %w", err)
	}
	if m.Signature != nil && !m.Verify() {
		return fmt.Errorf("manifest signature invalid")
	}
	ref, _ := ParseDropURI(idOrURL)
	_, sealed, cleanup, err := a.fetchPayload(ctx, ref)
	defer cleanup()
	if err != nil {
		return err
	}
	got, _, err := Sha256HexFile(sealed)
	if err != nil {
		return err
	}
	if got != m.PayloadHash {
		return fmt.Errorf("payload hash mismatch")
	}
	if exp, err := time.Parse(time.RFC3339, m.ExpiresAt); err == nil && time.Now().After(exp) {
		return fmt.Errorf("drop expired")
	}
	return nil
}

// Revoke deletes a drop locally and, for relay drops, on the relay.
func (a *App) Revoke(ctx context.Context, idOrURL string) error {
	ref, err := ParseDropURI(idOrURL)
	if err != nil {
		return err
	}
	m, lerr := a.loadDrop(ref.ID)
	if lerr != nil {
		return ErrNotFound
	}
	if m.Storage.Backend == "relay" && ref.Relay != "" {
		rc := NewRelayClient(ref.Relay, ref.Token)
		if err := rc.DeleteDrop(ctx, ref.ID); err != nil && err != ErrNotFound {
			// Best effort against the relay; local state still revoked.
			_ = err
		}
	}
	_ = a.store.Delete(ctx, ref.ID)
	os.RemoveAll(filepath.Join(a.dropsDir, ref.ID))
	a.appendHistory("revoke", m)
	return nil
}

// List returns known drop manifests, newest first.
func (a *App) List() ([]*Manifest, error) {
	ents, err := os.ReadDir(a.dropsDir)
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		m, err := a.loadDrop(e.Name())
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

// Status renders one line of drop health for humans.
func (a *App) Status(ctx context.Context, idOrURL string) (string, error) {
	m, err := a.Inspect(ctx, idOrURL)
	if err != nil {
		return "", err
	}
	present := "missing"
	if m.Storage.Backend == "local" {
		if ok, _ := a.store.Exists(ctx, m.DropID); ok {
			present = "present"
		}
	} else {
		present = "relay"
	}
	return fmt.Sprintf("%s mode=%s files=%d size=%d payload=%s expires=%s one_time=%v",
		m.DropID, m.Mode, m.FileCount, m.PayloadSize, present, m.ExpiresAt, m.OneTime), nil
}

// --- local metadata store ---

func (a *App) dropDir(id string) string { return filepath.Join(a.dropsDir, id) }

func (a *App) saveDrop(id, token string, m *Manifest) error {
	dir := a.dropDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0o600)
}

func (a *App) loadDrop(id string) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(a.dropDir(id), "manifest.json"))
	if err != nil {
		return nil, ErrNotFound
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (a *App) appendHistory(action string, m *Manifest) {
	line, _ := json.Marshal(map[string]any{
		"ts": m.CreatedAt, "action": action, "drop": m.DropID,
		"mode": m.Mode, "size": m.PayloadSize,
	})
	f, err := os.OpenFile(filepath.Join(a.dataDir, "history.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, string(line))
}

// --- relay envelope: BE32 manifestLen || manifest JSON || sealed payload ---

func writeEnvelope(m *Manifest, sealedPath, outPath string) error {
	mraw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	in, err := os.Open(sealedPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(mraw)))
	if _, err := out.Write(lb[:]); err != nil {
		return err
	}
	if _, err := out.Write(mraw); err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return err
}

func splitEnvelope(envPath, stage string) (*Manifest, string, error) {
	f, err := os.Open(envPath)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	var lb [4]byte
	if _, err := io.ReadFull(f, lb[:]); err != nil {
		return nil, "", fmt.Errorf("bad envelope: %w", err)
	}
	mlen := binary.BigEndian.Uint32(lb[:])
	if mlen == 0 || mlen > 16<<20 {
		return nil, "", fmt.Errorf("bad envelope manifest length %d", mlen)
	}
	mraw := make([]byte, mlen)
	if _, err := io.ReadFull(f, mraw); err != nil {
		return nil, "", fmt.Errorf("bad envelope manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(mraw, &m); err != nil {
		return nil, "", fmt.Errorf("bad envelope manifest: %w", err)
	}
	sealed := filepath.Join(stage, "payload.gd")
	out, err := os.Create(sealed)
	if err != nil {
		return nil, "", err
	}
	if _, err := io.Copy(out, f); err != nil {
		out.Close()
		return nil, "", err
	}
	out.Close()
	return &m, sealed, nil
}

// progressReader reports stream progress.
type progressReader struct {
	r    io.Reader
	done int64
	total int64
	fn   func(written, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.fn != nil && n > 0 {
		p.fn(p.done, p.total)
	}
	return n, err
}
