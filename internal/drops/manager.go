// Package drops orchestrates the drop lifecycle: encrypt, hash, manifest,
// sign, store, retrieve, verify, revoke — with expiry enforcement and a
// ghost mode that never touches the database.
package drops

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ghostdrop/internal/crypto"
	"ghostdrop/internal/database"
	"ghostdrop/internal/manifest"
	"ghostdrop/internal/storage"
)

// Status is the drop lifecycle state.
type Status string

// Lifecycle states.
const (
	StatusPreparing  Status = "PREPARING"
	StatusEncrypting Status = "ENCRYPTING"
	StatusUploading  Status = "UPLOADING"
	StatusReady      Status = "READY"
	StatusDelivered  Status = "DELIVERED"
	StatusRetrieved  Status = "RETRIEVED"
	StatusVerified   Status = "VERIFIED"
	StatusExpired    Status = "EXPIRED"
	StatusRevoked    Status = "REVOKED"
	StatusFailed     Status = "FAILED"
)

// ErrExpired is returned when a drop is past its expiry.
var ErrExpired = storage.ErrExpired

// CreateOpts configures Manager.Create.
type CreateOpts struct {
	// ID overrides the generated drop ID (tests); empty = GenerateDropID.
	ID string
	// Mode is the drop mode (anonymous, password, recipient, paid, direct).
	Mode string
	// SenderIdentity is the (possibly empty) sender label.
	SenderIdentity string
	// RecipientCommitment optionally binds the intended recipient.
	RecipientCommitment string
	// Expiry is the drop expiry; zero = now + 72h.
	Expiry time.Time
	// OneTime deletes the stored payload after first successful retrieve.
	OneTime bool
	// SignPriv optionally signs the manifest (Ed25519 seed or private key).
	SignPriv []byte
	// SignBy names the signer in the signature block.
	SignBy string
	// RecipientPub optionally recipient-locks the file key (X25519).
	RecipientPub *[32]byte
	// Password optionally passphrase-locks the file key (Argon2id).
	Password string
	// Amount/PaidTo configure paid drops.
	Amount      uint64
	PaidTo      string
	TxidRequired bool
}

// RetrieveOpts selects how the file key is resolved on retrieve.
type RetrieveOpts struct {
	// Key is the file key directly (sender flow).
	Key *[32]byte
	// RecipientPriv unwraps the file key via the manifest (recipient flow).
	RecipientPriv *[32]byte
	// Password derives the file key via the manifest salt (password flow).
	Password string
}

// Manager orchestrates drops over a storage Provider with optional DB
// persistence. In ghost mode no database writes occur.
type Manager struct {
	mu          sync.Mutex
	store       storage.Provider
	db          *database.DB
	ghost       bool
	manifestDir string
	manifests   map[string]*manifest.Manifest
	statuses    map[string]Status
}

// NewManager returns a Manager. db may be nil (no persistence).
// manifestDir may be "" (memory-only manifests).
func NewManager(store storage.Provider, db *database.DB, ghost bool, manifestDir string) *Manager {
	return &Manager{
		store:       store,
		db:          db,
		ghost:      ghost,
		manifestDir: manifestDir,
		manifests:   map[string]*manifest.Manifest{},
		statuses:    map[string]Status{},
	}
}

// Ghost reports whether ghost mode is enabled.
func (m *Manager) Ghost() bool { return m.ghost }

// Store exposes the underlying provider (resume, health).
func (m *Manager) Store() storage.Provider { return m.store }

func (m *Manager) setStatus(id string, st Status) {
	m.mu.Lock()
	m.statuses[id] = st
	m.mu.Unlock()
	if m.db != nil && !m.ghost {
		_ = m.db.UpdateStatus(id, string(st))
	}
}

func (m *Manager) remember(id string, man *manifest.Manifest, st Status) {
	m.mu.Lock()
	m.manifests[id] = man
	m.statuses[id] = st
	m.mu.Unlock()
	if m.manifestDir != "" {
		_ = os.MkdirAll(m.manifestDir, 0o700)
		_ = man.Save(filepath.Join(m.manifestDir, id+".json"))
	}
}
// GetManifest returns the cached (or persisted) manifest for id.
func (m *Manager) GetManifest(id string) (*manifest.Manifest, error) {
	m.mu.Lock()
	man, ok := m.manifests[id]
	m.mu.Unlock()
	if ok {
		return man, nil
	}
	if m.manifestDir != "" {
		if man, err := manifest.Load(filepath.Join(m.manifestDir, id+".json")); err == nil {
			m.mu.Lock()
			m.manifests[id] = man
			m.mu.Unlock()
			return man, nil
		}
	}
	return nil, storage.ErrNotFound
}

// Create encrypts srcPath, builds and signs the manifest, uploads the
// ciphertext, and records the drop. It returns the manifest and file key.
func (m *Manager) Create(ctx context.Context, srcPath string, opts CreateOpts) (*manifest.Manifest, [32]byte, error) {
	var zero [32]byte
	id := opts.ID
	if id == "" {
		id = crypto.GenerateDropID()
	}
	if err := storage.ValidateID(id); err != nil {
		return nil, zero, err
	}
	mode := opts.Mode
	if mode == "" {
		mode = "anonymous"
	}
	expiry := opts.Expiry
	if expiry.IsZero() {
		expiry = time.Now().Add(72 * time.Hour)
	}
	m.setStatus(id, StatusPreparing)

	fi, err := os.Stat(srcPath)
	if err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}
	if err := ctx.Err(); err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}

	fileKey, err := crypto.GenerateFileKey()
	if err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}
	defer func() {
		if err != nil {
			crypto.Wipe(fileKey[:])
		}
	}()

	m.setStatus(id, StatusEncrypting)
	tmp, err := os.CreateTemp("", "ghostdrop-enc-*.bin")
	if err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)

	cipherHash, plainHash, _, err := crypto.SealFile(srcPath, tmpName, fileKey)
	if err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}
	encFi, err := os.Stat(tmpName)
	if err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}
	encSize := encFi.Size()

	man := manifest.New(id, mode, expiry)
	man.SenderIdentity = opts.SenderIdentity
	man.RecipientCommitment = opts.RecipientCommitment
	man.PayloadHash = cipherHash
	man.PayloadSize = encSize
	man.PlaintextHash = plainHash
	man.OneTime = opts.OneTime
	man.Storage = manifest.StorageRef{Backend: m.store.Backend(), Ref: id}
	man.Payment = manifest.Payment{Amount: opts.Amount, Address: opts.PaidTo, TxidRequired: opts.TxidRequired}
	if err := man.EncryptFilenames([]string{filepath.Base(srcPath)}, fileKey); err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}
	man.SetFileInfo(0, fi.Size(), plainHash)

	if opts.RecipientPub != nil {
		ephemPub, ephemPriv, err := crypto.GenerateRecipientKeypair()
		if err != nil {
			m.setStatus(id, StatusFailed)
			return nil, zero, err
		}
		wrapped, pub, err := crypto.WrapFileKey(fileKey, *opts.RecipientPub, ephemPriv)
		if err != nil {
			m.setStatus(id, StatusFailed)
			return nil, zero, err
		}
		_ = ephemPub
		man.Access.WrappedKey = hex.EncodeToString(wrapped)
		man.Access.EphemPub = hex.EncodeToString(pub[:])
		man.Access.KDF = "x25519"
	}
	if opts.Password != "" {
		salt, err := crypto.NewSalt()
		if err != nil {
			m.setStatus(id, StatusFailed)
			return nil, zero, err
		}
		dk := crypto.DeriveKeyFromPassphrase(opts.Password, salt)
		nonce, cipher, err := crypto.SealBytes(fileKey[:], dk[:])
		crypto.Wipe(dk[:])
		if err != nil {
			m.setStatus(id, StatusFailed)
			return nil, zero, err
		}
		// wrapped_key = nonce(24) || sealed file key.
		man.Access.WrappedKey = hex.EncodeToString(append(nonce, cipher...))
		man.Access.PassphraseSalt = hex.EncodeToString(salt)
		man.Access.KDF = "argon2id"
	}
	if len(opts.SignPriv) > 0 {
		if err := man.Sign(opts.SignPriv, opts.SignBy); err != nil {
			m.setStatus(id, StatusFailed)
			return nil, zero, err
		}
	}
	if err := man.Validate(); err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}

	m.setStatus(id, StatusUploading)
	f, err := os.Open(tmpName)
	if err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}
	err = m.store.Put(ctx, id, f, encSize, expiry)
	f.Close()
	if err != nil {
		m.setStatus(id, StatusFailed)
		return nil, zero, err
	}

	m.remember(id, man, StatusReady)
	if m.db != nil && !m.ghost {
		_ = m.db.UpsertDrop(database.Drop{
			ID: id, Mode: mode, Recipient: opts.RecipientCommitment,
			CreatedAt: man.CreatedAt, ExpiresAt: expiry, Status: string(StatusReady),
			PayloadHash: cipherHash, Size: encSize,
			StorageRef: m.store.Backend() + "/" + id,
		})
		_ = m.db.AddEvent(id, "created", "mode="+mode)
	}
	return man, fileKey, nil
}

// resolveKey resolves the file key per RetrieveOpts and the manifest.
func resolveKey(man *manifest.Manifest, opts RetrieveOpts) ([32]byte, error) {
	var zero [32]byte
	if opts.Key != nil {
		return *opts.Key, nil
	}
	if opts.RecipientPriv != nil {
		if man.Access.WrappedKey == "" || man.Access.EphemPub == "" {
			return zero, errors.New("drops: no recipient lock on manifest")
		}
		wrapped, err := hex.DecodeString(man.Access.WrappedKey)
		if err != nil {
			return zero, err
		}
		ephemRaw, err := hex.DecodeString(man.Access.EphemPub)
		if err != nil {
			return zero, err
		}
		var ephemPub [32]byte
		if len(ephemRaw) != 32 {
			return zero, fmt.Errorf("drops: bad ephem_pub length %d", len(ephemRaw))
		}
		copy(ephemPub[:], ephemRaw)
		return crypto.UnwrapFileKey(wrapped, ephemPub, *opts.RecipientPriv)
	}
	if opts.Password != "" {
		if man.Access.WrappedKey == "" || man.Access.PassphraseSalt == "" {
			return zero, errors.New("drops: no passphrase lock on manifest")
		}
		raw, err := hex.DecodeString(man.Access.WrappedKey)
		if err != nil {
			return zero, err
		}
		salt, err := hex.DecodeString(man.Access.PassphraseSalt)
		if err != nil {
			return zero, err
		}
		if len(raw) < 24+32 {
			return zero, fmt.Errorf("drops: bad wrapped key length %d", len(raw))
		}
		dk := crypto.DeriveKeyFromPassphrase(opts.Password, salt)
		plain, err := crypto.OpenBytes(raw[:24], raw[24:], dk[:])
		crypto.Wipe(dk[:])
		if err != nil {
			return zero, err
		}
		var key [32]byte
		if len(plain) != 32 {
			return zero, fmt.Errorf("drops: bad unwrapped key length %d", len(plain))
		}
		copy(key[:], plain)
		return key, nil
	}
	return zero, errors.New("drops: no key material provided")
}

// Retrieve downloads, decrypts, and hash-verifies the drop into dstPath.
func (m *Manager) Retrieve(ctx context.Context, id string, dstPath string, opts RetrieveOpts) error {
	man, err := m.GetManifest(id)
	if err != nil {
		return err
	}
	if time.Now().After(man.ExpiresAt) {
		m.setStatus(id, StatusExpired)
		return ErrExpired
	}
	key, err := resolveKey(man, opts)
	if err != nil {
		return err
	}
	defer crypto.Wipe(key[:])
	if err := ctx.Err(); err != nil {
		return err
	}

	m.setStatus(id, StatusDelivered)
	enc, err := os.CreateTemp("", "ghostdrop-dl-*.bin")
	if err != nil {
		return err
	}
	encName := enc.Name()
	enc.Close()
	defer os.Remove(encName)

	rc, err := m.store.Get(ctx, id, 0)
	if err != nil {
		return err
	}
	out, err := os.Create(encName)
	if err != nil {
		rc.Close()
		return err
	}
	_, copyErr := io.Copy(out, rc)
	rc.Close()
	out.Close()
	if copyErr != nil {
		return copyErr
	}
	if err := crypto.OpenFile(encName, dstPath, key); err != nil {
		m.setStatus(id, StatusFailed)
		return err
	}
	m.setStatus(id, StatusRetrieved)

	got, _, err := crypto.Sha256HexFile(dstPath)
	if err != nil {
		return err
	}
	if man.PlaintextHash != "" && got != man.PlaintextHash {
		m.setStatus(id, StatusFailed)
		return fmt.Errorf("drops: plaintext hash mismatch")
	}
	m.setStatus(id, StatusVerified)
	if m.db != nil && !m.ghost {
		_ = m.db.SetVerified(id, true)
		_ = m.db.UpdateStatus(id, string(StatusVerified))
		_ = m.db.AddEvent(id, "retrieved", "hash=ok")
	}
	if man.OneTime {
		_ = m.store.Delete(ctx, id)
	}
	return nil
}

// Revoke deletes the stored payload and marks the drop revoked.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	if err := m.store.Delete(ctx, id); err != nil {
		return err
	}
	m.setStatus(id, StatusRevoked)
	if m.db != nil && !m.ghost {
		_ = m.db.UpdateStatus(id, string(StatusRevoked))
		_ = m.db.AddEvent(id, "revoked", "")
	}
	return nil
}

// Status returns the lifecycle state, enforcing expiry.
func (m *Manager) Status(ctx context.Context, id string) (Status, error) {
	man, err := m.GetManifest(id)
	if err == nil && time.Now().After(man.ExpiresAt) {
		m.setStatus(id, StatusExpired)
		return StatusExpired, nil
	}
	m.mu.Lock()
	st, ok := m.statuses[id]
	m.mu.Unlock()
	if ok {
		return st, nil
	}
	if m.db != nil && !m.ghost {
		if d, err := m.db.GetDrop(id); err == nil {
			return Status(d.Status), nil
		}
	}
	if err := m.store.Health(ctx); err != nil {
		return StatusFailed, err
	}
	return StatusFailed, storage.ErrNotFound
}

// ResumeOffset returns bytes already held by storage (upload resume point).
func (m *Manager) ResumeOffset(ctx context.Context, id string) (int64, error) {
	size, _, err := m.store.Stat(ctx, id)
	if err != nil {
		return 0, err
	}
	return size, nil
}
