// Package manifest defines the Ghostdrop drop manifest: the signed JSON
// document describing an encrypted payload without ever containing keys
// or plaintext.
package manifest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ghostdrop/internal/crypto"
)

// Version is the current manifest schema version.
const Version = 1

// ChunkSize is the sealed-chunk size (1 MiB), matching the file format.
const ChunkSize = 1 << 20

// CipherSuite identifies the file encryption construction.
const CipherSuite = "XChaCha20-Poly1305"

// Modes accepted by Validate.
var knownModes = map[string]bool{
	"anonymous": true,
	"password":  true,
	"recipient": true,
	"paid":      true,
	"direct":    true,
}

// FileEntry describes one encrypted file inside the drop.
type FileEntry struct {
	NameEnc string `json:"name_enc"`
	Nonce   string `json:"nonce"`
	Size    int64  `json:"size"`
	Hash    string `json:"hash"`
}

// StorageRef locates the encrypted payload.
type StorageRef struct {
	Backend string `json:"backend"`
	Ref     string `json:"ref"`
}

// Access holds key-wrapping material (never the file key itself).
type Access struct {
	WrappedKey     string `json:"wrapped_key"`
	EphemPub       string `json:"ephem_pub"`
	PassphraseSalt string `json:"passphrase_salt"`
	KDF            string `json:"kdf"`
}

// Payment holds paid-drop terms.
type Payment struct {
	Amount       uint64 `json:"amount"`
	Address      string `json:"address"`
	TxidRequired bool   `json:"txid_required"`
}

// Signature holds the sender's signature over CanonicalBytes.
type Signature struct {
	By  string `json:"by"`
	Pub string `json:"pub"`
	Sig string `json:"sig"`
}

// Manifest is the signed drop descriptor.
type Manifest struct {
	DropID              string     `json:"drop_id"`
	Version             int        `json:"version"`
	CreatedAt           time.Time  `json:"created_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	Mode                string     `json:"mode"`
	SenderIdentity      string     `json:"sender_identity"`
	RecipientCommitment string     `json:"recipient_commitment"`
	Cipher              string     `json:"cipher"`
	PayloadHash         string     `json:"payload_hash"`
	PayloadSize         int64      `json:"payload_size"`
	PlaintextHash       string     `json:"plaintext_hash"`
	FileCount           int        `json:"file_count"`
	Files               []FileEntry `json:"files"`
	Storage             StorageRef `json:"storage"`
	Access              Access     `json:"access"`
	Payment             Payment    `json:"payment"`
	OneTime             bool       `json:"one_time"`
	Signature           Signature  `json:"signature"`
	ChunkSize           int        `json:"chunk_size"`
}

// New returns a Manifest skeleton with identity, timestamps, cipher, and
// chunk size filled in.
func New(id, mode string, expiry time.Time) *Manifest {
	now := time.Now().UTC()
	return &Manifest{
		DropID:    id,
		Version:   Version,
		CreatedAt: now,
		ExpiresAt: expiry.UTC(),
		Mode:      mode,
		Cipher:    CipherSuite,
		Files:     []FileEntry{},
		ChunkSize: ChunkSize,
	}
}

// Validate checks structural invariants (not signature validity).
func (m *Manifest) Validate() error {
	if m == nil {
		return errors.New("manifest: nil")
	}
	if !strings.HasPrefix(m.DropID, "GD-") || len(m.DropID) != 15 {
		return fmt.Errorf("manifest: bad drop_id %q", m.DropID)
	}
	if _, err := hex.DecodeString(m.DropID[3:]); err != nil {
		return fmt.Errorf("manifest: bad drop_id hex: %w", err)
	}
	if m.Version != Version {
		return fmt.Errorf("manifest: unsupported version %d", m.Version)
	}
	if m.Mode == "" {
		return errors.New("manifest: empty mode")
	}
	if !knownModes[m.Mode] {
		return fmt.Errorf("manifest: unknown mode %q", m.Mode)
	}
	if m.CreatedAt.IsZero() {
		return errors.New("manifest: zero created_at")
	}
	if !m.ExpiresAt.After(m.CreatedAt) {
		return errors.New("manifest: expires_at must be after created_at")
	}
	if m.ChunkSize != ChunkSize {
		return fmt.Errorf("manifest: chunk_size must be %d", ChunkSize)
	}
	if m.Cipher == "" {
		return errors.New("manifest: empty cipher")
	}
	if m.FileCount != len(m.Files) {
		return errors.New("manifest: file_count mismatch")
	}
	if m.PayloadSize < 0 {
		return errors.New("manifest: negative payload_size")
	}
	for i, f := range m.Files {
		if f.NameEnc == "" || f.Nonce == "" {
			return fmt.Errorf("manifest: file %d missing encrypted name", i)
		}
		if _, err := hex.DecodeString(f.NameEnc); err != nil {
			return fmt.Errorf("manifest: file %d bad name_enc: %w", i, err)
		}
		if _, err := hex.DecodeString(f.Nonce); err != nil {
			return fmt.Errorf("manifest: file %d bad nonce: %w", i, err)
		}
		if f.Size < 0 {
			return fmt.Errorf("manifest: file %d negative size", i)
		}
	}
	return nil
}

// CanonicalBytes returns the deterministic signing payload: the manifest
// JSON with the signature zeroed.
func (m *Manifest) CanonicalBytes() []byte {
	cp := *m
	cp.Signature = Signature{}
	raw, _ := json.Marshal(cp)
	return raw
}

// Sign signs the canonical bytes with an Ed25519 private key (seed or
// full private key) and fills the Signature block. By names the signer.
func (m *Manifest) Sign(priv []byte, by string) error {
	msg := m.CanonicalBytes()
	sig, err := crypto.Sign(priv, msg)
	if err != nil {
		return err
	}
	pub, err := pubFromPriv(priv)
	if err != nil {
		return err
	}
	m.Signature = Signature{
		By:  by,
		Pub: hex.EncodeToString(pub),
		Sig: hex.EncodeToString(sig),
	}
	return nil
}

// Verify reports whether the embedded signature is valid for the canonical
// bytes. An unsigned manifest verifies as false.
func (m *Manifest) Verify() bool {
	if m == nil {
		return false
	}
	if m.Signature.Pub == "" || m.Signature.Sig == "" {
		return false
	}
	pub, err := hex.DecodeString(m.Signature.Pub)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(m.Signature.Sig)
	if err != nil {
		return false
	}
	return crypto.Verify(pub, m.CanonicalBytes(), sig)
}

// EncryptFilenames seals each filename with the file key, replacing the
// file entries (sizes/hashes reset to zero values; use SetFileInfo after).
func (m *Manifest) EncryptFilenames(names []string, key [32]byte) error {
	entries := make([]FileEntry, 0, len(names))
	for _, n := range names {
		nonce, cipher, err := crypto.SealBytes([]byte(n), key[:])
		if err != nil {
			return err
		}
		entries = append(entries, FileEntry{
			NameEnc: hex.EncodeToString(cipher),
			Nonce:   hex.EncodeToString(nonce),
		})
	}
	m.Files = entries
	m.FileCount = len(entries)
	return nil
}

// DecryptFilenames opens every sealed filename with the file key.
func (m *Manifest) DecryptFilenames(key [32]byte) ([]string, error) {
	out := make([]string, 0, len(m.Files))
	for i, f := range m.Files {
		nonce, err := hex.DecodeString(f.Nonce)
		if err != nil {
			return nil, fmt.Errorf("manifest: file %d bad nonce: %w", i, err)
		}
		cipher, err := hex.DecodeString(f.NameEnc)
		if err != nil {
			return nil, fmt.Errorf("manifest: file %d bad name_enc: %w", i, err)
		}
		plain, err := crypto.OpenBytes(nonce, cipher, key[:])
		if err != nil {
			return nil, fmt.Errorf("manifest: file %d open: %w", i, err)
		}
		out = append(out, string(plain))
	}
	return out, nil
}

// SetFileInfo records plaintext size/hash for entry i.
func (m *Manifest) SetFileInfo(i int, size int64, hash string) {
	if i >= 0 && i < len(m.Files) {
		m.Files[i].Size = size
		m.Files[i].Hash = hash
	}
}

// SealMetadata seals arbitrary metadata (e.g. sender notes) with key,
// returning hex-encoded nonce and ciphertext.
func SealMetadata(plain []byte, key [32]byte) (nonceHex, cipherHex string, err error) {
	nonce, cipher, err := crypto.SealBytes(plain, key[:])
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(nonce), hex.EncodeToString(cipher), nil
}

// OpenMetadata opens hex-encoded sealed metadata with key.
func OpenMetadata(nonceHex, cipherHex string, key [32]byte) ([]byte, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("manifest: bad metadata nonce: %w", err)
	}
	cipher, err := hex.DecodeString(cipherHex)
	if err != nil {
		return nil, fmt.Errorf("manifest: bad metadata cipher: %w", err)
	}
	return crypto.OpenBytes(nonce, cipher, key[:])
}

// Save writes the manifest as indented JSON (0600).
func (m *Manifest) Save(path string) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// Load reads and validates a manifest file.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// pubFromPriv derives the Ed25519 public key from a seed or private key.
func pubFromPriv(priv []byte) ([]byte, error) {
	switch len(priv) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(priv).Public().(ed25519.PublicKey), nil
	case ed25519.PrivateKeySize:
		k := ed25519.PrivateKey(priv)
		pub := make([]byte, ed25519.PublicKeySize)
		copy(pub, k[32:])
		return pub, nil
	default:
		return nil, fmt.Errorf("manifest: bad signing key length %d", len(priv))
	}
}
