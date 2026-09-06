package app

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)
// Manifest mirrors the contract Manifest JSON exactly.
type Manifest struct {
	DropID              string     `json:"drop_id"`
	Version             int        `json:"version"`
	CreatedAt           string     `json:"created_at"`
	ExpiresAt           string     `json:"expires_at"`
	Mode                string     `json:"mode"`
	SenderIdentity      string     `json:"sender_identity"`
	RecipientCommitment string     `json:"recipient_commitment,omitempty"`
	Cipher              string     `json:"cipher"`
	PayloadHash         string     `json:"payload_hash"`
	PayloadSize         int64      `json:"payload_size"`
	PlaintextHash       string     `json:"plaintext_hash"`
	FileCount           int        `json:"file_count"`
	Files               []FileRef  `json:"files"`
	Storage             StorageRef `json:"storage"`
	Access              AccessRef  `json:"access"`
	Payment             PaymentRef `json:"payment,omitempty"`
	OneTime             bool       `json:"one_time"`
	Signature           *SigRef    `json:"signature,omitempty"`
	ChunkSize           int        `json:"chunk_size"`
}

// FileRef describes one file in a drop. NameEnc holds base64(sealed name).
type FileRef struct {
	NameEnc string `json:"name_enc"`
	Nonce   string `json:"nonce"`
	Size    int64  `json:"size"`
	Hash    string `json:"hash"`
}

// StorageRef locates the payload.
type StorageRef struct {
	Backend string `json:"backend"`
	Ref     string `json:"ref"`
}

// AccessRef carries the wrapped file key material.
type AccessRef struct {
	WrappedKey    string `json:"wrapped_key,omitempty"`
	EphemPub      string `json:"ephem_pub,omitempty"`
	PassphraseSalt string `json:"passphrase_salt,omitempty"`
	KDF           string `json:"kdf,omitempty"`
}

// PaymentRef carries optional payment requirements.
type PaymentRef struct {
	Amount      uint64 `json:"amount,omitempty"`
	Address     string `json:"address,omitempty"`
	TxidRequired bool   `json:"txid_required,omitempty"`
}

// SigRef carries the manifest signature.
type SigRef struct {
	By  string `json:"by"`
	Pub string `json:"pub"`
	Sig string `json:"sig"`
}

// NewManifest builds a manifest skeleton for id/mode/expiry.
func NewManifest(id, mode string, expiry time.Time) *Manifest {
	now := time.Now().UTC()
	return &Manifest{
		DropID:    id,
		Version:   1,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: expiry.UTC().Format(time.RFC3339),
		Mode:      mode,
		Cipher:    "xchacha20-poly1305",
		ChunkSize: ChunkSize,
	}
}

// Validate checks manifest invariants.
func (m *Manifest) Validate() error {
	if !strings.HasPrefix(m.DropID, "GD-") || len(m.DropID) != 15 {
		return fmt.Errorf("bad drop_id %q", m.DropID)
	}
	if m.Version != 1 {
		return fmt.Errorf("unsupported version %d", m.Version)
	}
	created, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return fmt.Errorf("bad created_at: %w", err)
	}
	expiry, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return fmt.Errorf("bad expires_at: %w", err)
	}
	if !expiry.After(created) {
		return fmt.Errorf("expires_at must be after created_at")
	}
	switch m.Mode {
	case "open", "password", "recipient", "paid", "demo":
	default:
		return fmt.Errorf("unknown mode %q", m.Mode)
	}
	if m.Cipher != "xchacha20-poly1305" {
		return fmt.Errorf("unknown cipher %q", m.Cipher)
	}
	if len(m.PayloadHash) != 64 || len(m.PlaintextHash) != 64 {
		return fmt.Errorf("bad payload/plaintext hash")
	}
	if m.PayloadSize <= 0 {
		return fmt.Errorf("bad payload_size")
	}
	if m.FileCount != len(m.Files) || m.FileCount < 1 {
		return fmt.Errorf("file_count mismatch")
	}
	for _, f := range m.Files {
		if f.NameEnc == "" || f.Nonce == "" || len(f.Hash) != 64 || f.Size < 0 {
			return fmt.Errorf("bad file entry")
		}
	}
	if m.Storage.Backend != "local" && m.Storage.Backend != "relay" {
		return fmt.Errorf("unknown storage backend %q", m.Storage.Backend)
	}
	switch m.Access.KDF {
	case "", "none", "argon2id", "x25519", "commitment":
	default:
		return fmt.Errorf("unknown kdf %q", m.Access.KDF)
	}
	if m.ChunkSize != ChunkSize {
		return fmt.Errorf("bad chunk_size %d", m.ChunkSize)
	}
	return nil
}

// CanonicalBytes returns the deterministic signing encoding (signature excluded).
func (m *Manifest) CanonicalBytes() []byte {
	cp := *m
	cp.Signature = nil
	b, _ := json.Marshal(cp)
	return b
}

// Sign signs the canonical manifest with priv and attaches the signature.
func (m *Manifest) Sign(priv []byte) error {
	sig, err := Sign(priv, m.CanonicalBytes())
	if err != nil {
		return err
	}
	pub := priv[len(priv)-32:]
	m.Signature = &SigRef{By: m.SenderIdentity, Pub: fmt.Sprintf("%x", pub), Sig: fmt.Sprintf("%x", sig)}
	return nil
}

// Verify checks the attached manifest signature.
func (m *Manifest) Verify() bool {
	if m.Signature == nil {
		return false
	}
	pub, err := hexDecode(m.Signature.Pub)
	if err != nil {
		return false
	}
	sig, err := hexDecode(m.Signature.Sig)
	if err != nil {
		return false
	}
	return Verify(pub, m.CanonicalBytes(), sig)
}

// EncryptFilenames seals each name with key and appends file entries.
func (m *Manifest) EncryptFilenames(key *[32]byte, names []string, sizes []int64, hashes []string) error {
	for i, name := range names {
		nonce, sealed, err := SealBytes([]byte(name), key[:])
		if err != nil {
			return err
		}
		m.Files = append(m.Files, FileRef{
			NameEnc: base64.StdEncoding.EncodeToString(sealed),
			Nonce:   base64.StdEncoding.EncodeToString(nonce),
			Size:    sizes[i],
			Hash:    hashes[i],
		})
	}
	m.FileCount = len(m.Files)
	return nil
}

// DecryptFilename recovers the original name of entry i.
func (m *Manifest) DecryptFilename(key *[32]byte, i int) (string, error) {
	if i < 0 || i >= len(m.Files) {
		return "", fmt.Errorf("file index out of range")
	}
	sealed, err := base64.StdEncoding.DecodeString(m.Files[i].NameEnc)
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(m.Files[i].Nonce)
	if err != nil {
		return "", err
	}
	plain, err := OpenBytes(nonce, sealed, key[:])
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Metadata returns display-safe manifest metadata (never key material).
func (m *Manifest) Metadata() map[string]any {
	return map[string]any{
		"drop_id":         m.DropID,
		"version":         m.Version,
		"created_at":      m.CreatedAt,
		"expires_at":      m.ExpiresAt,
		"mode":            m.Mode,
		"sender_identity": m.SenderIdentity,
		"payload_size":    m.PayloadSize,
		"file_count":      m.FileCount,
		"storage":         m.Storage.Backend,
		"one_time":        m.OneTime,
		"chunk_size":      m.ChunkSize,
	}
}
func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

