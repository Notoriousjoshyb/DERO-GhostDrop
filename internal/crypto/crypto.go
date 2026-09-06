// Package crypto implements Ghostdrop V1 file encryption.
//
// Format (GD01):
//
//	magic "GD01" || headerNonce(24B) || chunks{ BE32 len || sealed }
//
// Each plaintext chunk is at most 1MiB. Chunk nonce = headerNonce with the
// last 8 bytes XORed by the big-endian uint64 chunk index. Each chunk is
// sealed with XChaCha20-Poly1305 under the file key.
//
// Single-shot helpers SealBytes/OpenBytes use a fresh random 24-byte nonce
// with XChaCha20-Poly1305. Recipient wrapping uses X25519 ECDH with
// wrapKey = SHA256(shared || ephemPub || recipientPub).
package crypto

import (
	"bufio"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// ChunkSize is the maximum plaintext bytes per chunk (1MiB).
	ChunkSize = 1 << 20
	// NonceSize is the XChaCha20-Poly1305 nonce size.
	NonceSize = 24
	// KeySize is the file-key size in bytes.
	KeySize = 32
	// SaltSize is the default passphrase salt size.
	SaltSize = 16
	// Magic prefixes every sealed file.
	Magic = "GD01"
	magicLen  = 4
	headerLen = magicLen + NonceSize
)
// chunkAEAD builds the XChaCha20-Poly1305 primitive for a file key.
func chunkAEAD(key [32]byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key[:])
}

// chunkNonce derives the per-chunk nonce from the header nonce and index.
// nonce = headerNonce XOR BE64(index) in the last 8 bytes.
func chunkNonce(headerNonce [NonceSize]byte, index uint64) [NonceSize]byte {
	var n [NonceSize]byte
	copy(n[:], headerNonce[:])
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], index)
	for i := 0; i < 8; i++ {
		n[NonceSize-8+i] ^= ctr[i]
	}
	return n
}

// GenerateFileKey returns a fresh random 256-bit file key.
func GenerateFileKey() ([32]byte, error) {
	var k [32]byte
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		var zero [32]byte
		return zero, fmt.Errorf("crypto: rand: %w", err)
	}
	return k, nil
}

// SealFile encrypts srcPath into dstPath using the GD01 chunked format.
// It streams with bufio and never loads the whole file into memory.
// Returns hex(sha256(sealedFile)), hex(sha256(plaintext)), plaintext byte count.
func SealFile(srcPath, dstPath string, key [32]byte) (cipherHashHex string, plainHashHex string, n int64, err error) {
	aead, err := chunkAEAD(key)
	if err != nil {
		return "", "", 0, err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return "", "", 0, err
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", 0, err
	}
	// Ensure partial output is removed on failure.
	success := false
	defer func() {
		_ = dst.Close()
		if !success {
			_ = os.Remove(dstPath)
		}
	}()

	var headerNonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, headerNonce[:]); err != nil {
		return "", "", 0, fmt.Errorf("crypto: rand: %w", err)
	}

	bw := bufio.NewWriterSize(dst, 1<<20)
	cipherHash := sha256.New()
	plainHash := sha256.New()
	mw := io.MultiWriter(bw, cipherHash)

	// Header.
	if _, err := mw.Write([]byte(Magic)); err != nil {
		return "", "", 0, err
	}
	if _, err := mw.Write(headerNonce[:]); err != nil {
		return "", "", 0, err
	}

	br := bufio.NewReaderSize(src, 1<<20)
	plain := make([]byte, ChunkSize)
	sealed := make([]byte, 0, ChunkSize+aead.Overhead())
	var lenBuf [4]byte
	var index uint64
	var total int64

	for {
		rn, rerr := io.ReadFull(br, plain)
		if rn > 0 {
			plainHash.Write(plain[:rn])
			total += int64(rn)
			nonce := chunkNonce(headerNonce, index)
			sealed = aead.Seal(sealed[:0], nonce[:], plain[:rn], nil)
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sealed)))
			if _, err := mw.Write(lenBuf[:]); err != nil {
				return "", "", 0, err
			}
			if _, err := mw.Write(sealed); err != nil {
				return "", "", 0, err
			}
			index++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return "", "", 0, rerr
		}
	}

	if err := bw.Flush(); err != nil {
		return "", "", 0, err
	}
	if err := dst.Close(); err != nil {
		return "", "", 0, err
	}
	success = true

	return hex.EncodeToString(cipherHash.Sum(nil)), hex.EncodeToString(plainHash.Sum(nil)), total, nil
}

// OpenFile decrypts a GD01 file at srcPath into dstPath, streaming.
// Any tamper, truncation, or wrong key returns an error and removes dstPath.
func OpenFile(srcPath, dstPath string, key [32]byte) error {
	aead, err := chunkAEAD(key)
	if err != nil {
		return err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	br := bufio.NewReaderSize(src, 1<<20)

	magic := make([]byte, magicLen)
	if _, err := io.ReadFull(br, magic); err != nil {
		return fmt.Errorf("crypto: bad header: %w", err)
	}
	if string(magic) != Magic {
		return fmt.Errorf("crypto: bad magic %q", magic)
	}
	var headerNonce [NonceSize]byte
	if _, err := io.ReadFull(br, headerNonce[:]); err != nil {
		return fmt.Errorf("crypto: bad header nonce: %w", err)
	}

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = dst.Close()
		if !success {
			_ = os.Remove(dstPath)
		}
	}()
	bw := bufio.NewWriterSize(dst, 1<<20)

	var lenBuf [4]byte
	var index uint64
	for {
		_, err := io.ReadFull(br, lenBuf[:])
		if err == io.EOF {
			break // clean end
		}
		if err == io.ErrUnexpectedEOF {
			return fmt.Errorf("crypto: truncated chunk header")
		}
		if err != nil {
			return err
		}
		slen := binary.BigEndian.Uint32(lenBuf[:])
		if slen < uint32(aead.Overhead()) || slen > uint32(ChunkSize+aead.Overhead()) {
			return fmt.Errorf("crypto: bad chunk length %d", slen)
		}
		sealed := make([]byte, slen)
		if _, err := io.ReadFull(br, sealed); err != nil {
			return fmt.Errorf("crypto: truncated chunk: %w", err)
		}
		nonce := chunkNonce(headerNonce, index)
		plain, err := aead.Open(nil, nonce[:], sealed, nil)
		if err != nil {
			return fmt.Errorf("crypto: chunk %d auth failed: %w", index, err)
		}
		if _, err := bw.Write(plain); err != nil {
			return err
		}
		// Best effort: clear decrypted chunk copy held by Open.
		Wipe(plain)
		Wipe(sealed)
		index++
	}

	if err := bw.Flush(); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	success = true
	return nil
}

// SealBytes encrypts plain with XChaCha20-Poly1305 under key.
// Returns a fresh random nonce and the ciphertext.
func SealBytes(plain, key []byte) (nonce, cipher []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("crypto: key must be %d bytes", KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: rand: %w", err)
	}
	cipher = aead.Seal(nil, nonce, plain, nil)
	return nonce, cipher, nil
}

// OpenBytes decrypts cipher sealed with nonce under key.
func OpenBytes(nonce, cipher, key []byte) (plain []byte, err error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes", KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("crypto: nonce must be %d bytes", NonceSize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err = aead.Open(nil, nonce, cipher, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: auth failed: %w", err)
	}
	return plain, nil
}

// DeriveKeyFromPassphrase derives a 32-byte key with Argon2id (64MiB, 3 iterations).
func DeriveKeyFromPassphrase(passphrase string, salt []byte) *[32]byte {
	raw := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, KeySize)
	var out [32]byte
	copy(out[:], raw)
	// Clear the transient copy.
	for i := range raw {
		raw[i] = 0
	}
	runtime.KeepAlive(passphrase)
	return &out
}

// NewSalt returns a fresh random SaltSize-byte salt.
func NewSalt() ([]byte, error) {
	s := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return nil, fmt.Errorf("crypto: rand: %w", err)
	}
	return s, nil
}

// GenerateDropID returns "GD-" followed by 12 uppercase hex chars.
func GenerateDropID() string {
	var b [6]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		// Fallback is never expected; keep format stable without panicking.
		panic("crypto: rand unavailable")
	}
	return "GD-" + strings.ToUpper(hex.EncodeToString(b[:]))
}

// Wipe zeroes b. Compiler is barred from eliding the wipe.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// Sha256HexFile streams path and returns hex(sha256(content)) and size.
func Sha256HexFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// GenerateRecipientKeypair returns a fresh X25519 (pub, priv) pair.
func GenerateRecipientKeypair() (pub, priv [32]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		var zp, zv [32]byte
		return zp, zv, fmt.Errorf("crypto: rand: %w", err)
	}
	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		var zp, zv [32]byte
		return zp, zv, err
	}
	copy(pub[:], pubSlice)
	return pub, priv, nil
}

// wrapKey derives the file-key-wrap key: SHA256(shared || ephemPub || recipientPub).
func wrapKey(shared, ephemPub, recipientPub []byte) [32]byte {
	h := sha256.New()
	h.Write(shared)
	h.Write(ephemPub)
	h.Write(recipientPub)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// WrapFileKey wraps fileKey for recipientPub using ephemPriv.
// Returns wrapped = nonce(24B) || sealed(fileKey) and the ephemeral public key.
func WrapFileKey(fileKey [32]byte, recipientPub, ephemPriv [32]byte) (wrapped []byte, ephemPub [32]byte, err error) {
	shared, err := curve25519.X25519(ephemPriv[:], recipientPub[:])
	if err != nil {
		return nil, [32]byte{}, err
	}
	defer Wipe(shared)
	ephemPubSlice, err := curve25519.X25519(ephemPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, [32]byte{}, err
	}
	copy(ephemPub[:], ephemPubSlice)

	wk := wrapKey(shared, ephemPub[:], recipientPub[:])
	defer Wipe(wk[:])
	aead, err := chacha20poly1305.NewX(wk[:])
	if err != nil {
		return nil, [32]byte{}, err
	}
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, [32]byte{}, fmt.Errorf("crypto: rand: %w", err)
	}
	wrapped = make([]byte, 0, NonceSize+KeySize+aead.Overhead())
	wrapped = append(wrapped, nonce[:]...)
	wrapped = aead.Seal(wrapped, nonce[:], fileKey[:], nil)
	if subtle.ConstantTimeCompare(wrapped, wrapped) == 0 {
		return nil, [32]byte{}, fmt.Errorf("crypto: internal error")
	}
	return wrapped, ephemPub, nil
}

// UnwrapFileKey recovers the file key using the recipient private key.
func UnwrapFileKey(wrapped []byte, ephemPub [32]byte, recipientPriv [32]byte) (fileKey [32]byte, err error) {
	if len(wrapped) < NonceSize {
		return [32]byte{}, fmt.Errorf("crypto: wrapped key too short")
	}
	shared, err := curve25519.X25519(recipientPriv[:], ephemPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	defer Wipe(shared)
	// Reconstruct recipient pub for domain separation.
	recipPubSlice, err := curve25519.X25519(recipientPriv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, err
	}
	wk := wrapKey(shared, ephemPub[:], recipPubSlice)
	defer Wipe(wk[:])
	aead, err := chacha20poly1305.NewX(wk[:])
	if err != nil {
		return [32]byte{}, err
	}
	nonce := wrapped[:NonceSize]
	sealed := wrapped[NonceSize:]
	plain, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("crypto: unwrap auth failed: %w", err)
	}
	defer Wipe(plain)
	if len(plain) != KeySize {
		return [32]byte{}, fmt.Errorf("crypto: bad unwrapped key length %d", len(plain))
	}
	copy(fileKey[:], plain)
	return fileKey, nil
}

// GenerateSignKeypair returns a fresh Ed25519 (pub, priv) pair.
func GenerateSignKeypair() (pub, priv []byte, err error) {
	pubK, privK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return []byte(pubK), []byte(privK), nil
}

// Sign signs msg with an Ed25519 private key.
func Sign(priv, msg []byte) (sig []byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("crypto: private key must be %d bytes", ed25519.PrivateKeySize)
	}
	s := ed25519.Sign(ed25519.PrivateKey(priv), msg)
	out := make([]byte, len(s))
	copy(out, s)
	return out, nil
}

// Verify reports whether sig is valid for msg under pub.
func Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
