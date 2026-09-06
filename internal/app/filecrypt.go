package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// ChunkSize is the plaintext chunk size for sealed files (1 MiB).
	ChunkSize = 1 << 20
	// FileMagic prefixes every sealed payload.
	FileMagic = "GD01"
	// NonceSize is the XChaCha20 nonce size.
	NonceSize = 24
)

var basepoint = [32]byte{9}

// GenerateFileKey returns 32 random bytes for file encryption.
func GenerateFileKey() ([32]byte, error) {
	var k [32]byte
	_, err := io.ReadFull(rand.Reader, k[:])
	return k, err
}

// NewSalt returns 16 random bytes for password KDF use.
func NewSalt() ([]byte, error) {
	s := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, s)
	return s, err
}

// GenerateDropID returns "GD-" + 12 uppercase hex chars.
func GenerateDropID() string {
	var b [6]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return "GD-" + strings.ToUpper(hex.EncodeToString(b[:]))
}

// Wipe zeroes b.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// DeriveKeyFromPassphrase derives a 32-byte key with Argon2id (64 MiB, 3 iterations).
func DeriveKeyFromPassphrase(passphrase string, salt []byte) *[32]byte {
	raw := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	var k [32]byte
	copy(k[:], raw)
	Wipe(raw)
	return &k
}

// SealBytes seals plain with key under a random nonce.
func SealBytes(plain, key []byte) (nonce, cipher []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plain, nil), nil
}

// OpenBytes opens a sealed message.
func OpenBytes(nonce, cipher, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, cipher, nil)
}

// chunkNonce derives the per-chunk nonce: headerNonce with last 8 bytes XORed by BE64(index).
func chunkNonce(header []byte, index uint64) [NonceSize]byte {
	var n [NonceSize]byte
	copy(n[:], header)
	v := binary.BigEndian.Uint64(n[16:24]) ^ index
	binary.BigEndian.PutUint64(n[16:24], v)
	return n
}

// SealFile streams srcPath to dstPath in the GD01 chunked format.
// Returns (cipherHashHex, plainHashHex, plainBytes, err).
func SealFile(srcPath, dstPath string, key [32]byte) (string, string, int64, error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return "", "", 0, err
	}
	defer in.Close()
	out, err := os.Create(dstPath)
	if err != nil {
		return "", "", 0, err
	}
	defer out.Close()

	header := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, header); err != nil {
		return "", "", 0, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", "", 0, err
	}
	plainH := sha256.New()
	cipherH := sha256.New()
	mw := io.MultiWriter(out, cipherH)

	if _, err := mw.Write([]byte(FileMagic)); err != nil {
		return "", "", 0, err
	}
	if _, err := mw.Write(header); err != nil {
		return "", "", 0, err
	}

	buf := make([]byte, ChunkSize)
	var index uint64
	var total int64
	for {
		nr, rerr := io.ReadFull(in, buf)
		if nr > 0 {
			chunk := buf[:nr]
			plainH.Write(chunk)
			nonce := chunkNonce(header, index)
			sealed := aead.Seal(nil, nonce[:], chunk, nil)
			var lb [4]byte
			binary.BigEndian.PutUint32(lb[:], uint32(len(sealed)))
			if _, err := mw.Write(lb[:]); err != nil {
				return "", "", 0, err
			}
			if _, err := mw.Write(sealed); err != nil {
				return "", "", 0, err
			}
			total += int64(nr)
			index++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return "", "", 0, rerr
		}
	}
	Wipe(buf)
	return hex.EncodeToString(cipherH.Sum(nil)), hex.EncodeToString(plainH.Sum(nil)), total, nil
}

// OpenFile streams the sealed srcPath to dstPath, failing on any tampered chunk.
func OpenFile(srcPath, dstPath string, key [32]byte) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return err
	}
	magic := make([]byte, len(FileMagic))
	if _, err := io.ReadFull(in, magic); err != nil {
		return fmt.Errorf("reading magic: %w", err)
	}
	if string(magic) != FileMagic {
		return fmt.Errorf("bad magic %q", magic)
	}
	header := make([]byte, NonceSize)
	if _, err := io.ReadFull(in, header); err != nil {
		return fmt.Errorf("reading header nonce: %w", err)
	}
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer out.Close()

	var lb [4]byte
	var index uint64
	for {
		_, rerr := io.ReadFull(in, lb[:])
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("reading chunk len: %w", rerr)
		}
		ln := binary.BigEndian.Uint32(lb[:])
		if ln == 0 || ln > ChunkSize+64 {
			return fmt.Errorf("corrupt chunk length %d", ln)
		}
		sealed := make([]byte, ln)
		if _, err := io.ReadFull(in, sealed); err != nil {
			return fmt.Errorf("reading chunk: %w", err)
		}
		nonce := chunkNonce(header, index)
		plain, err := aead.Open(nil, nonce[:], sealed, nil)
		if err != nil {
			Wipe(sealed)
			return fmt.Errorf("chunk %d failed authentication", index)
		}
		Wipe(sealed)
		if _, err := out.Write(plain); err != nil {
			Wipe(plain)
			return err
		}
		Wipe(plain)
		index++
	}
	return nil
}

// Sha256HexFile streams a file through SHA-256. Returns (hex, size, err).
func Sha256HexFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return Sha256HexReader(f)
}

// Sha256HexReader hashes a stream without loading it.
func Sha256HexReader(r io.Reader) (string, int64, error) {
	var h hash.Hash = sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// GenerateRecipientKeypair creates an X25519 keypair.
func GenerateRecipientKeypair() (pub, priv [32]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return pub, priv, err
	}
	raw, err := curve25519.X25519(priv[:], basepoint[:])
	if err != nil {
		return pub, priv, err
	}
	copy(pub[:], raw)
	return pub, priv, nil
}

func wrapKEK(shared, ephemPub, recipientPub []byte) [32]byte {
	h := sha256.New()
	h.Write(shared)
	h.Write(ephemPub)
	h.Write(recipientPub)
	var k [32]byte
	copy(k[:], h.Sum(nil))
	return k
}

// WrapFileKey seals fileKey for recipientPub using ephemPriv. Returns wrapped = nonce||sealed.
func WrapFileKey(fileKey [32]byte, recipientPub, ephemPriv [32]byte) (wrapped []byte, ephemPub [32]byte, err error) {
	rawPub, err := curve25519.X25519(ephemPriv[:], basepoint[:])
	if err != nil {
		return nil, ephemPub, err
	}
	copy(ephemPub[:], rawPub)
	shared, err := curve25519.X25519(ephemPriv[:], recipientPub[:])
	if err != nil {
		return nil, ephemPub, err
	}
	kek := wrapKEK(shared, ephemPub[:], recipientPub[:])
	defer Wipe(kek[:])
	aead, err := chacha20poly1305.NewX(kek[:])
	if err != nil {
		return nil, ephemPub, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ephemPub, err
	}
	sealed := aead.Seal(nil, nonce, fileKey[:], nil)
	return append(nonce, sealed...), ephemPub, nil
}

// UnwrapFileKey recovers a file key wrapped by WrapFileKey.
func UnwrapFileKey(wrapped []byte, ephemPub [32]byte, recipientPriv [32]byte) (fileKey [32]byte, err error) {
	if len(wrapped) != NonceSize+32+16 {
		return fileKey, fmt.Errorf("bad wrapped key length %d", len(wrapped))
	}
	shared, err := curve25519.X25519(recipientPriv[:], ephemPub[:])
	if err != nil {
		return fileKey, err
	}
	var recipientPub [32]byte
	rawPub, err := curve25519.X25519(recipientPriv[:], basepoint[:])
	if err != nil {
		return fileKey, err
	}
	copy(recipientPub[:], rawPub)
	kek := wrapKEK(shared, ephemPub[:], recipientPub[:])
	defer Wipe(kek[:])
	aead, err := chacha20poly1305.NewX(kek[:])
	if err != nil {
		return fileKey, err
	}
	plain, err := aead.Open(nil, wrapped[:NonceSize], wrapped[NonceSize:], nil)
	if err != nil {
		return fileKey, fmt.Errorf("key unwrap failed")
	}
	copy(fileKey[:], plain)
	Wipe(plain)
	return fileKey, nil
}

// GenerateSignKeypair creates an Ed25519 keypair.
func GenerateSignKeypair() (pub, priv []byte, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign signs msg with an Ed25519 private key.
func Sign(priv, msg []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad private key length %d", len(priv))
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), msg), nil
}

// Verify reports whether sig is valid for msg under pub.
func Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
