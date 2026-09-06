package crypto

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCryptoFileRoundtrip(t *testing.T) {
	key, err := GenerateFileKey()
	if err != nil {
		t.Fatal(err)
	}
	// Multi-chunk payload: 2.5 MiB deterministic pseudo-random.
	plain := make([]byte, 2*(1<<20)+(1<<19))
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	src := writeTemp(t, plain)
	dir := t.TempDir()
	sealed := filepath.Join(dir, "sealed.gd")
	out := filepath.Join(dir, "out.bin")

	cHash, pHash, n, err := SealFile(src, sealed, key)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(plain)) {
		t.Fatalf("n=%d want %d", n, len(plain))
	}
	if cHash == "" || pHash == "" {
		t.Fatal("empty hashes")
	}
	wantPlain, _, err := Sha256HexFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if wantPlain != pHash {
		t.Fatal("plaintext hash mismatch")
	}
	if err := OpenFile(sealed, out, key); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestCryptoTamperFails(t *testing.T) {
	key, _ := GenerateFileKey()
	src := writeTemp(t, []byte("ghostdrop tamper test payload"))
	dir := t.TempDir()
	sealed := filepath.Join(dir, "s.gd")
	if _, _, _, err := SealFile(src, sealed, key); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(sealed)
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(sealed, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := OpenFile(sealed, filepath.Join(dir, "o.bin"), key); err == nil {
		t.Fatal("tampered file opened without error")
	}
}

func TestCryptoWrongKeyFails(t *testing.T) {
	k1, _ := GenerateFileKey()
	k2, _ := GenerateFileKey()
	src := writeTemp(t, []byte("wrong key payload"))
	dir := t.TempDir()
	sealed := filepath.Join(dir, "s.gd")
	if _, _, _, err := SealFile(src, sealed, k1); err != nil {
		t.Fatal(err)
	}
	if err := OpenFile(sealed, filepath.Join(dir, "o.bin"), k2); err == nil {
		t.Fatal("wrong key opened without error")
	}
}

func TestCryptoBytesRoundtrip(t *testing.T) {
	key, _ := GenerateFileKey()
	nonce, cipher, err := SealBytes([]byte("hello ghostdrop"), key[:])
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenBytes(nonce, cipher, key[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "hello ghostdrop" {
		t.Fatal("bytes roundtrip mismatch")
	}
}

func TestCryptoPassphraseDerive(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	k1 := DeriveKeyFromPassphrase("correct horse battery staple!", salt)
	k2 := DeriveKeyFromPassphrase("correct horse battery staple!", salt)
	if *k1 != *k2 {
		t.Fatal("derive not deterministic")
	}
	nonce, cipher, err := SealBytes([]byte("passphrase payload"), k1[:])
	if err != nil {
		t.Fatal(err)
	}
	Wipe(k1[:])
	if _, err := OpenBytes(nonce, cipher, k2[:]); err != nil {
		t.Fatal(err)
	}
	bad := DeriveKeyFromPassphrase("wrong passphrase here!", salt)
	if _, err := OpenBytes(nonce, cipher, bad[:]); err == nil {
		t.Fatal("wrong passphrase opened without error")
	}
}

func TestCryptoWrapUnwrap(t *testing.T) {
	fileKey, _ := GenerateFileKey()
	pub, priv, err := GenerateRecipientKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var ephemPriv [32]byte
	if _, err := rand.Read(ephemPriv[:]); err != nil {
		t.Fatal(err)
	}
	wrapped, ephemPub, err := WrapFileKey(fileKey, pub, ephemPriv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapFileKey(wrapped, ephemPub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != fileKey {
		t.Fatal("wrap roundtrip mismatch")
	}
	// Wrong recipient fails.
	_, badPriv, _ := GenerateRecipientKeypair()
	if _, err := UnwrapFileKey(wrapped, ephemPub, badPriv); err == nil {
		t.Fatal("wrong recipient unwrapped without error")
	}
}

func TestCryptoSignVerify(t *testing.T) {
	pub, priv, err := GenerateSignKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("manifest bytes")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, msg, sig) {
		t.Fatal("valid sig did not verify")
	}
	sig[0] ^= 1
	if Verify(pub, msg, sig) {
		t.Fatal("tampered sig verified")
	}
}

func TestCryptoDropIDFormat(t *testing.T) {
	id := GenerateDropID()
	if !strings.HasPrefix(id, "GD-") || len(id) != 15 {
		t.Fatalf("bad drop id %q", id)
	}
	for _, c := range id[3:] {
		if !strings.ContainsRune("0123456789ABCDEF", c) {
			t.Fatalf("bad drop id char %q", id)
		}
	}
}
