// Package tests exercises the crypto + security contract end to end.
package tests

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"ghostdrop/internal/crypto"
	"ghostdrop/internal/security"
)

func TestCryptoFileRoundtrip(t *testing.T) {
	key, err := crypto.GenerateFileKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 1<<20+12345) // spans two chunks
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(src, plain, 0600); err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(dir, "sealed.gd")
	out := filepath.Join(dir, "out.bin")
	if _, _, _, err := crypto.SealFile(src, sealed, key); err != nil {
		t.Fatal(err)
	}
	if err := crypto.OpenFile(sealed, out, key); err != nil {
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

func TestCryptoTamperRejected(t *testing.T) {
	key, _ := crypto.GenerateFileKey()
	dir := t.TempDir()
	src := filepath.Join(dir, "in.bin")
	_ = os.WriteFile(src, []byte("tamper me"), 0600)
	sealed := filepath.Join(dir, "s.gd")
	if _, _, _, err := crypto.SealFile(src, sealed, key); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(sealed)
	raw[len(raw)-5] ^= 0x01
	_ = os.WriteFile(sealed, raw, 0600)
	if err := crypto.OpenFile(sealed, filepath.Join(dir, "o.bin"), key); err == nil {
		t.Fatal("tampered open succeeded")
	}
}

func TestCryptoWrongKeyRejected(t *testing.T) {
	k1, _ := crypto.GenerateFileKey()
	k2, _ := crypto.GenerateFileKey()
	dir := t.TempDir()
	src := filepath.Join(dir, "in.bin")
	_ = os.WriteFile(src, []byte("secret"), 0600)
	sealed := filepath.Join(dir, "s.gd")
	if _, _, _, err := crypto.SealFile(src, sealed, k1); err != nil {
		t.Fatal(err)
	}
	if err := crypto.OpenFile(sealed, filepath.Join(dir, "o.bin"), k2); err == nil {
		t.Fatal("wrong-key open succeeded")
	}
}

func TestCryptoPassphraseRoundtrip(t *testing.T) {
	salt, err := crypto.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	good := crypto.DeriveKeyFromPassphrase("S3cure!Passphrase#42", salt)
	nonce, cipher, err := crypto.SealBytes([]byte("passphrase data"), good[:])
	if err != nil {
		t.Fatal(err)
	}
	same := crypto.DeriveKeyFromPassphrase("S3cure!Passphrase#42", salt)
	if _, err := crypto.OpenBytes(nonce, cipher, same[:]); err != nil {
		t.Fatal(err)
	}
	bad := crypto.DeriveKeyFromPassphrase("Wrong!Passphrase#43", salt)
	if _, err := crypto.OpenBytes(nonce, cipher, bad[:]); err == nil {
		t.Fatal("wrong passphrase opened")
	}
	crypto.Wipe(good[:])
	crypto.Wipe(same[:])
	crypto.Wipe(bad[:])
}

func TestCryptoWrapRoundtrip(t *testing.T) {
	fileKey, _ := crypto.GenerateFileKey()
	pub, priv, err := crypto.GenerateRecipientKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var ephemPriv [32]byte
	if _, err := rand.Read(ephemPriv[:]); err != nil {
		t.Fatal(err)
	}
	wrapped, ephemPub, err := crypto.WrapFileKey(fileKey, pub, ephemPriv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.UnwrapFileKey(wrapped, ephemPub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != fileKey {
		t.Fatal("wrap mismatch")
	}
}

func TestSecurityTraversalBlocked(t *testing.T) {
	dir := t.TempDir()
	got, err := security.SafeJoin(dir, "../../evil.txt")
	if err != nil {
		return // blocked outright: fine
	}
	if filepath.Dir(got) != dir {
		t.Fatalf("escaped: %q", got)
	}
}

func TestSecurityManifestCapRejected(t *testing.T) {
	if err := security.ValidateManifestSize(security.MaxManifestSize + 1); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}
