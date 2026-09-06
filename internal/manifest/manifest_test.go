package manifest

import (
	"testing"
	"time"

	"ghostdrop/internal/crypto"
)

func testKey() (key [32]byte) {
	k, err := crypto.GenerateFileKey()
	if err != nil {
		panic(err)
	}
	return k
}

func TestNewValidate(t *testing.T) {
	m := New(crypto.GenerateDropID(), "anonymous", time.Now().Add(time.Hour))
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if m.Version != Version || m.ChunkSize != ChunkSize {
		t.Fatalf("bad defaults: %+v", m)
	}
}

func TestValidateRejects(t *testing.T) {
	good := New(crypto.GenerateDropID(), "anonymous", time.Now().Add(time.Hour))
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.DropID = "bogus" },
		func(m *Manifest) { m.Version = 99 },
		func(m *Manifest) { m.Mode = "teleport" },
		func(m *Manifest) { m.ExpiresAt = m.CreatedAt.Add(-time.Hour) },
		func(m *Manifest) { m.ChunkSize = 512 },
		func(m *Manifest) { m.FileCount = 7 },
	} {
		m := *good
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Fatalf("expected Validate error for %+v", &m)
		}
	}
}

func TestSignVerify(t *testing.T) {
	m := New(crypto.GenerateDropID(), "direct", time.Now().Add(time.Hour))
	if m.Verify() {
		t.Fatal("unsigned manifest must not verify")
	}
	pub, priv, err := crypto.GenerateSignKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sign(priv, "tester"); err != nil {
		t.Fatal(err)
	}
	if !m.Verify() {
		t.Fatal("signed manifest must verify")
	}
	if m.Signature.By != "tester" {
		t.Fatalf("lost signer: %q", m.Signature.By)
	}
	_ = pub
	// Tamper → verify fails.
	m.PayloadSize++
	if m.Verify() {
		t.Fatal("tampered manifest must not verify")
	}
}

func TestFilenamesRoundtrip(t *testing.T) {
	key := testKey()
	m := New(crypto.GenerateDropID(), "anonymous", time.Now().Add(time.Hour))
	names := []string{"hello.txt", "spaced name №2.bin", "🔒.dat"}
	if err := m.EncryptFilenames(names, key); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate after EncryptFilenames: %v", err)
	}
	got, err := m.DecryptFilenames(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(names) {
		t.Fatalf("got %d names, want %d", len(got), len(names))
	}
	for i := range names {
		if got[i] != names[i] {
			t.Fatalf("name %d: got %q want %q", i, got[i], names[i])
		}
	}
	var other [32]byte
	other[0] = 1
	if _, err := m.DecryptFilenames(other); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestMetadataRoundtrip(t *testing.T) {
	key := testKey()
	nonceHex, cipherHex, err := SealMetadata([]byte("sender notes"), key)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenMetadata(nonceHex, cipherHex, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "sender notes" {
		t.Fatalf("got %q", plain)
	}
}

func TestSaveLoad(t *testing.T) {
	m := New(crypto.GenerateDropID(), "paid", time.Now().Add(time.Hour))
	key := testKey()
	if err := m.EncryptFilenames([]string{"a.bin"}, key); err != nil {
		t.Fatal(err)
	}
	_, priv, err := crypto.GenerateSignKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sign(priv, "save-test"); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/m.json"
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Verify() {
		t.Fatal("loaded manifest must verify")
	}
	if loaded.DropID != m.DropID {
		t.Fatalf("drop id mismatch: %q vs %q", loaded.DropID, m.DropID)
	}
}
