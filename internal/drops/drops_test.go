package drops

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ghostdrop/internal/crypto"
	"ghostdrop/internal/database"
	"ghostdrop/internal/storage"
)

func ctx() context.Context { return context.Background() }

func testManager(t *testing.T, ghost bool) (*Manager, *database.DB) {
	t.Helper()
	store := storage.NewMemoryProvider(1 << 30)
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	m := NewManager(store, db, ghost, t.TempDir())
	return m, db
}

func writeSrc(t *testing.T, size int) string {
	t.Helper()
	block := []byte("ghostdrop-e2e-block-0123456789-")
	payload := bytes.Repeat(block, size/len(block)+2)[:size]
	path := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCreateRetrieveRevoke(t *testing.T) {
	m, db := testManager(t, false)
	src := writeSrc(t, 300000) // multi-chunk-ish but under 1MiB
	wantHash, _, err := crypto.Sha256HexFile(src)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := crypto.GenerateSignKeypair()
	if err != nil {
		t.Fatal(err)
	}
	man, key, err := m.Create(ctx(), src, CreateOpts{
		Mode: "anonymous", Expiry: time.Now().Add(24 * time.Hour),
		SignPriv: priv, SignBy: "alice",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !man.Verify() {
		t.Fatal("manifest must verify")
	}
	st, err := m.Status(ctx(), man.DropID)
	if err != nil || st != StatusReady {
		t.Fatalf("Status = %v,%v", st, err)
	}
	off, err := m.ResumeOffset(ctx(), man.DropID)
	if err != nil || off != man.PayloadSize {
		t.Fatalf("ResumeOffset = %d,%v (payload %d)", off, err, man.PayloadSize)
	}
	// DB record present (non-ghost).
	if _, err := db.GetDrop(man.DropID); err != nil {
		t.Fatalf("db record missing: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := m.Retrieve(ctx(), man.DropID, dst, RetrieveOpts{Key: &key}); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	gotHash, _, err := crypto.Sha256HexFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != wantHash {
		t.Fatal("plaintext hash mismatch after retrieve")
	}
	if st, _ := m.Status(ctx(), man.DropID); st != StatusVerified {
		t.Fatalf("Status after retrieve = %v", st)
	}

	if err := m.Revoke(ctx(), man.DropID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if st, _ := m.Status(ctx(), man.DropID); st != StatusRevoked {
		t.Fatalf("Status after revoke = %v", st)
	}
	if ok, _ := m.Store().Exists(ctx(), man.DropID); ok {
		t.Fatal("payload must be gone after revoke")
	}
}

func TestGhostModeNoDBWrites(t *testing.T) {
	m, db := testManager(t, true)
	src := writeSrc(t, 1024)
	man, key, err := m.Create(ctx(), src, CreateOpts{Mode: "anonymous"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetDrop(man.DropID); err != database.ErrNotFound {
		t.Fatalf("ghost mode wrote to db: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := m.Retrieve(ctx(), man.DropID, dst, RetrieveOpts{Key: &key}); err != nil {
		t.Fatal(err)
	}
}

func TestRecipientLock(t *testing.T) {
	m, _ := testManager(t, true)
	pub, priv, err := crypto.GenerateRecipientKeypair()
	if err != nil {
		t.Fatal(err)
	}
	src := writeSrc(t, 4096)
	man, _, err := m.Create(ctx(), src, CreateOpts{Mode: "recipient", RecipientPub: &pub})
	if err != nil {
		t.Fatal(err)
	}
	if man.Access.WrappedKey == "" || man.Access.EphemPub == "" {
		t.Fatal("recipient lock material missing")
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := m.Retrieve(ctx(), man.DropID, dst, RetrieveOpts{RecipientPriv: &priv}); err != nil {
		t.Fatalf("recipient retrieve: %v", err)
	}
	want, _, _ := crypto.Sha256HexFile(src)
	got, _, _ := crypto.Sha256HexFile(dst)
	if want != got {
		t.Fatal("hash mismatch")
	}
}

func TestPasswordLock(t *testing.T) {
	m, _ := testManager(t, true)
	src := writeSrc(t, 4096)
	man, _, err := m.Create(ctx(), src, CreateOpts{Mode: "password", Password: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	if man.Access.PassphraseSalt == "" || man.Access.KDF != "argon2id" {
		t.Fatalf("passphrase material missing: %+v", man.Access)
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := m.Retrieve(ctx(), man.DropID, dst, RetrieveOpts{Password: "correct horse"}); err != nil {
		t.Fatalf("password retrieve: %v", err)
	}
	dst2 := filepath.Join(t.TempDir(), "out2.bin")
	if err := m.Retrieve(ctx(), man.DropID, dst2, RetrieveOpts{Password: "wrong"}); err == nil {
		t.Fatal("wrong password must fail")
	}
}

func TestExpiryEnforced(t *testing.T) {
	m, _ := testManager(t, true)
	src := writeSrc(t, 512)
	man, key, err := m.Create(ctx(), src, CreateOpts{
		Mode: "anonymous", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force expiry by editing the cached manifest.
	cached, _ := m.GetManifest(man.DropID)
	cached.ExpiresAt = time.Now().Add(-time.Minute)
	if st, _ := m.Status(ctx(), man.DropID); st != StatusExpired {
		t.Fatalf("Status = %v, want EXPIRED", st)
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := m.Retrieve(ctx(), man.DropID, dst, RetrieveOpts{Key: &key}); err != ErrExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestOneTimeDeletesPayload(t *testing.T) {
	m, _ := testManager(t, true)
	src := writeSrc(t, 512)
	man, key, err := m.Create(ctx(), src, CreateOpts{Mode: "anonymous", OneTime: true})
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := m.Retrieve(ctx(), man.DropID, dst, RetrieveOpts{Key: &key}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Store().Exists(ctx(), man.DropID); ok {
		t.Fatal("one-time payload must be deleted after retrieve")
	}
}
