package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "ghostdrop.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrateCreatesTables(t *testing.T) {
	db := openTemp(t)
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := os.Stat(db.Path() + ".bak"); err != nil {
		t.Fatalf("expected backup file: %v", err)
	}
}

func TestDropCRUD(t *testing.T) {
	db := openTemp(t)
	d := Drop{
		ID: "GD-ABCDEF123456", Mode: "anonymous", Recipient: "cap",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second),
		Status: "READY", PayloadHash: "deadbeef", Size: 1234,
		StorageRef: "local/GD-ABCDEF123456",
	}
	if err := db.UpsertDrop(d); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetDrop(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != d.Mode || got.Size != d.Size || got.PayloadHash != d.PayloadHash {
		t.Fatalf("mismatch: %+v", got)
	}
	if err := db.UpdateStatus(d.ID, "DELIVERED"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVerified(d.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetDrop(d.ID)
	if string(got.Status) != "DELIVERED" || !got.Verified {
		t.Fatalf("status/verified not updated: %+v", got)
	}
	list, err := db.ListDrops()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListDrops = %d,%v", len(list), err)
	}
	if err := db.DeleteDrop(d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetDrop(d.ID); err != ErrNotFound {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestHistory(t *testing.T) {
	db := openTemp(t)
	if err := db.AddEvent("GD-ABCDEF123456", "created", "mode=anonymous"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddEvent("GD-ABCDEF123456", "retrieved", "hash=ok"); err != nil {
		t.Fatal(err)
	}
	evs, err := db.ListEvents("GD-ABCDEF123456")
	if err != nil || len(evs) != 2 {
		t.Fatalf("ListEvents = %d,%v", len(evs), err)
	}
	if evs[0].Event != "created" || evs[1].Event != "retrieved" {
		t.Fatalf("order wrong: %+v", evs)
	}
}

func TestContacts(t *testing.T) {
	db := openTemp(t)
	c := Contact{Name: "captain", Address: "dero1qxyz", Trust: TrustKnown, LastSeen: time.Now().UTC().Truncate(time.Second)}
	if err := db.PutContact(c); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetContact("captain")
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != c.Address || got.Trust != TrustKnown {
		t.Fatalf("mismatch: %+v", got)
	}
	if err := db.PutContact(Contact{Name: "spammer", Address: "dero1qbad", Trust: TrustBlocked}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutContact(Contact{Name: "x", Address: "y", Trust: "SUPER"}); err == nil {
		t.Fatal("bad trust must fail")
	}
	all, err := db.ListContacts()
	if err != nil || len(all) != 2 {
		t.Fatalf("ListContacts = %d,%v", len(all), err)
	}
	if err := db.DeleteContact("spammer"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetContact("spammer"); err != ErrNotFound {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestMemoryDB(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertDrop(Drop{ID: "GD-ABCDEF123456", Mode: "direct", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Status: "READY"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetDrop("GD-ABCDEF123456"); err != nil {
		t.Fatal(err)
	}
}
