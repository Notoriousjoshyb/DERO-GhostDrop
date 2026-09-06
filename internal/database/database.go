// Package database persists drop records, event history, and contacts in
// SQLite (modernc.org/sqlite, pure Go) at the OS-native data directory.
package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ghostdrop/internal/platform"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("database: not found")

// Trust levels for contacts.
const (
	TrustUnknown = "UNKNOWN"
	TrustKnown   = "KNOWN"
	TrustTrusted = "TRUSTED"
	TrustBlocked = "BLOCKED"
)

// schema creates all tables.
const schema = `
CREATE TABLE IF NOT EXISTS drops(
  id TEXT PRIMARY KEY,
  mode TEXT NOT NULL,
  recipient TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_hash TEXT NOT NULL DEFAULT '',
  size INTEGER NOT NULL DEFAULT 0,
  storage_ref TEXT NOT NULL DEFAULT '',
  verified INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS history(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  drop_id TEXT NOT NULL,
  event TEXT NOT NULL,
  at TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_history_drop ON history(drop_id);
CREATE TABLE IF NOT EXISTS contacts(
  name TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  trust TEXT NOT NULL DEFAULT 'UNKNOWN',
  last_seen TEXT NOT NULL DEFAULT ''
);
`

// DB wraps the SQLite connection.
type DB struct {
	sql  *sql.DB
	path string
}

// Open opens (creating parent dirs) the SQLite database at path.
// The path ":memory:" selects an in-memory database (tests).
func Open(path string) (*DB, error) {
	if path != ":memory:" {
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, err
			}
		}
	}
	sqldb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, err
	}
	db := &DB{sql: sqldb, path: path}
	if err := db.Migrate(); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// OpenDefault opens DataDir()/ghostdrop.db.
func OpenDefault() (*DB, error) { return Open(platform.DBFile()) }

// Close closes the database.
func (db *DB) Close() error { return db.sql.Close() }

// Path returns the database file path.
func (db *DB) Path() string { return db.path }

// Migrate backs up the file, applies the schema, verifies all tables, and
// restores the backup (rollback) on failure.
func (db *DB) Migrate() error {
	if db.path != ":memory:" {
		if _, err := os.Stat(db.path); err == nil {
			bak := db.path + ".bak"
			if err := copyFile(db.path, bak); err != nil {
				return fmt.Errorf("database: backup: %w", err)
			}
			defer func() {
				// Rollback is handled explicitly below; this only cleans
				// the *stale* backup marker logic — keep .bak for recovery.
			}()
			if err := db.migrateInner(); err != nil {
				_ = copyFile(bak, db.path)
				return err
			}
			return db.verify()
		}
	}
	if err := db.migrateInner(); err != nil {
		return err
	}
	return db.verify()
}

func (db *DB) migrateInner() error {
	_, err := db.sql.Exec(schema)
	return err
}

// verify confirms every expected table exists.
func (db *DB) verify() error {
	for _, t := range []string{"drops", "history", "contacts"} {
		var name string
		err := db.sql.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, t).Scan(&name)
		if err != nil {
			return fmt.Errorf("database: verify table %s: %w", t, err)
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o600)
}

// Drop is one drop record.
type Drop struct {
	ID          string
	Mode        string
	Recipient   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Status      string
	PayloadHash string
	Size        int64
	StorageRef  string
	Verified    bool
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// UpsertDrop inserts or replaces a drop record.
func (db *DB) UpsertDrop(d Drop) error {
	_, err := db.sql.Exec(`INSERT INTO drops(id,mode,recipient,created_at,expires_at,status,payload_hash,size,storage_ref,verified)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET mode=excluded.mode,recipient=excluded.recipient,created_at=excluded.created_at,expires_at=excluded.expires_at,status=excluded.status,payload_hash=excluded.payload_hash,size=excluded.size,storage_ref=excluded.storage_ref,verified=excluded.verified`,
		d.ID, d.Mode, d.Recipient, d.CreatedAt.UTC().Format(time.RFC3339),
		d.ExpiresAt.UTC().Format(time.RFC3339), d.Status, d.PayloadHash,
		d.Size, d.StorageRef, boolInt(d.Verified))
	return err
}

func scanDrop(row *sql.Row) (Drop, error) {
	var d Drop
	var created, expires string
	var verified int
	err := row.Scan(&d.ID, &d.Mode, &d.Recipient, &created, &expires,
		&d.Status, &d.PayloadHash, &d.Size, &d.StorageRef, &verified)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return d, ErrNotFound
		}
		return d, err
	}
	if d.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
		return d, err
	}
	if d.ExpiresAt, err = time.Parse(time.RFC3339, expires); err != nil {
		return d, err
	}
	d.Verified = verified != 0
	return d, nil
}

// GetDrop returns the drop record for id.
func (db *DB) GetDrop(id string) (Drop, error) {
	return scanDrop(db.sql.QueryRow(
		`SELECT id,mode,recipient,created_at,expires_at,status,payload_hash,size,storage_ref,verified FROM drops WHERE id=?`, id))
}

// ListDrops returns all drops, newest first.
func (db *DB) ListDrops() ([]Drop, error) {
	rows, err := db.sql.Query(
		`SELECT id,mode,recipient,created_at,expires_at,status,payload_hash,size,storage_ref,verified FROM drops ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Drop
	for rows.Next() {
		var d Drop
		var created, expires string
		var verified int
		if err := rows.Scan(&d.ID, &d.Mode, &d.Recipient, &created, &expires,
			&d.Status, &d.PayloadHash, &d.Size, &d.StorageRef, &verified); err != nil {
			return nil, err
		}
		var err error
		if d.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, err
		}
		if d.ExpiresAt, err = time.Parse(time.RFC3339, expires); err != nil {
			return nil, err
		}
		d.Verified = verified != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateStatus sets a drop's status.
func (db *DB) UpdateStatus(id, status string) error {
	res, err := db.sql.Exec(`UPDATE drops SET status=? WHERE id=?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetVerified sets a drop's verified flag.
func (db *DB) SetVerified(id string, v bool) error {
	res, err := db.sql.Exec(`UPDATE drops SET verified=? WHERE id=?`, boolInt(v), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteDrop removes a drop record and its history.
func (db *DB) DeleteDrop(id string) error {
	if _, err := db.sql.Exec(`DELETE FROM history WHERE drop_id=?`, id); err != nil {
		return err
	}
	res, err := db.sql.Exec(`DELETE FROM drops WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Event is one history row.
type Event struct {
	ID     int64
	DropID string
	Event  string
	At     time.Time
	Detail string
}

// AddEvent appends a history event.
func (db *DB) AddEvent(dropID, event, detail string) error {
	_, err := db.sql.Exec(`INSERT INTO history(drop_id,event,at,detail) VALUES(?,?,?,?)`,
		dropID, event, time.Now().UTC().Format(time.RFC3339), detail)
	return err
}

// ListEvents returns history for a drop, oldest first.
func (db *DB) ListEvents(dropID string) ([]Event, error) {
	rows, err := db.sql.Query(
		`SELECT id,drop_id,event,at,detail FROM history WHERE drop_id=? ORDER BY id ASC`, dropID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at string
		if err := rows.Scan(&e.ID, &e.DropID, &e.Event, &at, &e.Detail); err != nil {
			return nil, err
		}
		if e.At, err = time.Parse(time.RFC3339, at); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Contact is one address-book row.
type Contact struct {
	Name     string
	Address  string
	Trust    string
	LastSeen time.Time
}

func validTrust(t string) bool {
	switch t {
	case TrustUnknown, TrustKnown, TrustTrusted, TrustBlocked:
		return true
	}
	return false
}

// PutContact inserts or replaces a contact.
func (db *DB) PutContact(c Contact) error {
	if !validTrust(c.Trust) {
		return fmt.Errorf("database: bad trust %q", c.Trust)
	}
	last := ""
	if !c.LastSeen.IsZero() {
		last = c.LastSeen.UTC().Format(time.RFC3339)
	}
	_, err := db.sql.Exec(`INSERT INTO contacts(name,address,trust,last_seen) VALUES(?,?,?,?)
ON CONFLICT(name) DO UPDATE SET address=excluded.address,trust=excluded.trust,last_seen=excluded.last_seen`,
		c.Name, c.Address, c.Trust, last)
	return err
}

// GetContact returns the contact for name.
func (db *DB) GetContact(name string) (Contact, error) {
	var c Contact
	var last string
	err := db.sql.QueryRow(`SELECT name,address,trust,last_seen FROM contacts WHERE name=?`, name).
		Scan(&c.Name, &c.Address, &c.Trust, &last)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c, ErrNotFound
		}
		return c, err
	}
	if last != "" {
		if c.LastSeen, err = time.Parse(time.RFC3339, last); err != nil {
			return c, err
		}
	}
	return c, nil
}

// ListContacts returns all contacts by name.
func (db *DB) ListContacts() ([]Contact, error) {
	rows, err := db.sql.Query(`SELECT name,address,trust,last_seen FROM contacts ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Contact
	for rows.Next() {
		var c Contact
		var last string
		if err := rows.Scan(&c.Name, &c.Address, &c.Trust, &last); err != nil {
			return nil, err
		}
		if last != "" {
			var err error
			if c.LastSeen, err = time.Parse(time.RFC3339, last); err != nil {
				return nil, err
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteContact removes a contact.
func (db *DB) DeleteContact(name string) error {
	res, err := db.sql.Exec(`DELETE FROM contacts WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
