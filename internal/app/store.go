package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Storage errors mirroring the contract set.
var (
	ErrNotFound = errors.New("drop not found")
	ErrExpired  = errors.New("drop expired")
	ErrQuota    = errors.New("storage quota exceeded")
)

// Provider is the local/relay storage contract used by App.
type Provider interface {
	Put(ctx context.Context, id string, r io.Reader, size int64, expiry time.Time) error
	Get(ctx context.Context, id string, offset int64) (io.ReadCloser, error)
	Delete(ctx context.Context, id string) error
	Exists(ctx context.Context, id string) (bool, error)
	Stat(ctx context.Context, id string) (size int64, expiry time.Time, err error)
	Health(ctx context.Context) error
	Backend() string
}

// FSStore is a filesystem-backed Provider rooted at dir.
type FSStore struct {
	dir string
}

// NewFSStore creates a filesystem store rooted at dir.
func NewFSStore(dir string) (*FSStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FSStore{dir: dir}, nil
}

func (s *FSStore) dataPath(id string) string { return filepath.Join(s.dir, id+".bin") }
func (s *FSStore) expPath(id string) string  { return filepath.Join(s.dir, id+".exp") }

// Put streams r to disk without loading it into memory.
func (s *FSStore) Put(ctx context.Context, id string, r io.Reader, size int64, expiry time.Time) error {
	dst := s.dataPath(id)
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	var w io.Writer = f
	if size < 0 {
		size = 0
	}
	_ = size
	if _, err := io.Copy(w, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.WriteFile(s.expPath(id), []byte(expiry.UTC().Format(time.RFC3339)), 0o644)
}

// Get opens the payload at offset for resumed reads.
func (s *FSStore) Get(_ context.Context, id string, offset int64) (io.ReadCloser, error) {
	if _, _, err := s.Stat(context.Background(), id); err != nil {
		return nil, err
	}
	f, err := os.Open(s.dataPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

// Delete removes a payload and its expiry record.
func (s *FSStore) Delete(_ context.Context, id string) error {
	if _, err := os.Stat(s.dataPath(id)); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	os.Remove(s.expPath(id))
	return os.Remove(s.dataPath(id))
}

// Exists reports whether a live payload is present.
func (s *FSStore) Exists(_ context.Context, id string) (bool, error) {
	_, _, err := s.Stat(context.Background(), id)
	if err == ErrNotFound || err == ErrExpired {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Stat returns payload size and expiry, enforcing expiry.
func (s *FSStore) Stat(_ context.Context, id string) (int64, time.Time, error) {
	fi, err := os.Stat(s.dataPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, time.Time{}, ErrNotFound
		}
		return 0, time.Time{}, err
	}
	raw, err := os.ReadFile(s.expPath(id))
	if err != nil {
		return 0, time.Time{}, ErrNotFound
	}
	exp, err := time.Parse(time.RFC3339, string(raw))
	if err != nil {
		return 0, time.Time{}, ErrNotFound
	}
	if time.Now().After(exp) {
		return 0, exp, ErrExpired
	}
	return fi.Size(), exp, nil
}

// Health probes writability of the store root.
func (s *FSStore) Health(_ context.Context) error {
	tmp, err := os.CreateTemp(s.dir, ".health-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	tmp.Close()
	return os.Remove(name)
}

// Backend names this provider.
func (s *FSStore) Backend() string { return "local" }
