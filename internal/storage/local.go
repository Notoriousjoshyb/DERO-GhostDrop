package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// localMeta is the .meta.json sidecar for a stored blob.
type localMeta struct {
	Size   int64     `json:"size"`
	Expiry time.Time `json:"expiry"`
}

// LocalProvider stores blobs under <dataDir>/drops/{id}.bin with a
// .meta.json sidecar. Writes are atomic (tmp file + rename) and streamed.
type LocalProvider struct {
	dir      string
	maxBytes int64
}

// NewLocalProvider opens (creating) the local store under dataDir.
func NewLocalProvider(dataDir string, maxBytes int64) (*LocalProvider, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("storage: local provider needs DataDir")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultQuotaBytes
	}
	dir := filepath.Join(dataDir, "drops")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &LocalProvider{dir: dir, maxBytes: maxBytes}, nil
}

// Backend implements Provider.
func (p *LocalProvider) Backend() string { return BackendLocal }

func (p *LocalProvider) binPath(id string) string  { return filepath.Join(p.dir, id+".bin") }
func (p *LocalProvider) metaPath(id string) string { return filepath.Join(p.dir, id+".meta.json") }

func (p *LocalProvider) readMeta(id string) (localMeta, error) {
	var m localMeta
	raw, err := os.ReadFile(p.metaPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return m, ErrNotFound
		}
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	return m, nil
}

// dirUsed sums stored payload bytes (sidecars excluded).
func (p *LocalProvider) dirUsed() int64 {
	ents, err := os.ReadDir(p.dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// sweep removes expired blobs; best-effort.
func (p *LocalProvider) sweep() {
	ents, err := os.ReadDir(p.dir)
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".meta.json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".meta.json")
		raw, err := os.ReadFile(filepath.Join(p.dir, e.Name()))
		if err != nil {
			continue
		}
		var m localMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		if !m.Expiry.IsZero() && now.After(m.Expiry) {
			os.Remove(p.binPath(id))
			os.Remove(p.metaPath(id))
		}
	}
}

// Put implements Provider.
func (p *LocalProvider) Put(ctx context.Context, id string, r io.Reader, size int64, expiry time.Time) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("storage: negative size")
	}
	if size > p.maxBytes || p.dirUsed()+size > p.maxBytes {
		return ErrQuota
	}
	tmp, err := os.CreateTemp(p.dir, id+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	var written int64
	buf := make([]byte, 1<<20)
	for written < size {
		if err := ctx.Err(); err != nil {
			tmp.Close()
			return err
		}
		want := int64(len(buf))
		if size-written < want {
			want = size - written
		}
		n, err := io.ReadFull(r, buf[:want])
		written += int64(n)
		if n > 0 {
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				tmp.Close()
				return werr
			}
		}
		if err != nil {
			tmp.Close()
			return fmt.Errorf("storage: short read: got %d want %d", written, size)
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	meta := localMeta{Size: size, Expiry: expiry}
	mraw, _ := json.Marshal(meta)
	if err := os.WriteFile(tmpName+".meta.json", mraw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p.binPath(id)); err != nil {
		os.Remove(tmpName + ".meta.json")
		return err
	}
	if err := os.Rename(tmpName+".meta.json", p.metaPath(id)); err != nil {
		os.Remove(p.binPath(id))
		return err
	}
	return nil
}

// Get implements Provider.
func (p *LocalProvider) Get(ctx context.Context, id string, offset int64) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	m, err := p.readMeta(id)
	if err != nil {
		return nil, err
	}
	if !m.Expiry.IsZero() && time.Now().After(m.Expiry) {
		os.Remove(p.binPath(id))
		os.Remove(p.metaPath(id))
		return nil, ErrExpired
	}
	f, err := os.Open(p.binPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if offset < 0 || offset > m.Size {
		f.Close()
		return nil, fmt.Errorf("storage: offset %d out of range (size %d)", offset, m.Size)
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

// Delete implements Provider (idempotent).
func (p *LocalProvider) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateID(id); err != nil {
		return err
	}
	os.Remove(p.binPath(id))
	os.Remove(p.metaPath(id))
	return nil
}

// Exists implements Provider.
func (p *LocalProvider) Exists(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m, err := p.readMeta(id)
	if err != nil {
		if err == ErrNotFound {
			return false, nil
		}
		return false, err
	}
	if !m.Expiry.IsZero() && time.Now().After(m.Expiry) {
		os.Remove(p.binPath(id))
		os.Remove(p.metaPath(id))
		return false, nil
	}
	if _, err := os.Stat(p.binPath(id)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Stat implements Provider.
func (p *LocalProvider) Stat(ctx context.Context, id string) (int64, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return 0, time.Time{}, err
	}
	m, err := p.readMeta(id)
	if err != nil {
		return 0, time.Time{}, err
	}
	if !m.Expiry.IsZero() && time.Now().After(m.Expiry) {
		os.Remove(p.binPath(id))
		os.Remove(p.metaPath(id))
		return 0, time.Time{}, ErrExpired
	}
	return m.Size, m.Expiry, nil
}

// Health implements Provider; it also sweeps expired blobs.
func (p *LocalProvider) Health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Stat(p.dir); err != nil {
		return err
	}
	p.sweep()
	return nil
}
