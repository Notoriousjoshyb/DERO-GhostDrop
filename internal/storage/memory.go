package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// memItem is one stored blob.
type memItem struct {
	data   []byte
	expiry time.Time
}

// MemoryProvider is an in-memory Provider (tests, ghost mode, cache).
type MemoryProvider struct {
	mu       sync.RWMutex
	items    map[string]*memItem
	used     int64
	maxBytes int64
}

// NewMemoryProvider returns an in-memory provider capped at maxBytes total.
// A non-positive maxBytes selects DefaultQuotaBytes.
func NewMemoryProvider(maxBytes int64) *MemoryProvider {
	if maxBytes <= 0 {
		maxBytes = DefaultQuotaBytes
	}
	return &MemoryProvider{items: map[string]*memItem{}, maxBytes: maxBytes}
}

// Backend implements Provider.
func (p *MemoryProvider) Backend() string { return BackendMemory }

// Put implements Provider.
func (p *MemoryProvider) Put(ctx context.Context, id string, r io.Reader, size int64, expiry time.Time) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("storage: negative size")
	}
	// Cap a single object at the quota so one Put cannot OOM the process.
	limited := io.LimitReader(r, p.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > p.maxBytes {
		return ErrQuota
	}
	if int64(len(data)) != size {
		return fmt.Errorf("storage: short read: got %d want %d", len(data), size)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	old := int64(0)
	if it, ok := p.items[id]; ok {
		old = int64(len(it.data))
	}
	if p.used-old+size > p.maxBytes {
		return ErrQuota
	}
	p.items[id] = &memItem{data: data, expiry: expiry}
	p.used = p.used - old + size
	return nil
}

// Get implements Provider.
func (p *MemoryProvider) Get(ctx context.Context, id string, offset int64) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	it, ok := p.items[id]
	p.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if !it.expiry.IsZero() && time.Now().After(it.expiry) {
		p.mu.Lock()
		delete(p.items, id)
		p.used -= int64(len(it.data))
		p.mu.Unlock()
		return nil, ErrExpired
	}
	if offset < 0 || offset > int64(len(it.data)) {
		return nil, fmt.Errorf("storage: offset %d out of range (size %d)", offset, len(it.data))
	}
	return io.NopCloser(bytes.NewReader(it.data[offset:])), nil
}

// Delete implements Provider (idempotent).
func (p *MemoryProvider) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if it, ok := p.items[id]; ok {
		delete(p.items, id)
		p.used -= int64(len(it.data))
	}
	return nil
}

// Exists implements Provider. Expired entries report false and are swept.
func (p *MemoryProvider) Exists(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	it, ok := p.items[id]
	if !ok {
		return false, nil
	}
	if !it.expiry.IsZero() && time.Now().After(it.expiry) {
		delete(p.items, id)
		p.used -= int64(len(it.data))
		return false, nil
	}
	return true, nil
}

// Stat implements Provider.
func (p *MemoryProvider) Stat(ctx context.Context, id string) (int64, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return 0, time.Time{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	it, ok := p.items[id]
	if !ok {
		return 0, time.Time{}, ErrNotFound
	}
	if !it.expiry.IsZero() && time.Now().After(it.expiry) {
		delete(p.items, id)
		p.used -= int64(len(it.data))
		return 0, time.Time{}, ErrExpired
	}
	return int64(len(it.data)), it.expiry, nil
}

// Health implements Provider.
func (p *MemoryProvider) Health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
