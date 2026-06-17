package cache

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type fakeStore struct {
	data       map[string][]byte
	closed     bool
	clearHits  int
	existsHits int
	err        error
}

func newFakeStore() *fakeStore {
	return &fakeStore{data: make(map[string][]byte)}
}

func (s *fakeStore) Get(ctx context.Context, key string) ([]byte, error) {
	_ = ctx
	if s.err != nil {
		return nil, s.err
	}
	val, ok := s.data[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), val...), nil
}

func (s *fakeStore) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	_, _ = ctx, ttl
	if s.err != nil {
		return s.err
	}
	s.data[key] = append([]byte(nil), val...)
	return nil
}

func (s *fakeStore) Delete(ctx context.Context, key string) error {
	_ = ctx
	if s.err != nil {
		return s.err
	}
	delete(s.data, key)
	return nil
}

func (s *fakeStore) Clear(ctx context.Context) error {
	_ = ctx
	if s.err != nil {
		return s.err
	}
	s.clearHits++
	s.data = make(map[string][]byte)
	return nil
}

func (s *fakeStore) Close() error {
	s.closed = true
	return s.err
}

func (s *fakeStore) Exists(ctx context.Context, key string) (bool, error) {
	_ = ctx
	if s.err != nil {
		return false, s.err
	}
	s.existsHits++
	_, ok := s.data[key]
	return ok, nil
}

type fakeStoreWithoutExists struct {
	inner *fakeStore
}

func (s *fakeStoreWithoutExists) Get(ctx context.Context, key string) ([]byte, error) {
	return s.inner.Get(ctx, key)
}

func (s *fakeStoreWithoutExists) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return s.inner.Set(ctx, key, val, ttl)
}

func (s *fakeStoreWithoutExists) Delete(ctx context.Context, key string) error {
	return s.inner.Delete(ctx, key)
}

func (s *fakeStoreWithoutExists) Clear(ctx context.Context) error {
	return s.inner.Clear(ctx)
}

func (s *fakeStoreWithoutExists) Close() error {
	return s.inner.Close()
}

func TestCacheHappyPath(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	c := NewStorageCache(store)

	var _ Cache = c

	if err := c.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	val, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(val, []byte("v")) {
		t.Fatalf("Get() = %q, want v", val)
	}
	ok, err := c.Exists(ctx, "k")
	if err != nil || !ok {
		t.Fatalf("Exists() = %v, %v; want true, nil", ok, err)
	}
	if store.existsHits != 1 {
		t.Fatalf("Exists() should use ExistenceStore, hits = %d", store.existsHits)
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := c.Get(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(deleted) error = %v, want ErrNotFound", err)
	}
}

func TestCacheMissConvertsNilToErrNotFound(t *testing.T) {
	c := NewStorageCache(newFakeStore())

	val, err := c.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
	if val != nil {
		t.Fatalf("Get() value = %q, want nil", val)
	}
}

func TestCacheExistsFallsBackToGet(t *testing.T) {
	ctx := context.Background()
	inner := newFakeStore()
	store := &fakeStoreWithoutExists{inner: inner}
	c := NewStorageCache(store)

	ok, err := c.Exists(ctx, "missing")
	if err != nil || ok {
		t.Fatalf("Exists(missing) = %v, %v; want false, nil", ok, err)
	}
	if err := c.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	ok, err = c.Exists(ctx, "k")
	if err != nil || !ok {
		t.Fatalf("Exists(k) = %v, %v; want true, nil", ok, err)
	}
	if inner.existsHits != 0 {
		t.Fatalf("fallback store should not call ExistenceStore, hits = %d", inner.existsHits)
	}
}

func TestCacheClearAndClose(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	c := NewStorageCache(store)

	if err := c.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := c.Clear(ctx); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if store.clearHits != 1 {
		t.Fatalf("Clear() hits = %d, want 1", store.clearHits)
	}
	if ok, _ := c.Exists(ctx, "k"); ok {
		t.Fatalf("Clear() should remove key")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !store.closed {
		t.Fatalf("Close() should close store")
	}
	if c.Store() != store {
		t.Fatalf("Store() should expose underlying store")
	}
}

func TestCachePropagatesStoreErrors(t *testing.T) {
	wantErr := errors.New("store down")
	store := newFakeStore()
	store.err = wantErr
	c := NewStorageCache(store)
	ctx := context.Background()

	if _, err := c.Get(ctx, "k"); !errors.Is(err, wantErr) {
		t.Fatalf("Get() error = %v, want %v", err, wantErr)
	}
	if err := c.Set(ctx, "k", []byte("v"), 0); !errors.Is(err, wantErr) {
		t.Fatalf("Set() error = %v, want %v", err, wantErr)
	}
	if err := c.Delete(ctx, "k"); !errors.Is(err, wantErr) {
		t.Fatalf("Delete() error = %v, want %v", err, wantErr)
	}
	if _, err := c.Exists(ctx, "k"); !errors.Is(err, wantErr) {
		t.Fatalf("Exists() error = %v, want %v", err, wantErr)
	}
	if err := c.Clear(ctx); !errors.Is(err, wantErr) {
		t.Fatalf("Clear() error = %v, want %v", err, wantErr)
	}
	if err := c.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close() error = %v, want %v", err, wantErr)
	}
}
