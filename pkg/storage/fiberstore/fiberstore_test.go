package fiberstore

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/darkit/gin/pkg/storage"
)

type fakeFiberStorage struct {
	data      map[string][]byte
	conn      *fakeConn
	closed    bool
	lastCtx   context.Context
	resetHits int
}

type fakeConn struct {
	name string
}

func newFakeFiberStorage() *fakeFiberStorage {
	return &fakeFiberStorage{
		data: make(map[string][]byte),
		conn: &fakeConn{name: "fake"},
	}
}

func (f *fakeFiberStorage) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	f.lastCtx = ctx
	val, ok := f.data[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), val...), nil
}

func (f *fakeFiberStorage) Get(key string) ([]byte, error) {
	return f.GetWithContext(context.Background(), key)
}

func (f *fakeFiberStorage) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	_ = exp
	f.lastCtx = ctx
	f.data[key] = append([]byte(nil), val...)
	return nil
}

func (f *fakeFiberStorage) Set(key string, val []byte, exp time.Duration) error {
	return f.SetWithContext(context.Background(), key, val, exp)
}

func (f *fakeFiberStorage) DeleteWithContext(ctx context.Context, key string) error {
	f.lastCtx = ctx
	delete(f.data, key)
	return nil
}

func (f *fakeFiberStorage) Delete(key string) error {
	return f.DeleteWithContext(context.Background(), key)
}

func (f *fakeFiberStorage) ResetWithContext(ctx context.Context) error {
	f.lastCtx = ctx
	f.resetHits++
	f.data = make(map[string][]byte)
	return nil
}

func (f *fakeFiberStorage) Reset() error {
	return f.ResetWithContext(context.Background())
}

func (f *fakeFiberStorage) Close() error {
	f.closed = true
	return nil
}

func (f *fakeFiberStorage) Conn() *fakeConn {
	return f.conn
}

func TestStoreAdaptsFiberStorage(t *testing.T) {
	ctx := context.WithValue(context.Background(), "scope", "test")
	raw := newFakeFiberStorage()
	store := New(raw)

	var _ storage.Store = store

	if val, err := store.Get(ctx, "missing"); err != nil || val != nil {
		t.Fatalf("missing key = %q, %v; want nil, nil", val, err)
	}
	if err := store.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	val, err := store.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(val, []byte("v")) {
		t.Fatalf("Get() = %q, want v", val)
	}
	if raw.lastCtx != ctx {
		t.Fatalf("adapter should call context-aware methods")
	}
	if err := store.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	val, err = store.Get(ctx, "k")
	if err != nil || val != nil {
		t.Fatalf("deleted key = %q, %v; want nil, nil", val, err)
	}
	if err := store.Set(ctx, "x", []byte("y"), 0); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := store.Clear(ctx); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if raw.resetHits != 1 {
		t.Fatalf("ResetWithContext calls = %d, want 1", raw.resetHits)
	}
	if val, _ := store.Get(ctx, "x"); val != nil {
		t.Fatalf("Clear() should remove keys, got %q", val)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !raw.closed {
		t.Fatalf("Close() should close backend")
	}
}

func TestConnReturnsUnderlyingConnection(t *testing.T) {
	raw := newFakeFiberStorage()
	store := New(raw)

	conn := Conn[*fakeConn](store)
	if conn != raw.conn {
		t.Fatalf("Conn() = %#v, want %#v", conn, raw.conn)
	}
}

func TestNewWithConnProvidesTypedConnection(t *testing.T) {
	raw := newFakeFiberStorage()
	store := NewWithConn[*fakeConn](raw)

	var _ storage.Store = store
	var _ storage.ConnProvider[*fakeConn] = store

	if conn := store.Conn(); conn != raw.conn {
		t.Fatalf("StoreWithConn.Conn() = %#v, want %#v", conn, raw.conn)
	}
	if err := store.Set(context.Background(), "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	val, err := store.Get(context.Background(), "k")
	if err != nil || !bytes.Equal(val, []byte("v")) {
		t.Fatalf("Get() = %q, %v; want v, nil", val, err)
	}
}

func TestConnReturnsZeroWhenUnsupported(t *testing.T) {
	store := New(&fakeFiberStorageNoConn{data: make(map[string][]byte)})

	if conn := Conn[*fakeConn](store); conn != nil {
		t.Fatalf("Conn() = %#v, want nil", conn)
	}
}

type fakeFiberStorageNoConn struct {
	data map[string][]byte
}

func (f *fakeFiberStorageNoConn) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	_ = ctx
	val, ok := f.data[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), val...), nil
}

func (f *fakeFiberStorageNoConn) Get(key string) ([]byte, error) {
	return f.GetWithContext(context.Background(), key)
}

func (f *fakeFiberStorageNoConn) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	_, _ = ctx, exp
	f.data[key] = append([]byte(nil), val...)
	return nil
}

func (f *fakeFiberStorageNoConn) Set(key string, val []byte, exp time.Duration) error {
	return f.SetWithContext(context.Background(), key, val, exp)
}

func (f *fakeFiberStorageNoConn) DeleteWithContext(ctx context.Context, key string) error {
	_ = ctx
	delete(f.data, key)
	return nil
}

func (f *fakeFiberStorageNoConn) Delete(key string) error {
	return f.DeleteWithContext(context.Background(), key)
}

func (f *fakeFiberStorageNoConn) ResetWithContext(ctx context.Context) error {
	_ = ctx
	f.data = make(map[string][]byte)
	return nil
}

func (f *fakeFiberStorageNoConn) Reset() error {
	return f.ResetWithContext(context.Background())
}

func (f *fakeFiberStorageNoConn) Close() error {
	return nil
}
