package cache

import (
	"bytes"
	"context"
	"testing"
	"time"
)

type fakeFiberBackend struct {
	data    map[string][]byte
	lastCtx context.Context
	closed  bool
}

func newFakeFiberBackend() *fakeFiberBackend {
	return &fakeFiberBackend{data: make(map[string][]byte)}
}

func (f *fakeFiberBackend) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	f.lastCtx = ctx
	val, ok := f.data[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), val...), nil
}

func (f *fakeFiberBackend) Get(key string) ([]byte, error) {
	return f.GetWithContext(context.Background(), key)
}

func (f *fakeFiberBackend) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	_, _ = ctx, exp
	f.lastCtx = ctx
	f.data[key] = append([]byte(nil), val...)
	return nil
}

func (f *fakeFiberBackend) Set(key string, val []byte, exp time.Duration) error {
	return f.SetWithContext(context.Background(), key, val, exp)
}

func (f *fakeFiberBackend) DeleteWithContext(ctx context.Context, key string) error {
	f.lastCtx = ctx
	delete(f.data, key)
	return nil
}

func (f *fakeFiberBackend) Delete(key string) error {
	return f.DeleteWithContext(context.Background(), key)
}

func (f *fakeFiberBackend) ResetWithContext(ctx context.Context) error {
	f.lastCtx = ctx
	f.data = make(map[string][]byte)
	return nil
}

func (f *fakeFiberBackend) Reset() error {
	return f.ResetWithContext(context.Background())
}

func (f *fakeFiberBackend) Close() error {
	f.closed = true
	return nil
}

func TestNewFiberStorage(t *testing.T) {
	ctx := context.WithValue(context.Background(), "request", "test")
	backend := newFakeFiberBackend()
	c := NewFiberStorage(backend)

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
	if backend.lastCtx != ctx {
		t.Fatalf("NewFiberStorage cache should use context-aware backend methods")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !backend.closed {
		t.Fatalf("Close() should close backend")
	}
}
