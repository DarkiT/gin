package cache

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type testCache struct{}

func (t *testCache) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, nil
}

func (t *testCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}

func (t *testCache) Delete(ctx context.Context, key string) error {
	return nil
}

func (t *testCache) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func (t *testCache) Clear(ctx context.Context) error {
	return nil
}

func (t *testCache) Close() error {
	return nil
}

func TestErrorConstants(t *testing.T) {
	if !errors.Is(ErrNotFound, ErrNotFound) {
		t.Fatalf("ErrNotFound not comparable with itself")
	}
	if !errors.Is(ErrExpired, ErrExpired) {
		t.Fatalf("ErrExpired not comparable with itself")
	}
}

func TestCacheInterfaceSignature(t *testing.T) {
	var _ Cache = (*testCache)(nil)

	iface := reflect.TypeOf((*Cache)(nil)).Elem()
	impl := reflect.TypeOf(&testCache{})

	if !impl.Implements(iface) {
		t.Fatalf("testCache should implement Cache")
	}
}
