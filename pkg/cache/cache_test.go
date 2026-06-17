package cache

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type testCache struct{}

func (t *testCache) Get(ctx context.Context, key string) ([]byte, error) { return nil, nil }
func (t *testCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}
func (t *testCache) Delete(ctx context.Context, key string) error { return nil }
func (t *testCache) Clear(ctx context.Context) error              { return nil }
func (t *testCache) Close() error                                 { return nil }

func TestErrorConstants(t *testing.T) {
	for _, err := range []error{ErrNotFound, ErrExpired, ErrClosed, ErrInvalidKey} {
		if !errors.Is(err, err) {
			t.Fatalf("%v not comparable with itself", err)
		}
	}
}

func TestCacheInterfaceSignature(t *testing.T) {
	var _ Cache = (*testCache)(nil)

	iface := reflect.TypeFor[Cache]()
	impl := reflect.TypeFor[*testCache]()
	if !impl.Implements(iface) {
		t.Fatalf("testCache should implement Cache")
	}
}
