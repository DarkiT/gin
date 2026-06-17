package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryBasicOperations(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	if err := c.Set(ctx, "key", []byte("value"), time.Second); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got, err := c.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got) != "value" {
		t.Fatalf("Get value mismatch: %s", string(got))
	}
	ok, err := c.Exists(ctx, "key")
	if err != nil || !ok {
		t.Fatalf("Exists failed: %v ok=%v", err, ok)
	}
	if err := c.Delete(ctx, "key"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := c.Get(ctx, "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryTTLExpiration(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	if err := c.Set(ctx, "key", []byte("value"), 10*time.Millisecond); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if _, err := c.Get(ctx, "key"); err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Get(ctx, "key"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if ok, err := c.Exists(ctx, "key"); err != nil || ok {
		t.Fatalf("expected not exists after expiration, got %v ok=%v", err, ok)
	}
}

func TestMemoryMaxEntriesEviction(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0), WithMaxEntries(2))
	defer c.Close()

	_ = c.Set(ctx, "k1", []byte("v1"), time.Second)
	_ = c.Set(ctx, "k2", []byte("v2"), time.Second)
	_ = c.Set(ctx, "k3", []byte("v3"), time.Second)

	if _, err := c.Get(ctx, "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected k1 evicted, got %v", err)
	}
	if _, err := c.Get(ctx, "k2"); err != nil {
		t.Fatalf("expected k2 present, got %v", err)
	}
	if _, err := c.Get(ctx, "k3"); err != nil {
		t.Fatalf("expected k3 present, got %v", err)
	}
	if stats := c.Stats(); stats.Evictions != 1 {
		t.Fatalf("evictions = %d, want 1", stats.Evictions)
	}
}

func TestMemoryLRUOrder(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0), WithMaxEntries(3))
	defer c.Close()

	_ = c.Set(ctx, "k1", []byte("v1"), 0)
	_ = c.Set(ctx, "k2", []byte("v2"), 0)
	_ = c.Set(ctx, "k3", []byte("v3"), 0)
	_, _ = c.Get(ctx, "k1")
	_ = c.Set(ctx, "k4", []byte("v4"), 0)

	if _, err := c.Get(ctx, "k2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected k2 evicted, got %v", err)
	}
	if _, err := c.Get(ctx, "k1"); err != nil {
		t.Fatalf("expected k1 present, got %v", err)
	}
}

func TestMemoryBatchOperations(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	if err := c.MSet(ctx, map[string][]byte{"a": []byte("1"), "b": []byte("2")}, 0); err != nil {
		t.Fatalf("MSet failed: %v", err)
	}
	values, err := c.MGet(ctx, []string{"a", "b", "missing"})
	if err != nil {
		t.Fatalf("MGet failed: %v", err)
	}
	if string(values["a"]) != "1" || string(values["b"]) != "2" {
		t.Fatalf("unexpected MGet values: %#v", values)
	}
	if _, ok := values["missing"]; ok {
		t.Fatalf("missing key should not be returned")
	}
	if err := c.MDelete(ctx, []string{"a", "b"}); err != nil {
		t.Fatalf("MDelete failed: %v", err)
	}
	if c.Len() != 0 {
		t.Fatalf("len = %d, want 0", c.Len())
	}
}

func TestMemoryAtomicOperations(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	val, err := c.GetOrSet(ctx, "k", func() ([]byte, error) { return []byte("v"), nil }, 0)
	if err != nil || string(val) != "v" {
		t.Fatalf("GetOrSet = %q, %v", val, err)
	}
	val, err = c.GetOrSet(ctx, "k", func() ([]byte, error) { return []byte("other"), nil }, 0)
	if err != nil || string(val) != "v" {
		t.Fatalf("GetOrSet existing = %q, %v", val, err)
	}
	got, err := c.Increment(ctx, "n", 2)
	if err != nil || got != 2 {
		t.Fatalf("Increment = %d, %v", got, err)
	}
	got, err = c.Decrement(ctx, "n", 1)
	if err != nil || got != 1 {
		t.Fatalf("Decrement = %d, %v", got, err)
	}
}

func TestMemoryGetOrSetCoalescesConcurrentLoads(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	var calls atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan string, 8)

	for range 8 {
		wg.Go(func() {
			<-start
			val, err := c.GetOrSet(ctx, "k", func() ([]byte, error) {
				calls.Add(1)
				time.Sleep(20 * time.Millisecond)
				return []byte("v"), nil
			}, 0)
			if err != nil {
				t.Errorf("GetOrSet failed: %v", err)
				return
			}
			results <- string(val)
		})
	}
	close(start)
	wg.Wait()
	close(results)

	if calls.Load() != 1 {
		t.Fatalf("loader calls = %d, want 1", calls.Load())
	}
	for got := range results {
		if got != "v" {
			t.Fatalf("result = %q, want v", got)
		}
	}
}

func TestMemoryStatsAndReset(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	_ = c.Set(ctx, "k", []byte("v"), 0)
	_, _ = c.Get(ctx, "k")
	_, _ = c.Get(ctx, "missing")
	stats := c.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Sets != 1 || stats.Keys != 1 || stats.HitRate != 0.5 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	c.ResetStats()
	stats = c.Stats()
	if stats.Hits != 0 || stats.Misses != 0 || stats.Keys != 1 {
		t.Fatalf("unexpected reset stats: %#v", stats)
	}
}

func TestMemoryCloneValues(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	value := []byte("abc")
	_ = c.Set(ctx, "k", value, 0)
	value[0] = 'x'
	got, _ := c.Get(ctx, "k")
	got[1] = 'y'
	again, _ := c.Get(ctx, "k")
	if string(again) != "abc" {
		t.Fatalf("cache should clone values, got %q", again)
	}
}

func TestMemoryConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0), WithMaxEntries(1000))
	defer c.Close()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			key := fmt.Sprintf("k-%d", i)
			if err := c.Set(ctx, key, []byte("v"), time.Second); err != nil {
				t.Errorf("Set failed: %v", err)
				return
			}
			if _, err := c.Get(ctx, key); err != nil {
				t.Errorf("Get failed: %v", err)
			}
		})
	}
	wg.Wait()
}

func TestMemoryCloseStopsCleanup(t *testing.T) {
	c := NewMemory(WithCleanupInterval(10 * time.Millisecond))
	if c.cleanupTicker == nil {
		t.Fatalf("expected cleanup timer")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	select {
	case <-c.stopCleanup:
	default:
		t.Fatalf("stopCleanup should be closed")
	}
	if err := c.Set(context.Background(), "k", []byte("v"), 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Set after Close = %v, want ErrClosed", err)
	}
}

func TestMemoryInvalidKey(t *testing.T) {
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	if err := c.Set(context.Background(), "", []byte("v"), 0); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Set empty key = %v, want ErrInvalidKey", err)
	}
}

func TestMemoryGetOrSetCleansLoadStateAfterPanic(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithCleanupInterval(0))
	defer c.Close()

	func() {
		defer func() {
			if recover() == nil {
				t.Fatalf("expected loader panic")
			}
		}()
		_, _ = c.GetOrSet(ctx, "panic-key", func() ([]byte, error) {
			panic("boom")
		}, 0)
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		val, err := c.GetOrSet(ctx, "panic-key", func() ([]byte, error) {
			return []byte("recovered"), nil
		}, 0)
		if err != nil {
			t.Errorf("GetOrSet after panic failed: %v", err)
			return
		}
		if string(val) != "recovered" {
			t.Errorf("GetOrSet after panic = %q, want recovered", val)
		}
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("GetOrSet blocked after panic loader")
	}
}
