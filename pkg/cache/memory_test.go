package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryCacheBasicOperations(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCleanupInterval(0)).(*memoryCache)
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

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
	if _, err := c.Get(ctx, "key"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryCacheTTLExpiration(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCleanupInterval(0), WithDefaultTTL(10*time.Millisecond)).(*memoryCache)
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	if err := c.Set(ctx, "key", []byte("value"), 0); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	_, err := c.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Get(ctx, "key"); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if ok, err := c.Exists(ctx, "key"); err != nil || ok {
		t.Fatalf("expected not exists after expiration, got %v ok=%v", err, ok)
	}
}

func TestMemoryCacheMaxSizeEviction(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCleanupInterval(0), WithMaxSize(2)).(*memoryCache)
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	if err := c.Set(ctx, "k1", []byte("v1"), time.Second); err != nil {
		t.Fatalf("Set k1 failed: %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := c.Set(ctx, "k2", []byte("v2"), time.Second); err != nil {
		t.Fatalf("Set k2 failed: %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := c.Set(ctx, "k3", []byte("v3"), time.Second); err != nil {
		t.Fatalf("Set k3 failed: %v", err)
	}

	if _, err := c.Get(ctx, "k1"); err != ErrNotFound {
		t.Fatalf("expected k1 evicted, got %v", err)
	}
	if _, err := c.Get(ctx, "k2"); err != nil {
		t.Fatalf("expected k2 present, got %v", err)
	}
	if _, err := c.Get(ctx, "k3"); err != nil {
		t.Fatalf("expected k3 present, got %v", err)
	}
}

func TestMemoryCacheConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCleanupInterval(0), WithMaxSize(1000)).(*memoryCache)
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("k-%d", i)
			if err := c.Set(ctx, key, []byte("v"), time.Second); err != nil {
				t.Errorf("Set failed: %v", err)
				return
			}
			if _, err := c.Get(ctx, key); err != nil {
				t.Errorf("Get failed: %v", err)
			}
		}()
	}
	for i := 0; i < 50; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("k-%d", i)
			if _, err := c.Exists(ctx, key); err != nil {
				t.Errorf("Exists failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestMemoryCacheCloseStopsCleanup(t *testing.T) {
	c := NewMemoryCache(WithCleanupInterval(10 * time.Millisecond)).(*memoryCache)
	if c.cleanupTimer == nil {
		t.Fatalf("expected cleanup timer")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	select {
	case <-c.stopCleanup:
	default:
		t.Fatalf("stopCleanup should be closed")
	}
}
