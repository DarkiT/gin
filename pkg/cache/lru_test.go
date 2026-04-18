package cache

import (
	"context"
	"testing"
	"time"
)

// TestNewLRU 测试创建 LRU 缓存
func TestNewLRU(t *testing.T) {
	cache := NewLRU(10)
	if cache == nil {
		t.Fatal("NewLRU returned nil")
	}
	if cache.Len() != 0 {
		t.Errorf("expected length 0, got %d", cache.Len())
	}
}

// TestLRUCache_SetAndGet 测试设置和获取
func TestLRUCache_SetAndGet(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	// 设置值
	err := cache.Set(ctx, "key1", []byte("value1"), 0)
	if err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// 获取值
	value, err := cache.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if string(value) != "value1" {
		t.Errorf("expected value1, got %s", string(value))
	}
}

// TestLRUCache_GetNotFound 测试获取不存在的键
func TestLRUCache_GetNotFound(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	_, err := cache.Get(ctx, "missing")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestLRUCache_UpdateExisting 测试更新已存在的键
func TestLRUCache_UpdateExisting(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	if err := cache.Set(ctx, "key1", []byte("value1"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key1", []byte("value2"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	value, err := cache.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if string(value) != "value2" {
		t.Errorf("expected value2, got %s", string(value))
	}

	if cache.Len() != 1 {
		t.Errorf("expected length 1, got %d", cache.Len())
	}
}

// TestLRUCache_Eviction 测试容量淘汰
func TestLRUCache_Eviction(t *testing.T) {
	cache := NewLRU(3)
	ctx := context.Background()

	// 添加 4 个项
	if err := cache.Set(ctx, "key1", []byte("value1"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key2", []byte("value2"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key3", []byte("value3"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key4", []byte("value4"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// key1 应该被淘汰
	_, err := cache.Get(ctx, "key1")
	if err != ErrNotFound {
		t.Errorf("expected key1 to be evicted")
	}

	// 其他键应该存在
	if _, err := cache.Get(ctx, "key2"); err != nil {
		t.Errorf("key2 should exist")
	}
	if _, err := cache.Get(ctx, "key3"); err != nil {
		t.Errorf("key3 should exist")
	}
	if _, err := cache.Get(ctx, "key4"); err != nil {
		t.Errorf("key4 should exist")
	}
}

// TestLRUCache_LRUOrder 测试 LRU 顺序
func TestLRUCache_LRUOrder(t *testing.T) {
	cache := NewLRU(3)
	ctx := context.Background()

	if err := cache.Set(ctx, "key1", []byte("value1"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key2", []byte("value2"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key3", []byte("value3"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// 访问 key1，使其成为最近使用
	if _, err := cache.Get(ctx, "key1"); err != nil {
		t.Fatalf("Get error: %v", err)
	}

	// 添加新项，key2 应该被淘汰
	if err := cache.Set(ctx, "key4", []byte("value4"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	_, err := cache.Get(ctx, "key2")
	if err != ErrNotFound {
		t.Errorf("expected key2 to be evicted")
	}

	// key1 应该还在
	if _, err := cache.Get(ctx, "key1"); err != nil {
		t.Errorf("key1 should still exist")
	}
}

// TestLRUCache_TTLExpiry 测试 TTL 过期
func TestLRUCache_TTLExpiry(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	// 设置 50ms 过期
	if err := cache.Set(ctx, "key1", []byte("value1"), 50*time.Millisecond); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// 立即获取应该成功
	_, err := cache.Get(ctx, "key1")
	if err != nil {
		t.Errorf("Get should succeed before expiry")
	}

	// 等待过期
	time.Sleep(100 * time.Millisecond)

	// 应该已过期
	_, err = cache.Get(ctx, "key1")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after expiry")
	}
}

// TestLRUCache_Delete 测试删除
func TestLRUCache_Delete(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	if err := cache.Set(ctx, "key1", []byte("value1"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	err := cache.Delete(ctx, "key1")
	if err != nil {
		t.Fatalf("Delete error: %v", err)
	}

	_, err = cache.Get(ctx, "key1")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete")
	}

	if cache.Len() != 0 {
		t.Errorf("expected length 0, got %d", cache.Len())
	}
}

// TestLRUCache_DeleteNotFound 测试删除不存在的键
func TestLRUCache_DeleteNotFound(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	err := cache.Delete(ctx, "missing")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestLRUCache_Clear 测试清空
func TestLRUCache_Clear(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	if err := cache.Set(ctx, "key1", []byte("value1"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key2", []byte("value2"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := cache.Set(ctx, "key3", []byte("value3"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("expected length 0 after clear, got %d", cache.Len())
	}

	_, err := cache.Get(ctx, "key1")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after clear")
	}
}

// TestLRUCache_Concurrent 测试并发访问
func TestLRUCache_Concurrent(t *testing.T) {
	cache := NewLRU(100)
	ctx := context.Background()

	const goroutines = 50
	const iterations = 100

	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			for j := 0; j < iterations; j++ {
				key := string(rune('a' + (id % 26)))
				value := []byte("value")

				if err := cache.Set(ctx, key, value, 0); err != nil {
					t.Errorf("Set error: %v", err)
				}
				if _, err := cache.Get(ctx, key); err != nil && err != ErrNotFound {
					t.Errorf("Get error: %v", err)
				}
				if j%2 == 0 {
					if err := cache.Delete(ctx, key); err != nil && err != ErrNotFound {
						t.Errorf("Delete error: %v", err)
					}
				}
			}
			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	// 验证缓存仍然正常工作
	if err := cache.Set(ctx, "final", []byte("test"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	value, err := cache.Get(ctx, "final")
	if err != nil {
		t.Errorf("cache should work after concurrent access: %v", err)
	}
	if string(value) != "test" {
		t.Errorf("expected test, got %s", string(value))
	}
}

// TestLRUCache_ZeroTTL 测试零 TTL（永不过期）
func TestLRUCache_ZeroTTL(t *testing.T) {
	cache := NewLRU(10)
	ctx := context.Background()

	if err := cache.Set(ctx, "key1", []byte("value1"), 0); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	value, err := cache.Get(ctx, "key1")
	if err != nil {
		t.Errorf("Get should succeed with zero TTL")
	}
	if string(value) != "value1" {
		t.Errorf("expected value1, got %s", string(value))
	}
}
