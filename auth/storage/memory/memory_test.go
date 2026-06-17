package memory

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSetKeepTTL(t *testing.T) {
	storage := NewStorage()

	// 测试场景1: 键不存在的情况
	err := storage.SetKeepTTL("non_existent_key", "value")
	if err == nil {
		t.Errorf("Expected error for non-existent key, got nil")
	}

	// 测试场景2: 键存在且未过期的情况
	key := "test_key"
	originalValue := "original_value"
	newValue := "new_value"
	ttl := 10 * time.Second

	// 先设置一个键值对
	err = storage.Set(key, originalValue, ttl)
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	// 获取原始TTL
	originalTTL, err := storage.TTL(key)
	if err != nil {
		t.Fatalf("Failed to get TTL: %v", err)
	}

	// 使用SetKeepTTL更新值
	err = storage.SetKeepTTL(key, newValue)
	if err != nil {
		t.Fatalf("SetKeepTTL failed: %v", err)
	}

	// 验证值已更新
	value, err := storage.Get(key)
	if err != nil {
		t.Fatalf("Failed to get value: %v", err)
	}
	if value != newValue {
		t.Errorf("Expected value %q, got %q", newValue, value)
	}

	// 验证TTL保持不变
	newTTL, err := storage.TTL(key)
	if err != nil {
		t.Fatalf("Failed to get TTL after update: %v", err)
	}

	// 允许有轻微误差（不超过1秒）
	ttlDiff := originalTTL - newTTL
	if ttlDiff < 0 {
		ttlDiff = -ttlDiff
	}
	if ttlDiff > time.Second {
		t.Errorf("TTL changed significantly. Original: %v, New: %v", originalTTL, newTTL)
	}

	// 注意：Memory实现中，过期检查是在访问时进行的，而不是通过后台任务
	// 因此我们无法可靠地测试已过期键的情况，这里只测试键不存在的情况
}

func TestConcurrentReadAndRenewPaths(t *testing.T) {
	storage := NewStorage()
	key := "race_key"

	if err := storage.Set(key, "initial", time.Minute); err != nil {
		t.Fatalf("Failed to seed key: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup

	reader := func(fn func()) {
		defer wg.Done()
		<-start
		for range 1000 {
			fn()
		}
	}

	wg.Add(4)
	go reader(func() {
		_, _ = storage.Get(key)
	})
	go reader(func() {
		_ = storage.Exists(key)
	})
	go reader(func() {
		_, _ = storage.TTL(key)
	})
	go func() {
		defer wg.Done()
		<-start
		for i := range 1000 {
			if err := storage.SetKeepTTL(key, fmt.Sprintf("value-%d", i)); err != nil {
				t.Errorf("SetKeepTTL failed: %v", err)
				return
			}
			if err := storage.Expire(key, time.Minute); err != nil {
				t.Errorf("Expire failed: %v", err)
				return
			}
		}
	}()

	close(start)
	wg.Wait()
}
