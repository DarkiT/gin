package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 简单缓存实现，模拟优化前的实现
type SimpleCache struct {
	items map[string]interface{}
	mu    sync.RWMutex
}

func NewSimpleCache() *SimpleCache {
	return &SimpleCache{
		items: make(map[string]interface{}),
	}
}

func (c *SimpleCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = value
}

func (c *SimpleCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.items[key]
	return v, ok
}

func (c *SimpleCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// 测试并发读取性能
func BenchmarkConcurrentRead(b *testing.B) {
	// 测试普通缓存
	b.Run("SimpleCache", func(b *testing.B) {
		cache := NewSimpleCache()
		// 预填充数据
		for i := 0; i < 10000; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key%d", i%10000)
				_, _ = cache.Get(key)
				i++
			}
		})
	})

	// 测试分片缓存
	b.Run("ShardedCache", func(b *testing.B) {
		cache := NewCache[string, int](5*time.Minute, 1*time.Minute, 16)
		// 预填充数据
		for i := 0; i < 10000; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key%d", i%10000)
				_, _ = cache.Get(key)
				i++
			}
		})
	})
}

// 测试并发写入性能
func BenchmarkConcurrentWrite(b *testing.B) {
	// 测试普通缓存
	b.Run("SimpleCache", func(b *testing.B) {
		cache := NewSimpleCache()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key%d", i)
				cache.Set(key, i)
				i++
			}
		})
	})

	// 测试分片缓存
	b.Run("ShardedCache", func(b *testing.B) {
		cache := NewCache[string, int](5*time.Minute, 1*time.Minute, 16)

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key%d", i)
				cache.Set(key, i)
				i++
			}
		})
	})
}

// 测试混合读写性能
func BenchmarkMixedOperations(b *testing.B) {
	// 测试普通缓存
	b.Run("SimpleCache", func(b *testing.B) {
		cache := NewSimpleCache()
		// 预填充部分数据
		for i := 0; i < 5000; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key%d", i%10000)
				if i%5 == 0 {
					cache.Set(key, i) // 20% 写操作
				} else {
					_, _ = cache.Get(key) // 80% 读操作
				}
				i++
			}
		})
	})

	// 测试分片缓存
	b.Run("ShardedCache", func(b *testing.B) {
		cache := NewCache[string, int](5*time.Minute, 1*time.Minute, 16)
		// 预填充部分数据
		for i := 0; i < 5000; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key%d", i%10000)
				if i%5 == 0 {
					cache.Set(key, i) // 20% 写操作
				} else {
					_, _ = cache.Get(key) // 80% 读操作
				}
				i++
			}
		})
	})
}
