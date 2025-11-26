package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 测试缓存基本功能
func TestCacheBasicOperations(t *testing.T) {
	// 创建带16个分片的缓存
	cache := NewCache[string, string](5*time.Minute, 1*time.Minute, 16)

	// 设置值
	cache.Set("key1", "value1")
	cache.Set("key2", "value2", 10*time.Second)

	// 获取值
	val, found := cache.Get("key1")
	if !found || val != "value1" {
		t.Errorf("Expected value1, got %v, found=%v", val, found)
	}

	val, found = cache.Get("key2")
	if !found || val != "value2" {
		t.Errorf("Expected value2, got %v, found=%v", val, found)
	}

	// 不存在的键
	_, found = cache.Get("nonexistent")
	if found {
		t.Error("Unexpectedly found nonexistent key")
	}

	// 测试删除
	cache.Delete("key1")
	_, found = cache.Get("key1")
	if found {
		t.Error("Key should be deleted")
	}
}

// 测试列表操作
func TestCacheListOperations(t *testing.T) {
	cache := NewCache[string, string](5*time.Minute, 1*time.Minute)

	// 列表操作 - LPush添加顺序是反向的，后推入的在前面
	cache.LPush("list1", "item1", "item2") // 此时列表为: [item2, item1]
	cache.RPush("list1", "item3")          // 此时列表为: [item2, item1, item3]

	// 检查列表长度
	length := cache.LLen("list1")
	if length != 3 {
		t.Errorf("Expected list length 3, got %d", length)
	}

	// 弹出元素
	val, found := cache.LPop("list1")
	if !found || val != "item1" { // 现在列表是 [item1, item3]，所以LPop应该得到item1
		t.Errorf("Expected item1, got %v, found=%v", val, found)
	}

	val, found = cache.RPop("list1")
	if !found || val != "item3" { // RPush后item3在最后，所以从尾部弹出
		t.Errorf("Expected item3, got %v, found=%v", val, found)
	}

	// 验证剩余长度
	length = cache.LLen("list1")
	if length != 1 {
		t.Errorf("Expected list length 1, got %d", length)
	}
}

// 测试并发安全性
func TestCacheConcurrency(t *testing.T) {
	// 使用4个分片
	cache := NewCache[string, int](5*time.Minute, 1*time.Minute, 4)
	const workers = 100
	const iterations = 1000

	wg := sync.WaitGroup{}
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(workerID int) {
			defer wg.Done()

			// 每个worker写入自己的key区间
			for j := 0; j < iterations; j++ {
				key := fmt.Sprintf("key_%d_%d", workerID, j)
				cache.Set(key, workerID*iterations+j)

				// 随机读取其他worker的数据
				otherWorker := (workerID + 1) % workers
				otherKey := fmt.Sprintf("key_%d_%d", otherWorker, j)
				_, _ = cache.Get(otherKey)
			}
		}(i)
	}

	wg.Wait()

	// 验证数据完整性
	successCount := 0
	for i := 0; i < workers; i++ {
		for j := 0; j < iterations; j++ {
			key := fmt.Sprintf("key_%d_%d", i, j)
			val, found := cache.Get(key)
			if found && val == i*iterations+j {
				successCount++
			}
		}
	}

	// 计算成功率，应该接近100%
	successRate := float64(successCount) / float64(workers*iterations) * 100
	if successRate < 99.9 {
		t.Errorf("Expected success rate close to 100%%, got %.2f%%", successRate)
	}
}

// 性能测试：分片缓存 vs 普通缓存
func BenchmarkCacheOperations(b *testing.B) {
	// 测试不同分片数量的性能
	shardCounts := []int{1, 4, 8, 16, 32}

	for _, shardCount := range shardCounts {
		b.Run(fmt.Sprintf("Shards_%d", shardCount), func(b *testing.B) {
			cache := NewCache[string, int](5*time.Minute, 1*time.Minute, shardCount)

			// 预填充一些数据
			for i := 0; i < 1000; i++ {
				cache.Set(fmt.Sprintf("init_key_%d", i), i)
			}

			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				counter := 0
				for pb.Next() {
					// 混合读写操作
					key := fmt.Sprintf("key_%d", counter%1000)
					if counter%3 == 0 {
						// 写操作
						cache.Set(key, counter)
					} else {
						// 读操作
						_, _ = cache.Get(key)
					}
					counter++
				}
			})
		})
	}
}

// 基准测试：列表操作性能
func BenchmarkListOperations(b *testing.B) {
	cache := NewCache[string, string](5*time.Minute, 1*time.Minute, 16)

	// 预填充一些列表
	for i := 0; i < 100; i++ {
		listKey := fmt.Sprintf("list_%d", i)
		for j := 0; j < 20; j++ {
			cache.RPush(listKey, fmt.Sprintf("item_%d", j))
		}
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			listKey := fmt.Sprintf("list_%d", counter%100)

			switch counter % 5 {
			case 0:
				// 添加
				cache.RPush(listKey, fmt.Sprintf("new_item_%d", counter))
			case 1:
				// 读取
				cache.LRange(listKey, 0, 10)
			case 2:
				// 删除
				cache.LRem(listKey, 1, fmt.Sprintf("item_%d", counter%20), func(a, b string) bool {
					return a == b
				})
			case 3:
				// 弹出
				_, _ = cache.LPop(listKey)
			case 4:
				// 推入
				cache.LPush(listKey, fmt.Sprintf("new_front_item_%d", counter))
			}

			counter++
		}
	})
}
