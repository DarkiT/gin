package middleware

import (
	"sync"
	"time"
)

// IdempotentStore 幂等性存储接口
type IdempotentStore interface {
	// Get 获取缓存的响应
	// 返回：statusCode, body, exists
	Get(key string) (statusCode int, body []byte, exists bool)

	// Set 设置缓存的响应
	Set(key string, statusCode int, body []byte, ttl time.Duration) error

	// Delete 删除缓存
	Delete(key string) error

	// Close 关闭存储（释放资源）
	Close() error
}

// idempotentShardCount 分片数量，使用 2 的幂次方便位运算
const idempotentShardCount = 32

// MemoryIdempotentStore 内存存储实现（分片设计，降低锁竞争）
type MemoryIdempotentStore struct {
	shards [idempotentShardCount]idempotentShard
	done   chan struct{}
	wg     sync.WaitGroup
}

// idempotentShard 单个分片
type idempotentShard struct {
	mu    sync.RWMutex
	store map[string]*idempotentEntry
}

type idempotentEntry struct {
	statusCode int
	body       []byte
	expiry     time.Time
}

// NewMemoryIdempotentStore 创建内存存储并启动清理任务
func NewMemoryIdempotentStore() *MemoryIdempotentStore {
	store := &MemoryIdempotentStore{
		done: make(chan struct{}),
	}

	// 初始化所有分片
	for i := range store.shards {
		store.shards[i].store = make(map[string]*idempotentEntry)
	}

	// 启动清理 goroutine，每分钟清理一次过期条目
	store.wg.Add(1)
	go store.cleanupExpired()

	return store
}

// getShard 根据 key 获取对应的分片（使用 FNV-1a 哈希）
func (s *MemoryIdempotentStore) getShard(key string) *idempotentShard {
	idx := idempotentHashKey(key) % idempotentShardCount
	return &s.shards[idx]
}

// idempotentHashKey 使用 FNV-1a 哈希算法计算 key 的哈希值
func idempotentHashKey(key string) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return hash
}

// Get 获取缓存条目
func (s *MemoryIdempotentStore) Get(key string) (int, []byte, bool) {
	shard := s.getShard(key)
	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists {
		return 0, nil, false
	}

	if time.Now().After(entry.expiry) {
		return 0, nil, false
	}

	bodyCopy := append([]byte(nil), entry.body...)
	return entry.statusCode, bodyCopy, true
}

// Set 写入缓存条目
func (s *MemoryIdempotentStore) Set(key string, statusCode int, body []byte, ttl time.Duration) error {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	bodyCopy := append([]byte(nil), body...)
	shard.store[key] = &idempotentEntry{
		statusCode: statusCode,
		body:       bodyCopy,
		expiry:     time.Now().Add(ttl),
	}

	return nil
}

// Delete 删除缓存条目
func (s *MemoryIdempotentStore) Delete(key string) error {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.store, key)
	return nil
}

func (s *MemoryIdempotentStore) cleanupExpired() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			// 遍历所有分片进行清理
			for i := range s.shards {
				shard := &s.shards[i]
				shard.mu.Lock()
				for key, entry := range shard.store {
					if now.After(entry.expiry) {
						delete(shard.store, key)
					}
				}
				shard.mu.Unlock()
			}
		case <-s.done:
			return
		}
	}
}

// Close 停止清理 goroutine
func (s *MemoryIdempotentStore) Close() error {
	close(s.done)
	s.wg.Wait()
	return nil
}
