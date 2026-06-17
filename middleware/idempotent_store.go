package middleware

import (
	"sync"
	"time"
)

// IdempotentStore 幂等性存储接口
type IdempotentStore interface {
	// Get 获取已完成的缓存响应（pending 占位条目视为未命中，返回 exists=false）。
	// 返回：statusCode, body, exists
	Get(key string) (statusCode int, body []byte, exists bool)

	// Set 设置完成的缓存响应（同时清除 pending 占位状态）。
	Set(key string, statusCode int, body []byte, ttl time.Duration) error

	// Reserve 原子地占位：仅当 key 不存在（或已过期）时写入一个 pending 占位条目并返回 true；
	// 已存在则返回 false。用于防止并发相同 key 的请求重复执行（重复扣款/创建）。
	Reserve(key string, ttl time.Duration) bool

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
	// pending=true 表示该 key 已被某请求占位、响应尚未写入完成；Get 视此类条目为未命中。
	pending bool
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

// Get 获取已完成的缓存条目（pending 占位视为未命中）。
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

	// pending 占位条目：响应尚未完成，视为未命中（由调用方决定等待或拒绝并发请求）。
	if entry.pending {
		return 0, nil, false
	}

	bodyCopy := append([]byte(nil), entry.body...)
	return entry.statusCode, bodyCopy, true
}

// Set 写入完成的缓存条目（清除 pending 占位）。
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

// Reserve 原子占位：key 不存在/已过期时写入 pending 占位并返回 true，已存在则返回 false。
func (s *MemoryIdempotentStore) Reserve(key string, ttl time.Duration) bool {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if entry, exists := shard.store[key]; exists && !time.Now().After(entry.expiry) {
		return false // 已有占位或已完成 → 并发请求，拒绝重复执行
	}
	shard.store[key] = &idempotentEntry{
		expiry:  time.Now().Add(ttl),
		pending: true,
	}
	return true
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
