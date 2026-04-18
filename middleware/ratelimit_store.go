package middleware

import (
	"sync"
	"time"
)

// RateLimitStore 限流存储接口（支持分布式实现）
type RateLimitStore interface {
	// Allow 判断是否允许请求
	Allow(key string, ratePerSecond float64, burst int) bool
	// Close 释放资源
	Close() error
}

// memoryRateLimitStore 内存存储实现
type memoryRateLimitStore struct {
	shards [rateLimitShardCount]rateLimitShard
	done   chan struct{}
	wg     sync.WaitGroup
}

type rateLimitShard struct {
	mu       sync.RWMutex
	limiters map[string]*rateLimitEntry
}

type rateLimitEntry struct {
	limiter  *rateLimiterBucket
	lastSeen time.Time
}

func newMemoryRateLimitStore() *memoryRateLimitStore {
	store := &memoryRateLimitStore{done: make(chan struct{})}
	for i := range store.shards {
		store.shards[i].limiters = make(map[string]*rateLimitEntry)
	}
	store.wg.Add(1)
	go store.cleanup()
	return store
}

func (s *memoryRateLimitStore) Allow(key string, ratePerSecond float64, burst int) bool {
	limiter := s.getLimiter(key, ratePerSecond, burst)
	return limiter.Allow()
}

func (s *memoryRateLimitStore) getLimiter(key string, ratePerSecond float64, burst int) *rateLimiterBucket {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, exists := shard.limiters[key]
	if !exists {
		limiter := newRateLimiterBucket(ratePerSecond, burst)
		shard.limiters[key] = &rateLimitEntry{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	entry.lastSeen = time.Now()
	entry.limiter.Update(ratePerSecond, burst)
	return entry.limiter
}

func (s *memoryRateLimitStore) Close() error {
	close(s.done)
	s.wg.Wait()
	return nil
}

func (s *memoryRateLimitStore) cleanup() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-3 * time.Minute)
			for i := range s.shards {
				shard := &s.shards[i]
				shard.mu.Lock()
				for key, entry := range shard.limiters {
					if entry.lastSeen.Before(cutoff) {
						delete(shard.limiters, key)
					}
				}
				shard.mu.Unlock()
			}
		}
	}
}

const rateLimitShardCount = 32

func (s *memoryRateLimitStore) getShard(key string) *rateLimitShard {
	idx := rateLimitHashKey(key) % rateLimitShardCount
	return &s.shards[idx]
}

func rateLimitHashKey(key string) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return hash
}
