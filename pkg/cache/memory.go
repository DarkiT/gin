package cache

import (
	"context"
	"sync"
	"time"
)

type cacheItem struct {
	value      []byte
	expiration time.Time
	createdAt  time.Time
}

type memoryCache struct {
	mu              sync.RWMutex
	items           map[string]*cacheItem
	maxSize         int
	defaultTTL      time.Duration
	cleanupInterval time.Duration
	cleanupTimer    *time.Ticker
	stopCleanup     chan struct{}
	stopOnce        sync.Once
}

type MemoryOption func(*memoryCache)

func WithMaxSize(size int) MemoryOption {
	return func(c *memoryCache) { c.maxSize = size }
}

func WithDefaultTTL(ttl time.Duration) MemoryOption {
	return func(c *memoryCache) { c.defaultTTL = ttl }
}

func WithCleanupInterval(d time.Duration) MemoryOption {
	return func(c *memoryCache) { c.cleanupInterval = d }
}

func NewMemoryCache(opts ...MemoryOption) Cache {
	c := &memoryCache{
		items:           make(map[string]*cacheItem),
		maxSize:         1000,
		defaultTTL:      5 * time.Minute,
		cleanupInterval: time.Minute,
		stopCleanup:     make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.cleanupInterval > 0 {
		c.cleanupTimer = time.NewTicker(c.cleanupInterval)
		go c.cleanupLoop()
	}
	return c
}

func (c *memoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	_ = ctx
	c.mu.RLock()
	item, ok := c.items[key]
	if !ok {
		c.mu.RUnlock()
		return nil, ErrNotFound
	}
	if c.isExpiredLocked(item) {
		c.mu.RUnlock()
		c.mu.Lock()
		c.deleteIfExpiredLocked(key)
		c.mu.Unlock()
		return nil, ErrExpired
	}
	value := make([]byte, len(item.value))
	copy(value, item.value)
	c.mu.RUnlock()
	return value, nil
}

func (c *memoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	exp := time.Time{}
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	if existing, ok := c.items[key]; ok {
		existing.value = cloneBytes(value)
		existing.expiration = exp
		existing.createdAt = time.Now()
		return nil
	}
	if c.maxSize > 0 && len(c.items) >= c.maxSize {
		c.evictOldestLocked()
	}
	c.items[key] = &cacheItem{
		value:      cloneBytes(value),
		expiration: exp,
		createdAt:  time.Now(),
	}
	return nil
}

func (c *memoryCache) Delete(ctx context.Context, key string) error {
	_ = ctx
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
	return nil
}

func (c *memoryCache) Exists(ctx context.Context, key string) (bool, error) {
	_ = ctx
	c.mu.RLock()
	item, ok := c.items[key]
	if !ok {
		c.mu.RUnlock()
		return false, nil
	}
	if c.isExpiredLocked(item) {
		c.mu.RUnlock()
		c.mu.Lock()
		c.deleteIfExpiredLocked(key)
		c.mu.Unlock()
		return false, ErrExpired
	}
	c.mu.RUnlock()
	return true, nil
}

func (c *memoryCache) Clear(ctx context.Context) error {
	_ = ctx
	c.mu.Lock()
	c.items = make(map[string]*cacheItem)
	c.mu.Unlock()
	return nil
}

func (c *memoryCache) Close() error {
	c.stopOnce.Do(func() {
		if c.cleanupTimer != nil {
			c.cleanupTimer.Stop()
		}
		close(c.stopCleanup)
	})
	return nil
}

func (c *memoryCache) cleanupLoop() {
	for {
		select {
		case <-c.cleanupTimer.C:
			c.cleanupExpired()
		case <-c.stopCleanup:
			return
		}
	}
}

func (c *memoryCache) cleanupExpired() {
	c.mu.Lock()
	for key, item := range c.items {
		if c.isExpiredLocked(item) {
			delete(c.items, key)
		}
	}
	c.mu.Unlock()
}

func (c *memoryCache) isExpiredLocked(item *cacheItem) bool {
	if item.expiration.IsZero() {
		return false
	}
	return time.Now().After(item.expiration)
}

func (c *memoryCache) deleteIfExpiredLocked(key string) {
	item, ok := c.items[key]
	if !ok {
		return
	}
	if c.isExpiredLocked(item) {
		delete(c.items, key)
	}
}

func (c *memoryCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, item := range c.items {
		if first || item.createdAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.createdAt
			first = false
		}
	}
	if !first {
		delete(c.items, oldestKey)
	}
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	return buf
}

// ============================================================
// BatchCache 接口实现
// ============================================================

// MGet 批量获取缓存值。
func (c *memoryCache) MGet(ctx context.Context, keys []string) (map[string][]byte, error) {
	_ = ctx
	result := make(map[string][]byte, len(keys))

	c.mu.RLock()
	for _, key := range keys {
		item, ok := c.items[key]
		if !ok {
			continue
		}
		if c.isExpiredLocked(item) {
			continue
		}
		result[key] = cloneBytes(item.value)
	}
	c.mu.RUnlock()

	return result, nil
}

// MSet 批量设置缓存值。
func (c *memoryCache) MSet(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	exp := time.Time{}
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	for key, value := range items {
		if existing, ok := c.items[key]; ok {
			existing.value = cloneBytes(value)
			existing.expiration = exp
			existing.createdAt = time.Now()
			continue
		}
		if c.maxSize > 0 && len(c.items) >= c.maxSize {
			c.evictOldestLocked()
		}
		c.items[key] = &cacheItem{
			value:      cloneBytes(value),
			expiration: exp,
			createdAt:  time.Now(),
		}
	}

	return nil
}

// MDelete 批量删除缓存。
func (c *memoryCache) MDelete(ctx context.Context, keys []string) error {
	_ = ctx
	c.mu.Lock()
	for _, key := range keys {
		delete(c.items, key)
	}
	c.mu.Unlock()
	return nil
}
