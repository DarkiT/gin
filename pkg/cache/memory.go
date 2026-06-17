package cache

import (
	"container/list"
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

type memoryEntry struct {
	key       string
	value     []byte
	expiresAt time.Time
	element   *list.Element
}

type loadCall struct {
	wg    sync.WaitGroup
	value []byte
	err   error
}

// Memory 是并发安全的本地内存缓存。
//
// 它使用 LRU 淘汰策略，支持 TTL、批量操作、统计信息与后台过期清理。
type Memory struct {
	mu              sync.RWMutex
	items           map[string]*memoryEntry
	lru             *list.List
	maxEntries      int
	cleanupInterval time.Duration
	cloneValues     bool
	cleanupTicker   *time.Ticker
	stopCleanup     chan struct{}
	stopOnce        sync.Once
	closed          bool
	stats           Stats
	loads           map[string]*loadCall
}

// MemoryOption 配置 Memory 缓存。
type MemoryOption func(*Memory)

// WithMaxEntries 设置最大缓存项数量，<= 0 表示不限制。
func WithMaxEntries(size int) MemoryOption {
	return func(c *Memory) { c.maxEntries = size }
}

// WithCleanupInterval 设置后台过期清理周期，<= 0 表示关闭后台清理。
func WithCleanupInterval(d time.Duration) MemoryOption {
	return func(c *Memory) { c.cleanupInterval = d }
}

// WithCloneValues 设置读写时是否复制 []byte，默认开启以避免调用方修改缓存内部状态。
func WithCloneValues(enabled bool) MemoryOption {
	return func(c *Memory) { c.cloneValues = enabled }
}

// NewMemory 创建本地内存缓存。
func NewMemory(opts ...MemoryOption) *Memory {
	c := &Memory{
		items:           make(map[string]*memoryEntry),
		lru:             list.New(),
		maxEntries:      1000,
		cleanupInterval: time.Minute,
		cloneValues:     true,
		stopCleanup:     make(chan struct{}),
		loads:           make(map[string]*loadCall),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.cleanupInterval > 0 {
		c.cleanupTicker = time.NewTicker(c.cleanupInterval)
		go c.cleanupLoop()
	}
	return c
}

// Get 获取缓存值。
func (c *Memory) Get(ctx context.Context, key string) ([]byte, error) {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrClosed
	}
	entry, ok := c.items[key]
	if !ok {
		c.stats.Misses++
		return nil, ErrNotFound
	}
	if c.isExpired(entry) {
		c.removeEntry(entry)
		c.stats.Misses++
		c.stats.Expirations++
		return nil, ErrExpired
	}
	c.lru.MoveToFront(entry.element)
	c.stats.Hits++
	return c.clone(entry.value), nil
}

// Set 设置缓存值，ttl <= 0 表示不过期。
func (c *Memory) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_ = ctx
	if key == "" {
		return ErrInvalidKey
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}
	expiresAt := time.Time{}
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}
	val := c.clone(value)
	if entry, ok := c.items[key]; ok {
		c.stats.Size += int64(len(val) - len(entry.value))
		entry.value = val
		entry.expiresAt = expiresAt
		c.lru.MoveToFront(entry.element)
		c.stats.Sets++
		return nil
	}

	entry := &memoryEntry{key: key, value: val, expiresAt: expiresAt}
	entry.element = c.lru.PushFront(entry)
	c.items[key] = entry
	c.stats.Keys = int64(len(c.items))
	c.stats.Size += int64(len(val))
	c.stats.Sets++
	c.evictIfNeeded()
	return nil
}

// Delete 删除缓存；key 不存在时返回 nil。
func (c *Memory) Delete(ctx context.Context, key string) error {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}
	if entry, ok := c.items[key]; ok {
		c.removeEntry(entry)
	}
	c.stats.Deletes++
	return nil
}

// Exists 检查缓存是否存在。
func (c *Memory) Exists(ctx context.Context, key string) (bool, error) {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false, ErrClosed
	}
	entry, ok := c.items[key]
	if !ok {
		return false, nil
	}
	if c.isExpired(entry) {
		c.removeEntry(entry)
		c.stats.Expirations++
		return false, nil
	}
	return true, nil
}

// Clear 清空所有缓存。
func (c *Memory) Clear(ctx context.Context) error {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}
	c.items = make(map[string]*memoryEntry)
	c.lru.Init()
	c.stats.Keys = 0
	c.stats.Size = 0
	return nil
}

// Close 关闭缓存后台资源。
func (c *Memory) Close() error {
	c.stopOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.cleanupTicker != nil {
			c.cleanupTicker.Stop()
		}
		close(c.stopCleanup)
		c.mu.Unlock()
	})
	return nil
}

// Len 返回当前缓存项数量。
func (c *Memory) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// MGet 批量获取缓存值。
func (c *Memory) MGet(ctx context.Context, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte, len(keys))
	for _, key := range keys {
		val, err := c.Get(ctx, key)
		if err == nil {
			result[key] = val
			continue
		}
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
			continue
		}
		return nil, err
	}
	return result, nil
}

// MSet 批量设置缓存值。
func (c *Memory) MSet(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	for key, value := range items {
		if err := c.Set(ctx, key, value, ttl); err != nil {
			return err
		}
	}
	return nil
}

// MDelete 批量删除缓存。
func (c *Memory) MDelete(ctx context.Context, keys []string) error {
	for _, key := range keys {
		if err := c.Delete(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// GetOrSet 获取缓存值，不存在时调用 fn 生成并设置。
func (c *Memory) GetOrSet(ctx context.Context, key string, fn func() ([]byte, error), ttl time.Duration) ([]byte, error) {
	if val, err := c.Get(ctx, key); err == nil {
		return val, nil
	} else if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrExpired) {
		return nil, err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if entry, ok := c.items[key]; ok {
		if c.isExpired(entry) {
			c.removeEntry(entry)
			c.stats.Expirations++
		} else {
			c.lru.MoveToFront(entry.element)
			value := c.clone(entry.value)
			c.mu.Unlock()
			return value, nil
		}
	}
	if call, ok := c.loads[key]; ok {
		c.mu.Unlock()
		call.wg.Wait()
		if call.err != nil {
			return nil, call.err
		}
		return c.clone(call.value), nil
	}
	call := &loadCall{}
	call.wg.Add(1)
	c.loads[key] = call
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.loads, key)
		c.mu.Unlock()
		call.wg.Done()
	}()

	value, err := fn()
	if err != nil {
		call.err = err
		return nil, err
	}
	if err := c.Set(ctx, key, value, ttl); err != nil {
		call.err = err
		return nil, err
	}
	call.value = c.clone(value)
	return c.clone(value), nil
}

// Increment 原子递增整数值。
func (c *Memory) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	return c.add(ctx, key, delta)
}

// Decrement 原子递减整数值。
func (c *Memory) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return c.add(ctx, key, -delta)
}

// Stats 返回缓存统计信息。
func (c *Memory) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stats := c.stats
	stats.Keys = int64(len(c.items))
	if total := stats.Hits + stats.Misses; total > 0 {
		stats.HitRate = float64(stats.Hits) / float64(total)
	}
	return stats
}

// ResetStats 重置缓存统计信息。
func (c *Memory) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := int64(len(c.items))
	size := c.stats.Size
	c.stats = Stats{Keys: keys, Size: size}
}

func (c *Memory) add(ctx context.Context, key string, delta int64) (int64, error) {
	_ = ctx
	if key == "" {
		return 0, ErrInvalidKey
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, ErrClosed
	}
	current := int64(0)
	expiresAt := time.Time{}
	if entry, ok := c.items[key]; ok {
		if c.isExpired(entry) {
			c.removeEntry(entry)
			c.stats.Expirations++
		} else {
			var err error
			current, err = strconv.ParseInt(string(entry.value), 10, 64)
			if err != nil {
				return 0, err
			}
			expiresAt = entry.expiresAt
		}
	}

	next := current + delta
	val := []byte(strconv.FormatInt(next, 10))
	if entry, ok := c.items[key]; ok {
		c.stats.Size += int64(len(val) - len(entry.value))
		entry.value = c.clone(val)
		entry.expiresAt = expiresAt
		c.lru.MoveToFront(entry.element)
		c.stats.Sets++
		return next, nil
	}

	entry := &memoryEntry{key: key, value: c.clone(val), expiresAt: expiresAt}
	entry.element = c.lru.PushFront(entry)
	c.items[key] = entry
	c.stats.Keys = int64(len(c.items))
	c.stats.Size += int64(len(entry.value))
	c.stats.Sets++
	c.evictIfNeeded()
	return next, nil
}

func (c *Memory) cleanupLoop() {
	for {
		select {
		case <-c.cleanupTicker.C:
			c.cleanupExpired()
		case <-c.stopCleanup:
			return
		}
	}
}

func (c *Memory) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range append([]*memoryEntry(nil), c.itemsSlice()...) {
		if c.isExpired(entry) {
			c.removeEntry(entry)
			c.stats.Expirations++
		}
	}
}

func (c *Memory) itemsSlice() []*memoryEntry {
	entries := make([]*memoryEntry, 0, len(c.items))
	for _, entry := range c.items {
		entries = append(entries, entry)
	}
	return entries
}

func (c *Memory) evictIfNeeded() {
	if c.maxEntries <= 0 {
		return
	}
	for len(c.items) > c.maxEntries {
		oldest := c.lru.Back()
		if oldest == nil {
			return
		}
		entry := oldest.Value.(*memoryEntry)
		c.removeEntry(entry)
		c.stats.Evictions++
	}
}

func (c *Memory) removeEntry(entry *memoryEntry) {
	delete(c.items, entry.key)
	if entry.element != nil {
		c.lru.Remove(entry.element)
	}
	c.stats.Keys = int64(len(c.items))
	c.stats.Size -= int64(len(entry.value))
	if c.stats.Size < 0 {
		c.stats.Size = 0
	}
}

func (c *Memory) isExpired(entry *memoryEntry) bool {
	return !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt)
}

func (c *Memory) clone(value []byte) []byte {
	if value == nil || !c.cloneValues {
		return value
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	return buf
}

var (
	_ Cache          = (*Memory)(nil)
	_ ExistenceCache = (*Memory)(nil)
	_ BatchCache     = (*Memory)(nil)
	_ AtomicCache    = (*Memory)(nil)
	_ StatsCache     = (*Memory)(nil)
)
