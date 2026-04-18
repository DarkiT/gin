// Package cache 提供内存缓存实现。
package cache

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// entry 缓存项
type entry struct {
	key    string
	value  []byte
	expiry time.Time
}

// LRUCache LRU 缓存
type LRUCache struct {
	capacity int
	items    map[string]*list.Element
	lru      *list.List
	mu       sync.RWMutex
}

// NewLRU 创建 LRU 缓存
func NewLRU(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Get 获取缓存
func (c *LRUCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[key]
	if !exists {
		return nil, ErrNotFound
	}

	entry := elem.Value.(*entry)

	// 检查过期
	if !entry.expiry.IsZero() && time.Now().After(entry.expiry) {
		c.removeElement(elem)
		return nil, ErrNotFound
	}

	// 移动到最前面（最近使用）
	c.lru.MoveToFront(elem)
	return entry.value, nil
}

// Set 设置缓存
func (c *LRUCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 已存在，更新并移动到最前面
	if elem, exists := c.items[key]; exists {
		c.lru.MoveToFront(elem)
		entry := elem.Value.(*entry)
		entry.value = value
		if ttl > 0 {
			entry.expiry = time.Now().Add(ttl)
		} else {
			entry.expiry = time.Time{}
		}
		return nil
	}

	// 容量检查，超出则删除最久未使用的
	if c.lru.Len() >= c.capacity {
		oldest := c.lru.Back()
		if oldest != nil {
			c.removeElement(oldest)
		}
	}

	// 添加新项
	newEntry := &entry{
		key:   key,
		value: value,
	}
	if ttl > 0 {
		newEntry.expiry = time.Now().Add(ttl)
	}
	elem := c.lru.PushFront(newEntry)
	c.items[key] = elem
	return nil
}

// Delete 删除缓存
func (c *LRUCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[key]
	if !exists {
		return ErrNotFound
	}

	c.removeElement(elem)
	return nil
}

// Len 返回缓存项数量
func (c *LRUCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lru.Len()
}

// Clear 清空缓存
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.lru.Init()
}

// removeElement 内部方法：删除元素（调用前必须持有锁）
func (c *LRUCache) removeElement(elem *list.Element) {
	entry := elem.Value.(*entry)
	delete(c.items, entry.key)
	c.lru.Remove(elem)
}
