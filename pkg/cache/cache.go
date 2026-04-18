package cache

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("cache: key not found")
	ErrExpired  = errors.New("cache: key expired")
)

// Cache 缓存接口定义。
type Cache interface {
	// Get 获取缓存值。
	Get(ctx context.Context, key string) ([]byte, error)
	// Set 设置缓存值。
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Delete 删除缓存。
	Delete(ctx context.Context, key string) error
	// Exists 检查缓存是否存在。
	Exists(ctx context.Context, key string) (bool, error)
	// Clear 清空所有缓存。
	Clear(ctx context.Context) error
	// Close 关闭缓存连接。
	Close() error
}

// BatchCache 批量操作缓存接口（可选实现）。
type BatchCache interface {
	Cache
	// MGet 批量获取缓存值。
	// 返回 map 中仅包含存在的 key，不存在的 key 不会出现在结果中。
	MGet(ctx context.Context, keys []string) (map[string][]byte, error)
	// MSet 批量设置缓存值。
	MSet(ctx context.Context, items map[string][]byte, ttl time.Duration) error
	// MDelete 批量删除缓存。
	MDelete(ctx context.Context, keys []string) error
}

// AtomicCache 原子操作缓存接口（可选实现）。
type AtomicCache interface {
	Cache
	// GetOrSet 获取缓存值，不存在时调用 fn 生成并设置。
	// 使用 singleflight 模式防止缓存击穿。
	GetOrSet(ctx context.Context, key string, fn func() ([]byte, error), ttl time.Duration) ([]byte, error)
	// Increment 原子递增。
	Increment(ctx context.Context, key string, delta int64) (int64, error)
	// Decrement 原子递减。
	Decrement(ctx context.Context, key string, delta int64) (int64, error)
}

// CacheStats 缓存统计信息。
type CacheStats struct {
	Hits      int64   // 命中次数
	Misses    int64   // 未命中次数
	Keys      int64   // 当前 key 数量
	Size      int64   // 当前缓存大小（字节）
	Evictions int64   // 淘汰次数
	HitRate   float64 // 命中率
}

// StatsCache 带统计功能的缓存接口（可选实现）。
type StatsCache interface {
	Cache
	// Stats 返回缓存统计信息。
	Stats() CacheStats
	// ResetStats 重置统计信息。
	ResetStats()
}
