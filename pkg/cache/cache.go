package cache

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound 表示缓存中不存在指定 key。
	ErrNotFound = errors.New("cache: key not found")
	// ErrExpired 表示指定 key 已过期，并已从缓存中移除。
	ErrExpired = errors.New("cache: key expired")
	// ErrClosed 表示缓存实例已关闭。
	ErrClosed = errors.New("cache: closed")
	// ErrInvalidKey 表示缓存 key 为空或非法。
	ErrInvalidKey = errors.New("cache: invalid key")
)

// Cache 定义最小缓存接口。
//
// 约束：
//   - Get miss 时返回 ErrNotFound 或 ErrExpired。
//   - Set 的 ttl <= 0 表示不过期。
//   - Close 必须可重复调用。
type Cache interface {
	// Get 获取缓存值。
	Get(ctx context.Context, key string) ([]byte, error)
	// Set 设置缓存值，ttl <= 0 表示不过期。
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Delete 删除缓存；key 不存在时应返回 nil。
	Delete(ctx context.Context, key string) error
	// Clear 清空所有缓存。
	Clear(ctx context.Context) error
	// Close 关闭缓存连接或后台资源。
	Close() error
}

// ExistenceCache 表示支持存在性检查的缓存。
type ExistenceCache interface {
	Cache
	// Exists 检查缓存是否存在。
	Exists(ctx context.Context, key string) (bool, error)
}

// BatchCache 表示支持批量操作的缓存。
type BatchCache interface {
	Cache
	// MGet 批量获取缓存值；返回结果只包含存在且未过期的 key。
	MGet(ctx context.Context, keys []string) (map[string][]byte, error)
	// MSet 批量设置缓存值。
	MSet(ctx context.Context, items map[string][]byte, ttl time.Duration) error
	// MDelete 批量删除缓存。
	MDelete(ctx context.Context, keys []string) error
}

// AtomicCache 表示支持原子操作的缓存。
type AtomicCache interface {
	Cache
	// GetOrSet 获取缓存值，不存在时调用 fn 生成并设置。
	GetOrSet(ctx context.Context, key string, fn func() ([]byte, error), ttl time.Duration) ([]byte, error)
	// Increment 原子递增。
	Increment(ctx context.Context, key string, delta int64) (int64, error)
	// Decrement 原子递减。
	Decrement(ctx context.Context, key string, delta int64) (int64, error)
}

// Stats 描述缓存运行统计。
type Stats struct {
	Hits        int64   // 命中次数
	Misses      int64   // 未命中次数
	Sets        int64   // 写入次数
	Deletes     int64   // 删除次数
	Evictions   int64   // 容量淘汰次数
	Expirations int64   // 过期清理次数
	Keys        int64   // 当前 key 数量
	Size        int64   // 当前缓存值总字节数
	HitRate     float64 // 命中率
}

// StatsCache 表示支持统计信息的缓存。
type StatsCache interface {
	Cache
	// Stats 返回缓存统计信息。
	Stats() Stats
	// ResetStats 重置缓存统计信息。
	ResetStats()
}
