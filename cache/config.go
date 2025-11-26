package cache

import "time"

// Config 缓存配置
type Config struct {
	// TTL 默认过期时间
	TTL time.Duration
	// CleanupInterval 清理过期项的间隔
	CleanupInterval time.Duration
	// ShardCount 分片数量（可选）
	ShardCount int
	// PersistPath 持久化文件路径（可选）
	PersistPath string
	// AutoPersistInterval 自动持久化间隔（可选）
	AutoPersistInterval time.Duration
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		TTL:             time.Hour,
		CleanupInterval: 10 * time.Minute,
		ShardCount:      0, // 使用默认值
	}
}

// New 使用配置创建缓存实例
func New[K comparable, V any](config Config) *Cache[K, V] {
	var cache *Cache[K, V]

	if config.ShardCount > 0 {
		cache = NewCache[K, V](config.TTL, config.CleanupInterval, config.ShardCount)
	} else {
		cache = NewCache[K, V](config.TTL, config.CleanupInterval)
	}

	// 如果配置了持久化
	if config.PersistPath != "" {
		if config.AutoPersistInterval > 0 {
			cache = cache.WithPersistence(config.PersistPath, config.AutoPersistInterval)
		} else {
			cache = cache.WithPersistence(config.PersistPath, time.Hour)
		}
	}

	return cache
}
