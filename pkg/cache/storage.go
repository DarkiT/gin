package cache

import (
	"context"
	"time"

	"github.com/darkit/gin/pkg/storage"
	"github.com/darkit/gin/pkg/storage/fiberstore"
)

// StorageCache 使用 storage.Store 实现 Cache。
//
// 它把通用 KV 存储的 nil, nil miss 语义转换为 cache.ErrNotFound，
// 适合将 Fiber storage 兼容后端、Redis/etcd/Badger/Bbolt/S3 等 KV 后端接入 c.Cache()。
type StorageCache struct {
	store storage.Store
}

// NewStorageCache 创建基于 storage.Store 的缓存实现。
func NewStorageCache(store storage.Store) *StorageCache {
	if store == nil {
		panic("cache: storage store is nil")
	}
	return &StorageCache{store: store}
}

// NewFiberStorage 创建基于 Fiber storage 兼容后端的缓存实现。
//
// 该函数不引入具体 gofiber/storage driver 依赖；应用侧可直接传入 bbolt.New()、
// badger.New()、etcd.New()、s3.New() 等结构兼容后端。
func NewFiberStorage(backend fiberstore.FiberStorage) *StorageCache {
	return NewStorageCache(fiberstore.New(backend))
}

// Get 获取缓存值。
func (c *StorageCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, ErrNotFound
	}
	return val, nil
}

// Set 设置缓存值。
func (c *StorageCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.store.Set(ctx, key, value, ttl)
}

// Delete 删除缓存。
func (c *StorageCache) Delete(ctx context.Context, key string) error {
	return c.store.Delete(ctx, key)
}

// Exists 检查缓存是否存在。
func (c *StorageCache) Exists(ctx context.Context, key string) (bool, error) {
	if store, ok := c.store.(storage.ExistenceStore); ok {
		return store.Exists(ctx, key)
	}
	val, err := c.store.Get(ctx, key)
	if err != nil {
		return false, err
	}
	return val != nil, nil
}

// Clear 清空所有缓存。
func (c *StorageCache) Clear(ctx context.Context) error {
	return c.store.Clear(ctx)
}

// Close 关闭底层存储。
func (c *StorageCache) Close() error {
	return c.store.Close()
}

// Store 返回底层 storage.Store。
func (c *StorageCache) Store() storage.Store {
	if c == nil {
		return nil
	}
	return c.store
}

var _ Cache = (*StorageCache)(nil)
