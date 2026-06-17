// Package fiberstore 提供 github.com/gofiber/storage 兼容后端到 pkg/storage.Store 的适配器。
package fiberstore

import (
	"context"
	"time"

	"github.com/darkit/gin/pkg/storage"
)

// FiberStorage 定义与 github.com/gofiber/storage.Storage 结构兼容的最小接口。
//
// 本包刻意不直接 import gofiber/storage，避免 darkit/gin 主模块强绑定具体存储生态；
// 只要后端实现相同方法集，即可被 New 包装。
type FiberStorage interface {
	// GetWithContext 使用 context 获取指定 key。
	GetWithContext(ctx context.Context, key string) ([]byte, error)
	// Get 获取指定 key。
	Get(key string) ([]byte, error)
	// SetWithContext 使用 context 写入指定 key，exp <= 0 表示不过期。
	SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error
	// Set 写入指定 key，exp <= 0 表示不过期。
	Set(key string, val []byte, exp time.Duration) error
	// DeleteWithContext 使用 context 删除指定 key。
	DeleteWithContext(ctx context.Context, key string) error
	// Delete 删除指定 key。
	Delete(key string) error
	// ResetWithContext 使用 context 清空存储。
	ResetWithContext(ctx context.Context) error
	// Reset 清空存储。
	Reset() error
	// Close 关闭存储连接或后台资源。
	Close() error
}

// Store 将 FiberStorage 适配为 storage.Store。
type Store struct {
	backend FiberStorage
}

// New 创建 Fiber storage 兼容后端适配器。
func New(backend FiberStorage) *Store {
	if backend == nil {
		panic("fiberstore: backend is nil")
	}
	return &Store{backend: backend}
}

// Get 获取指定 key 的值。
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	return s.backend.GetWithContext(ctx, key)
}

// Set 写入指定 key 的值。
func (s *Store) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return s.backend.SetWithContext(ctx, key, val, ttl)
}

// Delete 删除指定 key。
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.backend.DeleteWithContext(ctx, key)
}

// Clear 清空存储。
func (s *Store) Clear(ctx context.Context) error {
	return s.backend.ResetWithContext(ctx)
}

// Close 关闭底层存储。
func (s *Store) Close() error {
	return s.backend.Close()
}

var _ storage.Store = (*Store)(nil)
