package fiberstore

import "github.com/darkit/gin/pkg/storage"

// FiberStorageWithConn 定义与 github.com/gofiber/storage.StorageWithConn[T] 结构兼容的连接暴露接口。
type FiberStorageWithConn[T any] interface {
	// Conn 返回底层连接对象。
	Conn() T
}

// FiberStorageConn 定义同时满足 FiberStorage 与 FiberStorageWithConn[T] 的后端。
type FiberStorageConn[T any] interface {
	FiberStorage
	FiberStorageWithConn[T]
}

// StoreWithConn 将带 Conn() T 的 Fiber storage 后端适配为 storage.Store 与 storage.ConnProvider[T]。
type StoreWithConn[T any] struct {
	*Store
	backend FiberStorageConn[T]
}

// NewWithConn 创建保留底层连接访问能力的 Fiber storage 适配器。
func NewWithConn[T any](backend FiberStorageConn[T]) *StoreWithConn[T] {
	if backend == nil {
		panic("fiberstore: backend is nil")
	}
	return &StoreWithConn[T]{
		Store:   New(backend),
		backend: backend,
	}
}

// Conn 返回底层 Fiber storage 后端暴露的连接对象。
func (s *StoreWithConn[T]) Conn() T {
	if s == nil || s.backend == nil {
		var zero T
		return zero
	}
	return s.backend.Conn()
}

// Conn 返回底层 Fiber storage 后端暴露的连接对象。
//
// 若底层后端未实现 Conn() T，则返回对应类型零值。
func Conn[T any](store *Store) T {
	var zero T
	if store == nil || store.backend == nil {
		return zero
	}
	conn, ok := store.backend.(FiberStorageWithConn[T])
	if !ok {
		return zero
	}
	return conn.Conn()
}

var (
	_ storage.Store             = (*StoreWithConn[any])(nil)
	_ storage.ConnProvider[any] = (*StoreWithConn[any])(nil)
)
