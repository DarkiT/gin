// Package storage 定义 darkit/gin 通用字节型 KV 存储抽象。
package storage

import (
	"context"
	"time"
)

// Store 定义通用字节型 KV 存储接口。
//
// 约束：
//   - key 不存在时返回 nil, nil。
//   - ttl <= 0 表示不过期。
//   - Close 用于释放连接、后台清理器或本地文件句柄。
type Store interface {
	// Get 获取指定 key 的值。
	Get(ctx context.Context, key string) ([]byte, error)
	// Set 写入指定 key 的值，ttl <= 0 表示不过期。
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	// Delete 删除指定 key；key 不存在时应返回 nil。
	Delete(ctx context.Context, key string) error
	// Clear 清空当前存储命名空间内的所有数据。
	Clear(ctx context.Context) error
	// Close 关闭存储连接或后台资源。
	Close() error
}

// KeyScanner 表示存储支持按 pattern 枚举 key。
//
// 该能力并非所有后端都天然支持；auth/session 等依赖 key 扫描的模块应在接入时显式探测。
type KeyScanner interface {
	// Keys 返回匹配 pattern 的 key 列表。
	Keys(ctx context.Context, pattern string) ([]string, error)
}

// TTLStore 表示存储支持独立 TTL 操作。
//
// 该接口用于 token 续期、session 保活等需要读取或保留过期时间的场景。
type TTLStore interface {
	// Expire 更新指定 key 的过期时间。
	Expire(ctx context.Context, key string, ttl time.Duration) error
	// TTL 返回指定 key 的剩余过期时间。
	TTL(ctx context.Context, key string) (time.Duration, error)
	// SetKeepTTL 更新值并保留原有过期时间。
	SetKeepTTL(ctx context.Context, key string, val []byte) error
}

// ExistenceStore 表示存储支持高效存在性检查。
type ExistenceStore interface {
	// Exists 检查指定 key 是否存在。
	Exists(ctx context.Context, key string) (bool, error)
}

// ConnProvider 暴露底层连接对象，用于访问驱动特有能力。
//
// 泛型参数 T 由具体后端决定，例如 Redis client、etcd client、本地 DB 句柄等。
type ConnProvider[T any] interface {
	// Conn 返回底层连接对象。
	Conn() T
}
