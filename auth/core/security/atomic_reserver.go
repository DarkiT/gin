package security

import (
	"sync"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
)

// atomicReserver 是 storage 可选的原子占用能力：仅当 key 不存在（或已过期）时写入，返回是否首次占用。
// memory 与 kv 存储均实现了该方法，因此一旦后端具备该能力即可获得真正的多实例防重放原子性。
//
// atomicReserver is the optional atomic reserve capability of a storage backend.
type atomicReserver interface {
	SetNX(key string, value any, expiration time.Duration) (bool, error)
}

// reserveOnce 原子地"首次占用"一个 key，返回是否首次占用成功（true = 此前不存在，本次占用）。
//
//   - 当 storage 实现 SetNX（memory / kv）时，由后端保证原子性，多实例部署同样安全；
//   - 否则降级为进程内互斥（靠 mu 串行化 Exists+Set），仅保证单实例安全。
//
// 该函数用于收紧一次性 nonce / 签名 nonce 的"先查再写"TOCTOU 窗口。
func reserveOnce(storage adapter.Storage, mu sync.Locker, key string, ttl time.Duration) bool {
	if ar, ok := storage.(atomicReserver); ok {
		ok, err := ar.SetNX(key, "1", ttl)
		return err == nil && ok
	}
	mu.Lock()
	defer mu.Unlock()
	if storage.Exists(key) {
		return false
	}
	_ = storage.Set(key, "1", ttl)
	return true
}
