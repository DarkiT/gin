# pkg/cache DESIGN

## 目标

`pkg/cache` 的目标是提供一个足够小、稳定、易接入的缓存抽象，同时让默认内存实现具备真实可用的缓存能力。

本模块不试图成为完整分布式缓存系统，也不替代 auth/session 的强语义存储接口。

## 设计原则

1. **最小主接口**
   - `Cache` 只保留 `Get` / `Set` / `Delete` / `Clear` / `Close`
   - `Exists`、批量、原子计数、统计信息放入可选接口

2. **后端友好**
   - `NewStorageCache(store)` 适配 `pkg/storage.Store`
   - `NewFiberStorage(raw)` 直接适配 Fiber storage 兼容后端
   - 不直接依赖任何具体 Fiber storage driver，避免主模块依赖膨胀

3. **本地实现可生产使用**
   - `Memory` 支持 TTL、LRU 淘汰、并发安全、后台清理、批量操作、原子计数、统计信息
   - 读写默认 clone `[]byte`，避免调用方修改缓存内部状态

4. **Gin 主链不变**
   - `gin.New()` 默认注入 `cache.NewMemory()`
   - `gin.WithCache(...)` / `Engine.WithCache(...)` / `c.Cache()` 用法保持不变
   - Engine 会接管注入缓存的生命周期，关闭时调用 `Close()`；传入 `nil` 会 fail-fast

## 接口分层

```go
type Cache interface {
    Get(ctx context.Context, key string) ([]byte, error)
    Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
    Clear(ctx context.Context) error
    Close() error
}
```

可选能力：

- `ExistenceCache`：存在性检查
- `BatchCache`：批量读写删除
- `AtomicCache`：`GetOrSet`、`Increment`、`Decrement`
- `StatsCache`：命中率、淘汰、过期、key 数、大小等统计

## Memory 实现

`Memory` 使用：

- `map[string]*memoryEntry` 做 O(1) key 访问
- `container/list` 做 LRU 顺序维护
- `sync.RWMutex` 保护并发访问
- `cleanupTicker` 周期性清理过期项
- `loads map[string]*loadCall` 合并并发 `GetOrSet` 加载，避免同 key 缓存击穿
- `GetOrSet` loader 即使 panic，也必须清理 `loads` 并释放等待者，避免后续同 key 调用永久阻塞

行为约束：

- `ttl <= 0` 表示不过期
- `maxEntries <= 0` 表示不限制容量
- `Delete` 删除不存在 key 返回 `nil`
- `Close` 可重复调用，关闭后读写返回 `ErrClosed`
- 空 key 写入返回 `ErrInvalidKey`
- `GetOrSet` 不吞掉 loader panic，但会先完成内部 singleflight 状态清理

## Storage/Fiber storage 适配

`StorageCache` 负责将 `pkg/storage.Store` 转成 `Cache`：

- `storage.Store` miss 语义：`nil, nil`
- `cache.Cache` miss 语义：`ErrNotFound`

`NewFiberStorage(raw)` 是面向调用方的优雅入口：

```go
gin.WithCache(cache.NewFiberStorage(bbolt.New()))
```

它内部通过 `pkg/storage/fiberstore` 做结构兼容适配，不把 `github.com/gofiber/storage/*` 的具体 driver 变成框架硬依赖。

## 已移除的旧路径

本次断代重构删除：

- `NewMemoryCache`
- `WithMaxSize`
- `WithDefaultTTL`
- 独立 `LRUCache`
- `pkg/cache/storagecache` 子包

替代方式：

- `NewMemory(...)`
- `WithMaxEntries(...)`
- `Memory` 内建 LRU 淘汰
- `NewStorageCache(...)`
- `NewFiberStorage(...)`

## Auth 边界

`pkg/cache` 不承担 auth/session 存储职责。

Auth 需要 `Keys`、`TTL`、`Expire`、`SetKeepTTL` 等 token/session 生命周期能力；这些能力不应塞进缓存主接口。接入 `pkg/storage` 到 auth 时，应通过 auth 专用 strict adapter 判断底层能力。
