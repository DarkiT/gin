# pkg/cache

`pkg/cache` 提供框架通用缓存抽象、生产可用的本地内存缓存，以及对 `pkg/storage` / Fiber storage 兼容后端的一行式接入入口。

## 模块用途

- 统一 `Cache` 最小接口，屏蔽具体后端。
- 提供 `Memory` 本地缓存：并发安全、TTL、LRU 淘汰、批量操作、原子计数、统计信息。
- 提供 `NewStorageCache(store)`：把 `pkg/storage.Store` 接入缓存。
- 提供 `NewFiberStorage(raw)`：直接包装 Fiber storage 兼容后端，例如 bbolt、badger、etcd、s3。

## 核心接口

```go
type Cache interface {
    Get(ctx context.Context, key string) ([]byte, error)
    Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
    Clear(ctx context.Context) error
    Close() error
}
```

约束：

- `Get` miss 返回 `ErrNotFound`，过期返回 `ErrExpired`
- `Set` 的 `ttl <= 0` 表示不过期
- `Delete` 删除不存在的 key 返回 `nil`
- `Close` 必须可重复调用

可选能力：

- `ExistenceCache`：`Exists(ctx, key)`
- `BatchCache`：`MGet` / `MSet` / `MDelete`
- `AtomicCache`：`GetOrSet` / `Increment` / `Decrement`
- `StatsCache`：`Stats` / `ResetStats`

## 本地内存缓存

```go
c := cache.NewMemory(
    cache.WithMaxEntries(10_000),
    cache.WithCleanupInterval(time.Minute),
)
defer c.Close()

_ = c.Set(ctx, "user:1", []byte("alice"), 5*time.Minute)
val, err := c.Get(ctx, "user:1")
```

配置项：

- `WithMaxEntries(size)`：最大 key 数，超过后按 LRU 淘汰；`<= 0` 表示不限制
- `WithCleanupInterval(d)`：后台过期清理周期；`<= 0` 表示关闭后台清理
- `WithCloneValues(enabled)`：读写时是否复制 `[]byte`；默认开启，避免调用方修改缓存内部状态

## 复用 Fiber storage 生态

推荐写法是一行式接入：

```go
import (
    gin "github.com/darkit/gin"
    "github.com/darkit/gin/pkg/cache"
    bbolt "github.com/gofiber/storage/bbolt/v2"
)

func main() {
    app := gin.New(
        gin.WithCache(cache.NewFiberStorage(bbolt.New())),
    )

    _ = app.Run()
}
```

同理可替换为 Fiber storage 生态中的其他后端：

```go
gin.WithCache(cache.NewFiberStorage(badger.New(...)))
gin.WithCache(cache.NewFiberStorage(etcd.New(...)))
gin.WithCache(cache.NewFiberStorage(s3.New(...)))
```

说明：

- `pkg/cache` 不直接 import 任何具体 Fiber storage driver
- 应用侧按需引入 bbolt / badger / etcd / s3，避免主模块依赖膨胀
- Fiber storage 的 `nil, nil` miss 语义会转换为 `cache.ErrNotFound`
- `cache.NewFiberStorage(raw)` 内部通过结构兼容方式接入，不要求业务代码手写 adapter
- 注入 `gin.WithCache(...)` / `app.WithCache(...)` 后，Engine 会接管缓存生命周期并在关闭时调用 `Close()`

## 接入任意 pkg/storage.Store

如果你已经有 `pkg/storage.Store`：

```go
store := newCustomStore()
app := gin.New(
    gin.WithCache(cache.NewStorageCache(store)),
)
```

`NewStorageCache` 会把 `storage.Store` 的 `nil, nil` miss 语义转换为 `cache.ErrNotFound`。

## 与 Engine 集成

`gin.New()` 默认注入：

```go
cache.NewMemory()
```

可通过以下方式替换。传入的缓存不能为 `nil`，并由 Engine 接管生命周期：

```go
app := gin.New(
    gin.WithCache(cache.NewMemory(cache.WithMaxEntries(10000))),
)

app.WithCache(cache.NewFiberStorage(raw))
```

请求内继续使用：

```go
val, err := c.Cache().Get(c.Request.Context(), "key")
```

## Auth 边界

`pkg/cache` 不是完整 auth/session 存储接口。

Auth 后端需要 `Keys`、`TTL`、`Expire`、`SetKeepTTL` 等增强语义。Fiber storage 的基础接口可用于 cache，但不能直接宣称为完整 auth 存储。
