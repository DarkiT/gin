# Cache & Storage Integration

这份文件用于处理 cache、storage、Fiber storage 后端和 auth/session 存储边界。

## 目录

- 先选对抽象
- Engine 级 cache
- 复用 Fiber storage 生态
- middleware.Cache 安全默认值
- Idempotent key 边界
- Auth storage 边界
- 排障与核对入口

## 先选对抽象

| 场景 | 推荐入口 | 关键边界 |
| --- | --- | --- |
| 请求内普通缓存 | `c.Cache()` | 由 Engine 注入并托管生命周期 |
| 应用级缓存后端 | `gin.WithCache(cache.Cache)` | Engine 关闭时会调用 `Close()` |
| 本地内存缓存 | `cache.NewMemory(...)` | TTL、LRU、并发安全、统计、`GetOrSet` |
| 复用 `pkg/storage.Store` | `cache.NewStorageCache(store)` | miss 从 `nil, nil` 转成 `cache.ErrNotFound` |
| 复用 Fiber storage 后端 | `cache.NewFiberStorage(raw)` | 不强制主模块依赖具体 driver |
| auth/session 后端 | `auth.NewKVStorage(store)` / `kv.NewStrict(store)` | 需要 `TTLStore` + `KeyScanner` |
| OAuth2 原子锁 | `auth.NewAtomicKVStorage(store)` / `kv.NewAtomic(store)` | 底层必须真正支持原子 `SetNX` |

## Engine 级 cache

最推荐的接法：

```go
app := gin.New(
    gin.WithCache(cache.NewMemory(cache.WithMaxEntries(10_000))),
)
```

运行时替换：

```go
app.WithCache(cache.NewFiberStorage(raw))
```

当前语义：

- `WithCache(...)` / `Engine.WithCache(...)` 传入的实例由 Engine 接管生命周期
- `Run()` 退出或 `Shutdown(ctx)` 时会调用 `Close()`
- 传入 `nil` 会 fail-fast
- Engine 停止后 `c.Cache()` 仍返回非 nil 占位，但读写会返回 `cache.ErrClosed`

## 复用 Fiber storage 生态

应用侧按需引入具体后端，框架侧只依赖结构兼容接口：

```go
import (
    gin "github.com/darkit/gin"
    "github.com/darkit/gin/pkg/cache"
    bbolt "github.com/gofiber/storage/bbolt/v2"
)

app := gin.New(
    gin.WithCache(cache.NewFiberStorage(bbolt.New())),
)
```

可以同样替换为 Fiber storage 生态中的 Badger、etcd、S3 等后端：

```go
gin.WithCache(cache.NewFiberStorage(badger.New(...)))
gin.WithCache(cache.NewFiberStorage(etcd.New(...)))
gin.WithCache(cache.NewFiberStorage(s3.New(...)))
```

底层适配入口：

- `pkg/storage/fiberstore.New(raw)`：包装最小 Fiber storage 方法集
- `pkg/storage/fiberstore.NewWithConn[T](raw)`：保留 `Conn() T` 访问能力
- `pkg/storage/fiberstore.Conn[T](store)`：从普通适配器尝试取底层连接

## middleware.Cache 安全默认值

当前响应缓存是 secure by default：

- 只缓存 `GET` / `HEAD`
- 默认跳过带 `Authorization` 或 `Cookie` 的请求
- 默认跳过请求侧 `Cache-Control: no-cache/no-store` 和 `Pragma: no-cache`
- 只缓存 `2xx` 响应
- 不缓存带 `Set-Cookie` 的响应
- 不缓存响应侧 `Cache-Control: private/no-cache/no-store`
- `WithCacheVary(...)` 不只写响应 `Vary`，还会把请求 Header 值纳入缓存 key
- 默认中间件内存 store 关闭后台 cleanup goroutine，避免无法托管的生命周期泄漏

常用写法：

```go
e.UseAny(
    middleware.Cache(time.Minute,
        middleware.WithCacheControl("public, max-age=60"),
        middleware.WithCacheVary("Accept-Language", "Accept-Encoding"),
    ),
)
```

业务需要显式跳过时：

```go
middleware.WithCacheSkip(func(c *gin.Context) bool {
    return c.GetHeader("X-Bypass-Cache") == "1"
})
```

## Idempotent key 边界

`middleware.Idempotent(...)` 默认使用：

```text
method + request path + Idempotency-Key
```

再做 SHA256 生成内部 key。这样同一个 `Idempotency-Key` 不会跨 method 或 path replay。

跨租户、跨用户、跨业务域时继续追加 namespace：

```go
e.UseAny(middleware.Idempotent(
    middleware.WithIdempotentNamespaceFunc(func(c *gin.Context) string {
        return c.GetHeader("Authorization")
    }),
))
```

生产建议：

- 支付、订单、库存、外部回调等写接口必须明确 namespace
- 如果同一路径下 body 差异也要隔离，自定义 `WithIdempotentKeyFunc(...)` 或在 namespace 中加入 body digest

## Auth storage 边界

不要把基础 `storage.Store` 直接当成完整 auth/session 后端。

Auth 需要：

- `Keys(ctx, pattern)`：枚举 token/session 相关 key
- `Expire(ctx, key, ttl)`：更新 TTL
- `TTL(ctx, key)`：读取剩余 TTL
- `SetKeepTTL(ctx, key, val)`：更新值但保留 TTL

严格接入：

```go
store := fiberstore.New(raw)
authStore, err := auth.NewKVStorage(store)
if err != nil {
    return err
}
```

如果底层只实现最小 KV，优先用于：

- `pkg/cache`
- `middleware.Cache` store
- 未来无需扫描/续期语义的通用 KV 场景

## 排障与核对入口

调用方项目中先核对：

- 是否由 `gin.WithCache(...)` 或 `app.WithCache(...)` 注入同一个 cache 实例
- 是否把 Fiber storage miss 的 `nil, nil` 语义交给 `cache.NewFiberStorage(...)` 适配
- 是否把最小 KV 后端误用于 auth/session 严格场景
- 是否在多租户/多主体接口上设置了 idempotency namespace

只有当前 workspace 是 `github.com/darkit/gin` 本仓时，再读：

- `pkg/cache/README.md`
- `pkg/cache/DESIGN.md`
- `pkg/storage/README.md`
- `pkg/storage/fiberstore/`
- `auth/storage/kv/README.md`
- `middleware/cache.go`
- `middleware/idempotent.go`
- `resource_cache.go`
