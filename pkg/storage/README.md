# pkg/storage

`pkg/storage` 定义 `darkit/gin` 内部统一使用的字节型 KV 存储抽象。

它的定位是**稳定的适配层**，不是具体驱动实现。通过它可以把 Redis、etcd、Badger、Bbolt、S3，或 `github.com/gofiber/storage` 生态中的后端，以统一方式接入 `pkg/cache`、后续 session / rate limit / idempotency 等能力。

## 核心原则

- `Store` 只表达最小 KV 能力：`Get` / `Set` / `Delete` / `Clear` / `Close`
- key 不存在时统一返回 `nil, nil`
- `ttl <= 0` 表示不过期
- 高阶能力不塞进主接口，而是通过可选接口探测：
  - `KeyScanner`
  - `TTLStore`
  - `ExistenceStore`
  - `ConnProvider[T]`

这样可以避免把 S3、Bbolt、Badger 这类后端强行伪造成 Redis。

## Fiber storage 生态接入

使用 `pkg/storage/fiberstore` 可以包装任何结构兼容 `github.com/gofiber/storage` 接口的后端：

```go
raw := newFiberCompatibleStorage()
store := fiberstore.New(raw)
```

`fiberstore` 不直接引入具体 driver 依赖。应用侧按需引入 `gofiber/storage` 的 bbolt、badger、etcd、s3 等模块即可，主模块不会被额外依赖污染。

## 与 cache 集成

`pkg/cache.NewStorageCache` 可把 `storage.Store` 适配成现有 `pkg/cache.Cache`：

```go
c := cache.NewStorageCache(store)
```

然后继续通过既有入口使用：

```go
app := gin.New(
	gin.WithCache(c),
)
```

## 与 auth 的边界

`auth` 存储需要 `Keys`、`TTL`、`Expire`、`SetKeepTTL` 等增强语义，不能直接把基础 `Store` 当作完整 auth 后端。

需要接入认证主链时，使用 `auth/storage/kv` 的严格适配器：

```go
storage, err := kv.NewStrict(store)
if err != nil {
    return err
}
```

严格模式要求：

- 底层必须支持 `TTLStore`
- 底层必须支持 `KeyScanner`

如果还希望 OAuth2 操作锁使用后端原子能力，请使用 `kv.NewAtomic(store)`，底层必须真正实现 `AtomicStore` 的原子 `SetNX`。

不满足能力条件的后端可以用于 cache，但不应宣称为完整 auth/session 存储。
