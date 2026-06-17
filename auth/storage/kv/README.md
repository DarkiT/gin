# auth/storage/kv

`auth/storage/kv` 把 `pkg/storage.Store` 适配为 `auth.Storage`，用于复用 Fiber storage 生态或其他通用 KV 后端。

这不是普通 cache adapter。Auth 运行时需要 token/session 级能力：

- `TTL` / `Expire`：自动续期、Session 保活、禁用状态过期
- `SetKeepTTL`：更新 TokenInfo 或踢出状态时保持原 TTL
- `Keys`：多端 token 列表、登录数量统计
- `Exists`：禁用状态、Nonce、防重放与续期标记
- 可选 `SetNX`：OAuth2 操作锁

## 推荐入口

```go
store := newAuthCapableStore() // 实现 storage.Store + storage.TTLStore + storage.KeyScanner

storage, err := kv.NewStrict(store)
if err != nil {
    panic(err)
}

mgr := auth.NewManager(storage, &cfg)
```

如果应用侧使用根包，可以写：

```go
storage, err := auth.NewKVStorage(store)
if err != nil {
    panic(err)
}
```

## Strict 与 Relaxed

### Strict

`NewStrict(store)` 会在构造期检查：

- `storage.TTLStore`
- `storage.KeyScanner`

不满足时返回 `MissingCapabilityError`，并可通过 `errors.Is(err, kv.ErrUnsupportedOperation)` 判断。

### Relaxed

`NewRelaxed(store)` 只要求 `storage.Store`，适合测试或明确不使用完整认证能力的场景。
当调用 `Keys`、`Expire`、`TTL`、`SetKeepTTL` 等底层不支持的能力时，会返回 `ErrUnsupportedOperation`。

## Atomic SetNX

OAuth2 内部会在存储实现暴露 `SetNX` 时使用它做操作锁。为避免非原子 fallback 误伤并发安全，普通 `Storage` 不暴露 `SetNX`。

只有底层实现了 `AtomicStore` 时才使用：

```go
storage := kv.NewAtomic(store)
```

此时底层 `SetNX(ctx, key, val, ttl)` 必须是真正原子操作。

## 编码语义

适配器写入规则：

- `string` -> 原样字节
- `[]byte` -> 原样拷贝
- `encoding.BinaryMarshaler` -> `MarshalBinary()`
- 其他类型 -> `json.Marshal`

读取时统一返回 `string`，保持 `auth.Manager` 对 token/account/session 数据的既有解析语义。

## 后端建议

| 后端 | 建议用途 | 说明 |
| --- | --- | --- |
| Redis-like / etcd | 生产 auth/session | 需要 TTL、scan/prefix keys、可选原子 SetNX |
| Badger / Bbolt | 单机或 edge auth/session | 多副本不会共享登录状态 |
| S3 | 不推荐做 auth 主存储 | 对象存储不适合高频小 key、TTL 与 token 续期 |

如果后端只实现基础 `storage.Store`，更适合接入 `pkg/cache`，不要直接宣称为完整 auth 存储。
