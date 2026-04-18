# pkg/cache

`pkg/cache` 定义框架通用缓存抽象，并提供内存实现。

## 模块用途

- 统一 `Cache` 接口，屏蔽具体存储实现。
- 提供默认内存缓存 `NewMemoryCache`，供 `Engine` 内部直接使用。
- 提供 `LRUCache` 作为轻量级本地淘汰容器，适合独立场景。

## 关键类型与函数

### 核心接口

- `type Cache interface`
  - `Get(ctx, key)`
  - `Set(ctx, key, value, ttl)`
  - `Delete(ctx, key)`
  - `Exists(ctx, key)`
  - `Clear(ctx)`
  - `Close()`
- `type BatchCache interface`
  - `MGet` / `MSet` / `MDelete`
- `type AtomicCache interface`
  - `GetOrSet` / `Increment` / `Decrement`
- `type StatsCache interface`
  - `Stats()` / `ResetStats()`

### 默认实现

- `NewMemoryCache(opts ...MemoryOption) Cache`
  - 基于 map + RWMutex
  - 支持 TTL、容量上限、后台清理、批量操作
- `NewLRU(capacity int) *LRUCache`
  - 基于 `container/list` 的 LRU 容器
  - 提供 `Get` / `Set` / `Delete` / `Len` / `Clear`
  - 适合直接嵌入业务逻辑；**当前并未完整实现 `Cache` 接口**

### 错误

- `ErrNotFound`
- `ErrExpired`

## 配置项

### MemoryCache

- `WithMaxSize(size int)`：最大 key 数，超过后淘汰最旧项
- `WithDefaultTTL(ttl time.Duration)`：`Set` 时未显式指定 TTL 的默认值
- `WithCleanupInterval(d time.Duration)`：过期清理周期；设为 `0` 可关闭后台清理

### Redis 实现说明

当前仓库**未内置 Redis 实现**。若需要 Redis，可自行实现 `Cache` / `BatchCache` / `AtomicCache`，再通过 `Engine.WithCache` 注入。

## 使用示例

### 使用默认内存缓存

```go
package main

import (
    "context"
    "time"

    "github.com/darkit/gin/pkg/cache"
)

func main() {
    c := cache.NewMemoryCache(
        cache.WithMaxSize(1000),
        cache.WithDefaultTTL(5*time.Minute),
        cache.WithCleanupInterval(time.Minute),
    )
    defer c.Close()

    _ = c.Set(context.Background(), "user:1", []byte("alice"), time.Minute)
    _, _ = c.Get(context.Background(), "user:1")
}
```

### 使用批量接口

```go
mc := cache.NewMemoryCache()
if batch, ok := mc.(cache.BatchCache); ok {
    _ = batch.MSet(context.Background(), map[string][]byte{
        "a": []byte("1"),
        "b": []byte("2"),
    }, time.Minute)
}
```

### 自定义 Redis 适配器

```go
type RedisCache struct{}

func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, error) { return nil, nil }
func (r *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error { return nil }
func (r *RedisCache) Delete(ctx context.Context, key string) error { return nil }
func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) { return false, nil }
func (r *RedisCache) Clear(ctx context.Context) error { return nil }
func (r *RedisCache) Close() error { return nil }
```

## 与 Engine 的集成

- `gin.New()` 默认注入 `cache.NewMemoryCache()` 作为内部缓存。
- 可通过 `e.WithCache(customCache)` 替换实现。
- 适合将自定义 Redis/分布式缓存注入到框架或业务层统一使用。

```go
e := gin.New()
e.WithCache(cache.NewMemoryCache(cache.WithDefaultTTL(10 * time.Minute)))
```
