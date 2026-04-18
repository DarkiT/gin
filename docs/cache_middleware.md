# 响应缓存中间件

本文档说明 `middleware.Cache`、`middleware.CacheIf` 与 `middleware.ETag` 的当前用法。

> 说明：这些缓存中间件返回原始 `gin.HandlerFunc`。
>
> 在 `github.com/darkit/gin` 中，推荐两种接法：
> - 全局或分组：`e.Use(...)` / `r.Use(...)`
> - 单路由：`engine.WrapMiddleware(middleware.Cache(...))`

## 功能特性

- ✅ 响应缓存：自动缓存 HTTP 响应
- ✅ 条件缓存：根据自定义条件决定是否缓存
- ✅ ETag 支持：自动生成 ETag 并处理 304 Not Modified
- ✅ 自定义缓存键：灵活的缓存键生成策略
- ✅ Cache-Control 头：自动设置缓存控制头
- ✅ Vary 头：支持内容协商
- ✅ 分布式缓存：支持外部缓存存储（如 Redis）
- ✅ 测试覆盖率：96.9%

## 文件说明

### 核心文件

- `middleware/cache.go` - 缓存中间件核心实现
- `middleware/etag.go` - ETag 中间件实现
- `middleware/cache_test.go` - 单元测试（15 个测试用例）

### 示例文件

- `examples/cache-demo/main.go` - 使用示例和交互式测试页面

## 快速开始

### 1. 基础缓存

```go
import (
    "time"
    "github.com/darkit/gin/middleware"
)

// 全局/分组级缓存
e.Use(middleware.Cache(5 * time.Minute))
```

### 2. 条件缓存

```go
// 当没有 nocache 参数时才缓存
e.Use(middleware.CacheIf(func(c *gin.Context) bool {
    return c.Query("nocache") == ""
}, 10*time.Minute))
```

### 3. ETag 支持

```go
// 自动生成 ETag 并处理 304 响应
e.Use(middleware.ETag())
```

### 4. 自定义缓存键

```go
// 根据用户 ID 生成缓存键
e.Use(middleware.Cache(5*time.Minute,
    middleware.WithCacheKey(func(c *gin.Context) string {
        return "profile:" + c.GetString("user_id")
    }),
))
```

### 5. Cache-Control 和 Vary 头

```go
e.Use(middleware.Cache(time.Minute,
    middleware.WithCacheControl("public, max-age=60"),
    middleware.WithCacheVary("Accept-Language", "Accept-Encoding"),
))
```

### 6. 分布式缓存

```go
// 使用自定义外部缓存适配器作为缓存存储
customStore := &RedisCache{}
e.Use(middleware.Cache(time.Minute,
    middleware.WithCacheStore(customStore),
))
```

## API 文档

### Cache 中间件

```go
func Cache(duration time.Duration, opts ...CacheOption) gin.HandlerFunc
```

缓存 HTTP 响应指定时间。

**参数：**
- `duration` - 缓存持续时间
- `opts` - 可选的缓存选项

**行为：**
- 只缓存 GET 和 HEAD 请求
- 只缓存成功响应（2xx 状态码）
- 自动设置 `X-Cache` 头（HIT 或 MISS）

### CacheIf 中间件

```go
func CacheIf(condition func(*gin.Context) bool, duration time.Duration, opts ...CacheOption) gin.HandlerFunc
```

根据条件决定是否缓存响应。

**参数：**
- `condition` - 条件函数，返回 true 时缓存
- `duration` - 缓存持续时间
- `opts` - 可选的缓存选项

### ETag 中间件

```go
func ETag() gin.HandlerFunc
```

自动生成 ETag 并处理 If-None-Match 请求头。

**行为：**
- 使用 MD5 哈希计算响应内容的 ETag
- 检查客户端的 If-None-Match 头
- 如果 ETag 匹配，返回 304 Not Modified
- 只处理 GET 和 HEAD 请求
- 只处理成功响应（2xx 状态码）

### 缓存选项

#### WithCacheStore

```go
func WithCacheStore(store cache.Cache) CacheOption
```

设置自定义缓存存储（用于分布式缓存）。

#### WithCacheKey

```go
func WithCacheKey(keyFunc func(*gin.Context) string) CacheOption
```

设置自定义缓存键生成函数。

**默认键格式：** `method:path:querystring` 的 SHA256 哈希

#### WithCacheControl

```go
func WithCacheControl(control string) CacheOption
```

设置 Cache-Control 响应头。

**示例：** `"public, max-age=60"`

#### WithCacheVary

```go
func WithCacheVary(headers ...string) CacheOption
```

设置 Vary 响应头，支持内容协商。

**示例：** `"Accept-Language", "Accept-Encoding"`

## 缓存响应结构

```go
type cachedResponse struct {
    Status  int         // HTTP 状态码
    Headers http.Header // 响应头
    Body    []byte      // 响应体
}
```

缓存会保存完整的响应信息，包括状态码、所有响应头和响应体。

## 默认缓存键生成

默认情况下，缓存键基于以下信息生成：

```
SHA256(method:path:querystring)
```

例如：
- `GET /articles/123` → `cache:a1b2c3...`
- `GET /articles/123?lang=en` → `cache:d4e5f6...`

## 工作原理

### Cache 中间件

1. 检查请求方法（只缓存 GET/HEAD）
2. 生成缓存键
3. 尝试从缓存获取响应
4. 如果缓存命中：
   - 反序列化响应
   - 设置响应头
   - 返回缓存的内容
   - 设置 `X-Cache: HIT`
5. 如果缓存未命中：
   - 使用自定义 ResponseWriter 拦截响应
   - 设置 `X-Cache: MISS`
   - 继续处理请求
   - 如果响应成功（2xx），保存到缓存

### ETag 中间件

1. 检查请求方法（只处理 GET/HEAD）
2. 使用自定义 ResponseWriter 拦截响应
3. 继续处理请求
4. 计算响应内容的 MD5 哈希作为 ETag
5. 检查客户端的 If-None-Match 头
6. 如果 ETag 匹配：
   - 返回 304 Not Modified
   - 不返回响应体
7. 如果 ETag 不匹配或客户端未提供：
   - 设置 ETag 头
   - 返回完整响应

## 测试用例

实现了 15 个全面的测试用例：

### Cache 中间件测试

1. `TestCache_Hit` - 缓存命中
2. `TestCache_Miss` - 缓存未命中
3. `TestCache_Expiry` - 缓存过期
4. `TestCacheIf_Condition` - 条件缓存
5. `TestCache_CustomKey` - 自定义缓存键
6. `TestCache_OnlyGetHead` - 只缓存 GET/HEAD 请求
7. `TestCache_OnlySuccessResponses` - 只缓存成功响应
8. `TestCache_WithCacheControl` - Cache-Control 头
9. `TestCache_WithVary` - Vary 头
10. `TestCache_WithCustomStore` - 自定义存储

### ETag 中间件测试

11. `TestETag_NotModified` - 304 Not Modified 响应
12. `TestETag_Modified` - ETag 不匹配时返回完整响应
13. `TestETag_OnlyGetHead` - 只处理 GET/HEAD 请求
14. `TestETag_OnlySuccessResponses` - 只对成功响应生成 ETag
15. `TestETag_DifferentContent` - 不同内容生成不同的 ETag

## 运行测试

```bash
# 运行所有缓存相关测试
go test -v -run "TestCache|TestETag" ./middleware/

# 查看测试覆盖率
go test -coverprofile=coverage.out ./middleware/cache.go ./middleware/etag.go ./middleware/cache_test.go
go tool cover -func=coverage.out

# 运行示例
go run examples/cache-demo/main.go
```

## 性能优化建议

1. **选择合适的缓存时间**
   - 静态内容：较长时间（如 1 小时）
   - 动态内容：较短时间（如 1-5 分钟）
   - 实时数据：不缓存或使用 ETag

2. **使用分布式缓存**
   - 对于多实例部署，可自定义实现 `pkg/cache.Cache` 后注入
   - 当前仓库未内置 Redis 实现
   - 避免每个实例维护独立缓存

3. **自定义缓存键**
   - 对于需要按用户缓存的接口，使用自定义键
   - 避免查询参数顺序影响缓存

4. **结合 ETag 使用**
   - 对于变化不频繁的内容，使用 ETag
   - 可以减少带宽消耗

5. **合理使用条件缓存**
   - 允许用户绕过缓存（如 `nocache` 参数）
   - 对管理员或特定用户禁用缓存

## 注意事项

1. **不要缓存敏感数据**
   - 用户个人信息应该使用自定义键
   - 认证相关接口不应缓存

2. **缓存失效策略**
   - 默认使用 TTL 过期
   - 如需主动清除，需要访问底层缓存存储

3. **响应头处理**
   - 缓存会保存所有响应头
   - 某些头可能需要特殊处理（如 Set-Cookie）

4. **内存使用**
   - 默认使用内存缓存
   - 大规模应用应使用外部缓存存储

5. **并发安全**
   - 所有中间件都是并发安全的
   - 使用了适当的互斥锁保护

## 最佳实践

### 1. API 接口缓存

```go
// 公开 API，缓存时间较长
e.GET(
    "/api/v1/products",
    engine.WrapMiddleware(middleware.Cache(10*time.Minute,
        middleware.WithCacheControl("public, max-age=600"),
    )),
    getProducts,
)

// 用户相关 API，按用户缓存
e.GET(
    "/api/v1/user/orders",
    engine.WrapMiddleware(middleware.Cache(1*time.Minute,
        middleware.WithCacheKey(func(c *gin.Context) string {
            return "orders:" + c.GetString("user_id")
        }),
    )),
    getOrders,
)
```

### 2. 静态资源

```go
// 使用 ETag 处理静态资源
e.GET("/static/*filepath", engine.WrapMiddleware(middleware.ETag()), serveStatic)
```

### 3. 搜索结果

```go
// 搜索结果缓存，但允许用户强制刷新
e.GET(
    "/search",
    engine.WrapMiddleware(middleware.CacheIf(func(c *gin.Context) bool {
        return c.Query("refresh") != "1"
    }, 5*time.Minute)),
    searchHandler,
)
```

### 4. 分布式部署

```go
// 使用自定义外部缓存适配器确保多实例缓存一致
customStore := &RedisCache{}
e.Use(middleware.Cache(time.Minute,
    middleware.WithCacheStore(customStore),
))
```

## 总结

当前缓存中间件提供了完整的响应缓存解决方案，包括：

- ✅ 灵活的缓存策略
- ✅ 条件缓存支持
- ✅ ETag 和 304 处理
- ✅ 自定义缓存键
- ✅ 分布式缓存支持
- ✅ 高测试覆盖率（96.9%）
- ✅ 生产级代码质量

所有代码都遵循项目规范，使用中文注释，并提供了详细的使用示例和测试用例。
