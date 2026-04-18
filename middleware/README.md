# middleware

`middleware/` 提供基于 Gin 的生产级中间件集合，并额外兼容 Chi 风格 `func(http.Handler) http.Handler` 中间件。

该目录内既包含框架默认启用的核心中间件，也包含安全、性能、业务与 Chi 生态移植组件。默认 `gin.Default()` 会预装 `RequestID`、`Recovery`、`Logger`；其余中间件按需在路由或分组上启用。

> 基于实际实现整理：`requestid.go`、`recovery.go`、`logger.go`、`cors.go`、`secure.go`、`ratelimit.go`、`signature.go`、`cache.go`、`compress.go`、`timeout.go`、`idempotent.go`、`interceptor.go`、`registry.go`，以及多组 Chi 风格兼容件。

---

## Middleware ecosystem overview

### 默认核心链

框架 `gin.Default()` 在 `engine.go` 中默认注册：

1. `RequestID()`：注入/透传 `X-Request-ID`
2. `Recovery()`：捕获 panic，避免进程崩溃
3. `Logger()`：记录请求方法、路径、状态码、耗时、客户端 IP

### 中间件生态分层

| 分类 | 中间件 | 作用 |
| --- | --- | --- |
| Core | `RequestID`、`Recovery`、`Logger`、`OTel` | 请求追踪、崩溃恢复、访问日志、OpenTelemetry 接入 |
| Security | `CORS`、`Secure`、`RateLimit`、`SignatureVerify` | 跨域、安全响应头、访问限流、签名验签 |
| Performance | `Cache`、`Compress`、`Timeout` | 响应缓存、压缩、超时控制 |
| Business | `Idempotent` | 幂等控制、防重复提交 |
| Chain / Extensibility | `Interceptor`、`Registry`、`Maybe` | 请求/响应拦截、注册表、条件执行 |
| Chi compatibility | `Throttle`、`RealIP`、`NoCache`、`URLFormat`、`Sunset`、`RouteHeaders`、`ValidateParam` | 从 Chi 设计迁移或兼容的中间件能力 |
| Other built-ins | `ETag`、`CircuitBreaker` | 条件缓存、熔断保护 |

---

## Available middlewares

### Core

#### RequestID

`RequestID()` 读取请求头 `X-Request-ID`；若不存在则生成 UUID，并同时写入：

- 请求上下文键 `request_id`
- 响应头 `X-Request-ID`

```go
r.Use(middleware.RequestID())

r.GET("/ping", func(c *gin.Context) {
    requestID, _ := c.Get("request_id")
    c.JSON(200, gin.H{"request_id": requestID})
})
```

**适用场景**：链路追踪、日志关联、错误排查。

#### Recovery

`Recovery()` 使用 `os.Stderr` 输出 panic 日志；`RecoveryWithWriter(out)` 可自定义日志输出位置。

实现特性：

- `recover()` 捕获 panic
- 对 `broken pipe` / `connection reset` 做特殊处理
- 普通 panic 返回 `500`

```go
r.Use(middleware.Recovery())

// 自定义日志输出
r.Use(middleware.RecoveryWithWriter(os.Stdout))
```

**适用场景**：生产环境防止单请求 panic 造成服务崩溃。

#### Logger

`Logger()` 使用标准库 `log.Logger` 输出访问日志，记录：

- HTTP Method
- Path
- Status
- Latency
- ClientIP

```go
r.Use(middleware.Logger())
```

**适用场景**：基础访问审计、延迟观测。

#### OTel

`OTel(service, opts...)` 基于官方 `otelgin` 中间件为请求接入 OpenTelemetry 追踪与指标。

```go
r.Use(middleware.OTel("order-api"))
```

配合增强 `Context`，可以在处理器中直接读取：

- `c.TraceID()`
- `c.SpanID()`

**适用场景**：链路追踪、分布式排障、指标采集。

---

### Security

#### CORS

`CORS(config ...CORSConfig)` 配置跨域响应头。未传配置时使用 `DefaultCORSConfig()`。

默认值包括：

- `AllowOrigins: ["*"]`
- `AllowMethods: GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS`
- `AllowHeaders: Origin/Content-Length/Content-Type/Authorization`
- `MaxAge: 12h`

对 `OPTIONS` 请求会直接返回 `204 No Content`。

```go
r.Use(middleware.CORS())

r.Use(middleware.CORS(middleware.CORSConfig{
    AllowOrigins:     []string{"https://app.example.com"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
    AllowHeaders:     []string{"Content-Type", "Authorization", "X-Request-ID"},
    ExposeHeaders:    []string{"X-Request-ID"},
    MaxAge:           3600,
    AllowCredentials: true,
}))
```

#### Secure

`Secure()` 注入一组安全响应头：

- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

```go
r.Use(middleware.Secure())
```

#### RateLimit

`RateLimit(config ...RateLimitConfig)` 为每个客户端 IP 创建独立 `rate.Limiter`。

默认配置：

- `RequestsPerSecond: 10`
- `Burst: 20`

超限后直接返回 `429 Too Many Requests`。内部会周期清理长期未访问的访客桶。

```go
r.Use(middleware.RateLimit())

r.Use(middleware.RateLimit(middleware.RateLimitConfig{
    RequestsPerSecond: 20,
    Burst:             40,
}))
```

#### SignatureVerify

`SignatureVerify(opts ...SignatureOption)` 对请求进行 HMAC 验签，内置防重放保护。

要求请求头：

- `X-Timestamp`
- `X-Nonce`
- `X-Signature`

默认行为：

- 默认算法：`HMAC-SHA256`
- 默认有效期：`300s`
- 默认 `NonceStore`：内存实现
- 默认 body 限制：`10MB`
- 时间戳、nonce、请求体、路径、方法与附加 headers 一并参与签名

```go
r.Use(middleware.SignatureVerify(
    middleware.WithSignatureSecret("top-secret"),
    middleware.WithSignatureExpiry(300),
    middleware.WithSignatureAlgorithm("HMAC-SHA256"),
    middleware.WithSignatureHeaders("X-Device-ID", "X-Tenant-ID"),
))
```

客户端可使用辅助函数生成签名：

```go
timestamp := strconv.FormatInt(time.Now().Unix(), 10)
nonce, err := middleware.GenerateNonce()
if err != nil {
    return err
}
signature := middleware.GenerateSignature(
    "POST",
    "/api/orders",
    `{"amount":100}`,
    timestamp,
    nonce,
    "top-secret",
    "HMAC-SHA256",
    map[string]string{"X-Device-ID": "mobile"},
)
```

---

### Performance

#### Cache

`Cache(duration, opts...)` 仅缓存 `GET` 和 `HEAD` 请求的成功响应（`2xx`）。

实现要点：

- 默认使用内存缓存 `pkg/cache.NewMemoryCache()`
- 默认 key：`method:path:query` 的 SHA-256 哈希
- 命中时写入 `X-Cache: HIT`
- 未命中时写入 `X-Cache: MISS`
- 响应通过 `gob` 序列化存储

```go
r.GET("/articles/:id",
    middleware.Cache(5*time.Minute),
    func(c *gin.Context) {
        c.JSON(200, gin.H{"id": c.Param("id")})
    },
)
```

自定义缓存存储、Key、响应头：

```go
store := cache.NewMemoryCache()

r.GET("/profile",
    middleware.Cache(30*time.Second,
        middleware.WithCacheStore(store),
        middleware.WithCacheControl("public, max-age=30"),
        middleware.WithCacheVary("Authorization"),
        middleware.WithCacheKey(func(c *gin.Context) string {
            return "profile:" + c.GetHeader("Authorization")
        }),
    ),
    handler,
)
```

条件缓存：

```go
r.GET("/feed",
    middleware.CacheIf(func(c *gin.Context) bool {
        return c.Query("preview") == ""
    }, time.Minute),
    handler,
)
```

#### Compress

`Compress(opts ...CompressOption)` 根据 `Accept-Encoding` 自动选择压缩算法。

当前实现支持：

- `gzip`（默认优先）
- `deflate`
- `br`

默认只压缩常见文本与 JSON/XML MIME，且响应体长度至少 `1024` 字节。

```go
r.Use(middleware.Compress())

r.Use(middleware.Compress(
    middleware.WithCompressAlgorithm("br"),
    middleware.WithCompressMinLength(512),
    middleware.WithCompressTypes("application/json", "text/html"),
))
```

#### Timeout

`Timeout(d)` 将请求上下文包装为 `context.WithTimeout`，并在超时后返回 `408 Request Timeout`（仅当处理器未写响应时）。

实现方式：

- 为当前请求派生带超时的 `Context`
- 在 goroutine 中执行 `c.Next()`
- 同时监听完成、panic、超时事件

```go
r.Use(middleware.Timeout(2 * time.Second))
```

**注意**：它控制的是请求处理链，而不是底层 socket/read/write timeout；后者仍应通过 `Engine` 配置管理。

---

### Business

#### Idempotent

`Idempotent(opts ...IdempotentOption)` 用请求头 `Idempotency-Key` 作为默认幂等键，缓存首次响应，后续相同 key 直接重放缓存结果。

默认行为：

- 默认 TTL：`5m`
- 默认存储：`MemoryIdempotentStore`
- 默认 key 来源：`Idempotency-Key`
- 若命中缓存：直接返回此前的状态码与响应体

```go
r.POST("/payments",
    middleware.Idempotent(),
    func(c *gin.Context) {
        c.JSON(201, gin.H{"status": "created"})
    },
)
```

自定义 TTL / Store / Key / Skip 逻辑：

```go
r.POST("/orders",
    middleware.Idempotent(
        middleware.WithIdempotentTTL(10*time.Minute),
        middleware.WithIdempotentKeyFunc(func(c *gin.Context) string {
            return c.GetHeader("X-Order-Key")
        }),
        middleware.WithIdempotentSkipFunc(func(c *gin.Context) bool {
            return c.Query("dry_run") == "true"
        }),
    ),
    createOrder,
)
```

---

## Extensibility and chain helpers

### Interceptor

`Interceptor(config InterceptorConfig)` 同时支持：

- `OnRequest`: 进入业务前校验/改写
- `OnResponse`: 捕获响应体后再处理

请求拦截失败返回 `400`；响应处理失败返回 `500`。

```go
r.Use(middleware.Interceptor(middleware.InterceptorConfig{
    OnRequest: func(c *gin.Context) error {
        if c.GetHeader("X-App-ID") == "" {
            return errors.New("missing X-App-ID")
        }
        return nil
    },
    OnResponse: func(c *gin.Context, body []byte) ([]byte, error) {
        return bytes.ToUpper(body), nil
    },
}))
```

### Maybe

`Maybe(mw, maybeFn)` 在满足条件时执行目标中间件，否则直接跳过。

```go
r.Use(middleware.Maybe(middleware.Logger(), func(c *gin.Context) bool {
    return strings.HasPrefix(c.Request.URL.Path, "/debug")
}))
```

### Registry

`Registry` 用于集中注册、启停与排序中间件。内建注册项包括：

- `recovery`
- `request_id`
- `logger`
- `cors`
- `ratelimit`
- `timeout`
- `secure`
- `circuit_breaker`

默认启用：`recovery`、`request_id`、`logger`。

```go
reg := middleware.NewRegistry()
reg.Enable("cors", "secure")
reg.Disable("logger")

for _, mw := range reg.GetChain() {
    r.Use(mw)
}
```

---

## Chi middleware compatibility

### 兼容模型

框架对 Chi / 标准库风格中间件的兼容入口在 `router.go` 的 `Router.Use()`：

- `gin.HandlerFunc`
- `func(*gin.Context)`
- 增强型 `HandlerFunc`
- `func(http.Handler) http.Handler`（Chi 风格）

其中 `gin_compat.go` 导出了 `HTTPMiddleware` 类型别名，便于声明标准 HTTP middleware。

### 适配行为

Chi 中间件通过 `adaptHTTPMiddleware` 适配进 Gin 链时，框架会：

1. 构造一个包装的 `nextHandler`
2. 记录 Chi 中间件是否调用了 `next.ServeHTTP`
3. 若中间件已提前写响应，则自动 `Abort()`
4. 若中间件未调用 `next`，也自动 `Abort()`，避免 Gin 继续向下执行

这保证了 Chi 与 Gin 两种链模型在行为上的一致性。

### 推荐用法

```go
import chimw "github.com/go-chi/chi/v5/middleware"

r.Use(chimw.RequestID)
r.Use(chimw.Logger)
r.Use(chimw.Recoverer)
```

### 注意事项

- **安全**：只读请求、设置 header、记录日志，然后调用 `next`
- **谨慎**：若 Chi 中间件提前写响应，不应再调用 `next`
- **建议**：需要精细控制 JSON 响应或 `Abort()` 语义时，优先使用 Gin 风格中间件

### 当前目录内的 Chi 兼容/移植能力

| 中间件 | 说明 |
| --- | --- |
| `Throttle` / `ThrottleBacklog` | 并发请求节流与积压队列 |
| `RealIP` | 解析 `X-Forwarded-For` / `X-Real-IP` |
| `NoCache` | 禁用缓存响应头 |
| `URLFormat` | 解析 `.json` / `.xml` 等 URL 扩展 |
| `Sunset` | RFC 8594 API 废弃通知 |
| `RouteHeaders` | 按请求头模式路由中间件 |
| `ValidateParam` | 路由参数正则校验 |

示例：

```go
api := e.Router().Group("/api")
api.Use(middleware.RealIP())
api.Use(middleware.NoCache())
api.Use(middleware.Throttle(100))
api.Use(middleware.URLFormat())
```

---

## Usage examples for Chi-derived middleware

### Throttle

```go
r.Use(middleware.Throttle(100))

r.Use(middleware.ThrottleBacklog(100, 50, 30*time.Second))
```

### RealIP

```go
r.Use(middleware.RealIP())

r.GET("/whoami", func(c *gin.Context) {
    c.JSON(200, gin.H{"ip": middleware.GetRealIP(c)})
})
```

### NoCache

```go
r.Use(middleware.NoCache())
```

### URLFormat

```go
r.Use(middleware.URLFormat())
r.GET("/articles/*path", func(c *gin.Context) {
    switch middleware.GetURLFormat(c) {
    case "xml":
        c.XML(200, article)
    default:
        c.JSON(200, article)
    }
})
```

### Sunset

```go
r.Use(middleware.Sunset(
    time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
    "<https://api.example.com/v2>; rel=\"successor-version\"",
))
```

### RouteHeaders

```go
r.Use(middleware.RouteHeaders().
    Route("Origin", "https://app.example.com", middleware.CORS()).
    RouteDefault(middleware.NoCache()).
    Handler())
```

### ValidateParam

```go
r.GET("/users/:id",
    middleware.ValidateParam("id", middleware.PatternNumeric),
    getUser,
)
```

---

## Custom middleware creation guide

### 1. 直接实现 Gin middleware

适合纯 `gin.HandlerFunc` 场景。

```go
func AuditTrail() gin.HandlerFunc {
    return func(c *gin.Context) {
        startedAt := time.Now()
        c.Next()
        log.Printf("%s %s %v", c.Request.Method, c.Request.URL.Path, time.Since(startedAt))
    }
}

r.Use(AuditTrail())
```

### 2. 编写增强上下文 middleware

若使用框架的增强路由器，可直接传入 `func(*gin.Context)` 或框架 `HandlerFunc`；`Router.Use()` 会自动适配。

```go
router := e.Router()
router.Use(func(c *gin.Context) {
    c.Set("tenant_id", c.GetHeader("X-Tenant-ID"))
    c.Next()
})
```

### 3. 实现标准 HTTP / Chi middleware

适合复用现有 `net/http` 或 Chi 中间件资产。

```go
func HeaderAudit(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Audit", "on")
        next.ServeHTTP(w, r)
    })
}

router.Use(HeaderAudit)
```

### 4. 接入 Registry

若中间件需要被统一启停、排序、延迟构造，可注册到 `Registry`。

```go
reg := middleware.NewRegistry()
reg.Register(&middleware.Middleware{
    Name:        "audit",
    Description: "记录审计头",
    Factory:     AuditTrail,
    Order:       25,
    Enabled:     true,
})
```

**建议**：

- 无状态中间件优先工厂化，便于重复注册
- 需要后台清理 goroutine 的中间件应暴露可关闭的 store/资源句柄
- 若会提前写响应，请明确 `Abort()` 或停止调用 `next`

---

## Best practices

1. **默认顺序**：追踪 → 恢复 → 日志 → 安全 → 性能 → 业务
2. **签名校验优先**：`SignatureVerify` 应早于业务处理
3. **缓存与压缩配合**：先产生稳定响应，再决定是否缓存/压缩
4. **幂等只用于写请求**：尤其是支付、下单、回调确认
5. **超时不是万能止血**：仍需为下游依赖设置独立 timeout
6. **Chi 适配只用于兼容**：需要精细中断语义时，优先原生 Gin middleware

---

## Related files

- `middleware/interceptor.go`：请求/响应双向拦截
- `middleware/registry.go`：中间件注册、启停、排序
- `router.go`：`Router.Use()` 智能适配与 Chi middleware 桥接
- `gin_compat.go`：兼容导出与 `HTTPMiddleware` 类型别名
- `engine.go`：默认核心链注册入口
