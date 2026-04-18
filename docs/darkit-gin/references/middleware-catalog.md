# Middleware Catalog

这份文件提供“上层接入时怎么选中间件、怎么挂载”的速查视图。

## 目录

- 默认链路
- 中间件怎么挂
- 常用中间件分类
- 常见组合
- 模板
- 常见误区
- 排障入口

## 默认链路

`gin.Default()` 默认包含：

- `middleware.RequestID()`
- `middleware.Recovery()`
- `middleware.Logger()`

## 中间件怎么挂

### 推荐默认写法

```go
e.UseAny(
    middleware.CORS(),
    middleware.RealIP(),
    middleware.Timeout(5*time.Second),
)
```

说明：

- 大多数 `middleware/*` 返回的是 `gin.HandlerFunc`
- 混挂时用 `UseAny(...)`
- 只有当中间件本身已经是增强 `HandlerFunc` 时，才直接用 `Use(...)`

### OTel 是个例外

`middleware.OTel(service, opts...)` 返回的是增强 `HandlerFunc`，因此既可以：

```go
e.Use(middleware.OTel("my-service"))
```

也可以和其他 middleware 一起统一走：

```go
e.UseAny(
    middleware.OTel("my-service"),
    middleware.CORS(),
)
```

## 常用中间件分类

### 基础运行时

- `Logger()`
- `Recovery()`
- `RequestID()`
- `RealIP()`

### Web 安全与协议

- `CORS()`
- `Secure()`
- `Cache(...)`
- `CacheIf(...)`
- `ETag()`
- `NoCache()`
- `RouteHeaders()`
- `URLFormat()`
- `URLFormatWithFormats(...)`

### 流量治理

- `RateLimit(...)`
- `RateLimitByUser(...)`
- `RateLimitByKey(...)`
- `RateLimitTier(...)`
- `Throttle(...)`
- `ThrottleBacklog(...)`
- `Timeout(...)`
- `CircuitBreaker(...)`

### 一致性与请求保护

- `Idempotent(...)`
- `SignatureVerify(...)`
- `ValidateParam(...)`
- `ValidateParamFunc(...)`
- `Interceptor(...)`
- `Maybe(...)`

### 生命周期与 API 管理

- `Sunset(...)`

### 性能与观测

- `Compress(...)`
- `OTel(service, opts...)`

## 常见组合

### 通用 API

- `RequestID`
- `Recovery`
- `Logger`
- `CORS`
- `RealIP`

### 对外公共接口

在通用 API 组合上追加：

- `RateLimit`
- `Timeout`
- `Secure`

### 写接口 / webhook / 幂等场景

优先考虑：

- `Idempotent`
- `SignatureVerify`
- `Timeout`

### 可观测性优先的服务

优先考虑：

- `RequestID`
- `Logger`
- `OTel`

## 模板

- `../assets/examples/middleware_chain.go.tmpl`

## 常见误区

- 直接用 `Use(...)` 塞 gin middleware
- 把 `SignatureVerify` 记成 `Signature`
- 在可能超时的大文件导出接口上盲目套很短的 `Timeout`
- 没配可信代理却依赖 `RealIP` 结果

## 排障入口

- 中间件链中断：`./troubleshooting.md`
- 路由与中间件组合：`./router-patterns.md`
