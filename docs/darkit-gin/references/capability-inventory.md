# Capability Inventory

这份文件用于让上层应用调用方先回答一个实际问题：

“我在业务项目里可以用 `github.com/darkit/gin` 的哪些能力，推荐从哪个入口接？”

它不展开实现，只做对外能力盘点，并标出推荐入口、生产边界和不要误说的地方。

## 目录

- 核心服务与运行时
- 路由与 API 组织
- handler 与响应能力
- 文件、图片、导出、WebSocket
- 现代 API 能力
- 静态资源与前端交付
- 认证与安全
- 中间件资产
- `pkg/*` 可复用能力
- 不要虚构的边界

## 核心服务与运行时

根包真实提供：

- `gin.New(opts...)`
- `gin.Default(opts...)`
- `Engine.Run(...)`
- `Engine.Shutdown(...)`
- `Engine.OnStart(...)`
- `Engine.OnShutdown(...)`
- `Engine.OnStopped(...)`
- `Engine.WithLogger(...)`
- `Engine.WithCache(...)`

可配置项真实覆盖：

- 地址、读写超时、优雅停机
- 可信代理
- logger / cache 注入和生命周期托管
- `pkg/storage` / Fiber storage 生态适配
- 上传配置
- mail / sms 注入
- auth 初始化
- Swagger/OpenAPI 初始化
- 开发 / 生产预设

## Gin 上游迁移视角

调用方项目从 `gin-gonic/gin` 迁移时，优先把 `darkit/gin` 当增强兼容层使用：

```go
import gin "github.com/darkit/gin"
```

调用方应知道的边界：

- 常见 Gin 心智仍成立：`Engine`、`Router`、`Context`、middleware 链、`gin.H`。
- `Context` / `Engine` / `HandlerFunc` / `OptionFunc` 是增强 wrapper，不保证与上游类型完全同一 identity。
- 低风险迁移先保持 `c.JSON`、`c.Query`、`c.Param` 等 Gin-compatible 写法，再逐步采用 `c.Success`、`c.Problem`、`Router()`、provider 注入。
- 公开面对齐门禁 `internal/tools/gincompat` 只属于 `github.com/darkit/gin` 本仓维护流程；不要在普通调用方项目中运行或依赖它。

## 路由与 API 组织

### 常规路由

- `GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS / Any / Match`
- `Group(...)`
- `Version(...)`
- `VersionedAPI(...)`

### 资源路由

- `Resource(...)`
- `CRUD(...)`

### 自动注册

- `AutoRegister(...)`
- `WithPrefix(...)`
- `WithMiddleware(...)`
- `WithRegexPattern(...)`

### regex 路由

真实支持：

- 在普通路由方法里直接写 chi 风格 pattern
- `Engine.RegexRouter()` 作为高级入口
- regex 路由进入 `Engine.Routes()` 和 Swagger 视图

### 探针

- `HealthCheck(...)`
- `Liveness(...)`
- `Readiness(...)`
- `Startup(...)`
- `NamedProbe(...)`

### OpenAPI 路由文档

- `GETDoc / POSTDoc / PUTDoc / PATCHDoc / DELETEDoc / HEADDoc / OPTIONSDoc`
- `LastRouteDoc()`
- `OperationID(...)`
- `RequestExample(...)` / `RequestExamples(...)`
- `ResponseExample(...)` / `ResponseExamples(...)`
- `ProblemResponse(...)`
- `DefaultError(...)` / `DefaultErrors(...)`

## handler 与响应能力

### 参数与绑定

- 上游兼容：`Param / Query / DefaultQuery / PostForm / DefaultPostForm`
- 增强聚合：`Input`
- 聚合解析：`ParamInt / ParamInt64 / ParamFloat / ParamBool`
- 带错误版本：`ParamIntE / ParamInt64E / ParamFloatE / ParamBoolE`
- 其它：`ParamSlice / ParamIntSlice / ParamTime / ParamDuration`
- 绑定：`BindAndValidate / BindJSONOrAbort / BindQueryOrAbort / JSONOrAbort`

### 标准响应

- `Success / SuccessWithMessage / Created / CreatedWithLocation / Accepted / NoContent`
- `Paginated`
- `CursorPaginated`

### 标准错误

- `BadRequest / Unauthorized / Forbidden / NotFound / Conflict`
- `ValidationError / InternalError / MethodNotAllowed / TooManyRequests`
- `ServiceUnavailable / GatewayTimeout / Gone`
- `ErrorResponse`

### Problem Details

- `WriteProblem`
- `Problem`
- `AbortWithProblem`
- `ValidationProblem`

### 请求与请求态辅助

- `RequestID / GetIP / GetUserAgent / GetBearerToken / GetBasicAuth`
- `TraceID / SpanID`
- `AcceptsJSON / AcceptsHTML / AutoNegotiate`
- `SetSecureCookie / GetCookieOr / DeleteCookie / SetCookieWithOptions`

## 文件、图片、导出、WebSocket

### 上传 / 下载

- `SaveFile`
- `SaveFiles`
- `ValidateFile`
- `StreamFile`
- `StreamFileInline`

### 图片处理

- `SaveImage`
- `ProcessImages`

### 导出

- `ExportExcel`
- `StreamExcel`
- `ExportCSV`
- `StreamCSV`

### 脱敏

- `OKMasked`
- `PaginatedMasked`

### WebSocket

- `UpgradeWebSocket(...)`

## 现代 API 能力

### 流式

- `BeginSSE`
- `SSE`
- `SSEComment`
- `SSEHeartbeat`
- `BeginNDJSON`
- `StreamNDJSON`

### webhook helper

- `RawBody`
- `MustRawBody`
- `RawBodyString`
- `WebhookEventID`
- `WebhookSignature`
- `WebhookTimestamp`

### 游标分页

- `ParseCursorPagination`
- `CursorPaginated`
- `WithDefaultCursorLimit`
- `WithMaxCursorLimit`

### OTel 读取

- `middleware.OTel(...)`
- `c.TraceID()`
- `c.SpanID()`

## 静态资源与前端交付

### 直接路由注册

- `Static`
- `StaticFS`
- `StaticFile`
- `StaticFileFS`
- `EmbedFS`
- `EmbedFile`

### 受控静态挂载

- `Assets / AssetsFS / AssetsZip / AssetsEmbeddedZip`
- `Site / SiteFS / SiteZip / SiteEmbeddedZip`
- `FallbackSite / FallbackSiteFS / FallbackSiteZip / FallbackSiteEmbeddedZip`

### `pkg/static`

真实提供：

- `NewAssetsService`
- `NewSiteService`
- `NewZipFileSystem`
- `NewEmbeddedZipFS`
- `NewZipFSConfig`
- `WithHistoryFallback`
- `WithoutHistoryFallback`
- `WithNotFoundFile`
- `WithIndexFile`
- `WithSubPaths`
- `WithPassword`
- `WithHotReload`

## 认证与安全

### auth 接入

- `gin.WithAuth(auth.AuthConfig{...})`
- `c.Auth()`

### 请求级常见操作

- `CheckLogin`
- `Login`
- `LoginID`
- `Logout`
- `CheckAnyPermission`
- `CheckRole`

### 安全 / 可靠性中间件

- `SignatureVerify`
- `Idempotent`
- `RateLimit`
- `Throttle`
- `Timeout`
- `CircuitBreaker`

当前安全边界：

- `middleware.Cache` 默认跳过认证态请求、私有响应、`Set-Cookie` 响应，并按 `Vary` 请求 Header 隔离 key
- `middleware.Idempotent` 默认 key 纳入 method + request path + `Idempotency-Key` + namespace，默认 namespace 取 `user_id`（鉴权主体，防他人凭 key 命中你的缓存）；并发同 key 处理期间返回 `409`，失败/abort 自动释放占位；跨租户/自定义主体用 `WithIdempotentNamespaceFunc(...)`
- auth `Login` 多步写入失败会做 best-effort rollback，避免 token/account/session 半登录状态残留

## 中间件资产

当前代码中高频且值得在 Skill 里显式讲到的有：

- `RequestID`
- `Recovery`
- `Logger`
- `CORS`
- `Secure`
- `RealIP`
- `RealIPStrict`
- `Timeout`
- `RateLimit`
- `RateLimitByUser`
- `RateLimitByKey`
- `RateLimitTier`
- `Throttle`
- `ThrottleBacklog`
- `Idempotent`
- `SignatureVerify`
- `Compress`
- `NoCache`
- `Cache`
- `CacheIf`
- `ETag`
- `RouteHeaders`
- `URLFormat`
- `URLFormatWithFormats`
- `ValidateParam`
- `ValidateParamFunc`
- `Maybe`
- `Interceptor`
- `Sunset`
- `OTel`

## `pkg/*` 可复用能力

除根包直接增强外，当前项目还真实包含这些子包能力：

- `pkg/static`
- `pkg/swagger`
- `pkg/routes`
- `pkg/cache`
- `pkg/storage`
- `pkg/lifecycle`
- `pkg/logger`
- `pkg/mail`
- `pkg/sms`
- `pkg/mask`
- `pkg/validator`
- `pkg/websocket`
- `pkg/export`
- `pkg/image`
- `pkg/retry`
- `pkg/concurrency`
- `pkg/circuitbreaker`
- `pkg/diagnostic`

### cache / storage 重点入口

- `cache.NewMemory(...)`：TTL、LRU、批量、原子计数、统计、并发 `GetOrSet`
- `cache.NewStorageCache(store)`：把 `pkg/storage.Store` 接成 `cache.Cache`
- `cache.NewFiberStorage(raw)`：一行式复用 Fiber storage 生态后端
- `fiberstore.New(raw)` / `fiberstore.NewWithConn[T](raw)`：结构兼容适配 Fiber storage
- `storage.Store`：最小字节型 KV，miss 返回 `nil, nil`
- `storage.TTLStore` / `storage.KeyScanner`：auth/session 这类强语义场景才需要的可选能力

## 不要虚构的边界

在当前代码里，不要把这个框架描述成已经内建了这些不存在或不完整的东西：

- GraphQL / Federation
- gRPC 网关框架
- 内建任务队列或工作流引擎
- Passkeys / WebAuthn 整套能力
- 自研 tracing backend 或 metrics backend
- 完整前端构建工具链

同样也不要把现有能力说得比实际更大：

- `Assets*` / `Site*` / `FallbackSite*` 是受控静态挂载，不是普通 catch-all 路由
- `middleware.OTel(...)` 只是官方 `otelgin` 的轻封装，不是完整观测平台
- `Problem Details` 是标准错误响应能力，不等于完整 API 规范治理系统
- `webhook helper` 提供读取与提取能力，不等于内建供应商 SDK
- `pkg/storage` 是适配抽象，不内置 Redis/etcd/S3/Badger/Bbolt 具体 driver
- Fiber storage 基础接口可直接用于 cache，但不是完整 auth/session 存储能力
