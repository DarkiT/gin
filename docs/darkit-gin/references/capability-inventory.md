# Capability Inventory

这份文件用于先回答一个最实际的问题：

“当前 `github.com/darkit/gin` 这套代码，真实对外提供了哪些能力？”

它不展开实现，只做基于当前代码导出面的能力盘点，并顺手标出推荐入口和不要误说的边界。

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
- logger / cache 注入
- 上传配置
- mail / sms 注入
- auth 初始化
- Swagger/OpenAPI 初始化
- 开发 / 生产预设

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

## 中间件资产

当前代码中高频且值得在 Skill 里显式讲到的有：

- `RequestID`
- `Recovery`
- `Logger`
- `CORS`
- `Secure`
- `RealIP`
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
