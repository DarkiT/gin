# API 参考文档

本文档提供 `github.com/darkit/gin` 的**精简 API 地图**。

目标不是列出所有导出项，而是帮你快速定位：

- 核心类型在哪
- 常用方法在哪
- 哪份源码/文档才是最终权威

## 权威来源

优先级如下：

1. 源码注释与测试
2. `go doc github.com/darkit/gin...`
3. 本文档

常用命令：

```bash
go doc github.com/darkit/gin
go doc github.com/darkit/gin.Context
go doc github.com/darkit/gin.Engine
go doc github.com/darkit/gin.Router
go doc github.com/darkit/gin/auth
```

与上游 `gin-gonic/gin` 的公开面对齐说明，见 `docs/gin-upstream-compat.md`。

## 核心包

### Engine

源码：`engine.go`

关键类型与函数：

- `type Engine struct`
- `func New(opts ...OptionFunc) *Engine`
- `func Default(opts ...OptionFunc) *Engine`
- `func (e *Engine) Router() *Router`
- `func (e *Engine) RegexRouter() *RegexRouter`（高级接口）
- `func (e *Engine) Run(addr ...string) error`
- `func (e *Engine) Shutdown(ctx context.Context) error`
- `func (e *Engine) OnStart(hooks ...lifecycle.Hook) *Engine`
- `func (e *Engine) OnShutdown(hooks ...lifecycle.Hook) *Engine`
- `func (e *Engine) OnStopped(hooks ...lifecycle.Hook) *Engine`
- `func (e *Engine) Mailer() (*mail.Mailer, error)`
- `func (e *Engine) SMS() (*sms.Service, error)`
- `func (e *Engine) WithLogger(l logger.Logger) *Engine`
- `func (e *Engine) WithCache(c cache.Cache) *Engine`

常用配置入口位于：`options.go`

### Router

源码：`router.go`

关键类型与函数：

- `type HandlerFunc func(*Context)`
- `type Router struct`
- `func (r *Router) GET(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) POST(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) PUT(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) PATCH(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) DELETE(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) HEAD(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) OPTIONS(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) Any(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) Handle(method, path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) GetHead(path string, handler HandlerFunc) IRoutes`（同时注册 GET + HEAD）
- `func (r *Router) Use(handlers ...HandlerFunc) IRoutes`
- `func (r *Router) UseAny(handlers ...any) IRoutes`
- `func (r *Router) Group(path string, handlers ...HandlerFunc) *Router`
- `func (r *Router) Resource(name string, ctrl ResourceController, opts ...ResourceOption)`
- `func (r *Router) CRUD(name string, ctrl ResourceController)`
- `func (r *Router) Version(v string) *Router`
- `func (r *Router) VersionedAPI(v string, setup func(*Router))`
- `func (r *Router) HealthCheck(path ...string)`
- `func (r *Router) Liveness(path ...string)`
- `func (r *Router) Readiness(checks ...Probe)`
- `func (r *Router) Startup(checks ...Probe)`
- `func (r *Router) GETDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo`
- `func (r *Router) POSTDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo`
- `func (r *Router) PUTDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo`
- `func (r *Router) PATCHDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo`
- `func (r *Router) DELETEDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo`
- `func (r *Router) Resource(name string, ctrl ResourceController, opts ...ResourceOption)`
- `func (r *Router) AutoRegister(controllers ...any)`
- `func (r *Router) EmbedFS(fs embed.FS, root string, path string)`
- `func (r *Router) EmbedFile(fs embed.FS, path string)`
- `func WrapMiddleware(h gin.HandlerFunc) HandlerFunc`
- `func AdaptHandler(h HandlerFunc) gin.HandlerFunc`

#### SwaggerRouteInfo 链式方法

| 方法 | 功能 |
|---|---|
| `Doc(summary)` | 接口摘要 |
| `Description(desc)` | 详细描述 |
| `Param(name, in, pType, desc, required)` | 参数声明 |
| `ParamModel(name, in, model, desc, required)` | 模型参数 |
| `Response(code, desc, models...)` | 响应声明 |
| `ResponseExample(code, desc, example)` | 带示例的响应 |
| `ResponseExamples(code, desc, examples)` | 多示例响应 |
| `Tag(tags...)` | 标签分组 |
| `Deprecated()` | 标记废弃 |
| `Security(security)` | 安全声明 |
| `OperationID(id)` | 操作 ID |
| `RequestExample(example)` | 请求示例 |
| `RequestExamples(examples)` | 多请求示例 |
| `ProblemResponse(code, desc)` | RFC 9457 错误响应 |
| `DefaultError(errors...)` | 默认错误声明 |
| `DefaultErrors(errors)` | 批量默认错误声明 |

### RegexRouter

源码：`regex_router.go`

定位：

- 高级 regex 控制接口，不是常规注册首选入口
- 默认应优先通过 `Engine/Router` 的 `GET/POST/Match/Any` 直接注册 chi 风格 pattern
- 当需要 `Match()`、`Handler()`、`NotFound()`、纯 regex `Group/Use` 时再使用

关键类型与函数：

- `type RegexRouter struct`
- `func NewRegexRouter() *RegexRouter`
- `func (r *RegexRouter) GET(pattern string, handlers ...HandlerFunc)`
- `func (r *RegexRouter) POST(pattern string, handlers ...HandlerFunc)`
- `func (r *RegexRouter) Match(method, path string) (HandlerFunc, map[string]string, bool)`

### Context

源码：

- `context.go`
- `context_upload.go`
- `context_export.go`
- `context_image.go`
- `context_mask.go`
- `context_auth.go`
- `context_websocket.go`
- `context_stream.go`
- `context_trace.go`
- `context_problem.go`
- `context_cursor_pagination.go`
- `context_webhook_helpers.go`

**参数与绑定**

- 与上游一致的单一来源取值：
  - `Param`
  - `Query`
  - `DefaultQuery`
  - `PostForm`
  - `DefaultPostForm`
- 项目增强的聚合取值：
  - `Input(key, def...)` —— 按"路径参数 -> query -> form"统一取值
  - `ParamInt` / `ParamInt64` / `ParamFloat` / `ParamBool` —— 类型化取值（不返回错误）
  - `ParamIntE` / `ParamInt64E` / `ParamFloatE` / `ParamBoolE` —— 类型化取值（区分 `ErrParamNotFound` 与 `ErrParamInvalid`）
  - `MustParamInt` / `MustParamInt64` / `MustParamFloat` / `MustParamBool` —— 不存在时 panic
  - `ParamSlice` / `ParamIntSlice` —— 逗号分隔切片参数
  - `ParamTime` / `ParamDuration` —— 时间/时长参数
  - `RequireParams(keys...)` —— 检查必需参数
  - `RequireParamsOrAbort(keys...)` —— 参数校验失败自动 400 + Abort
- `BindAndValidate`
- `BindJSONOrAbort`
- `BindQueryOrAbort`
- `JSONOrAbort`
- `ParsePagination`
- `ParseCursorPagination(opts...)`

说明：

- `Param(key string) string` 仅表示路径参数，行为与上游 `gin.Context.Param` 一致。
- `Input(key, def...)` 会按"路径参数 -> query -> form"的顺序统一取值。
- `ParamInt/ParamBool` 这类增强 helper 也基于 `Input(...)`，因此语义是"聚合输入解析"，而不是"只解析路径参数"。

**成功响应**

- `Success(data)`
- `SuccessWithMessage(data, msg)`
- `Created(data)`
- `CreatedWithLocation(data, location)`
- `Accepted(data)`
- `NoContent()`
- `Paginated(data, page, perPage, total)`
- `CursorPaginated(data, info)`
- `OKIf(condition, data)`
- `OKMasked(data, opts...)` —— 脱敏后响应

**错误响应**

- `BadRequest(msg)`
- `Unauthorized(msg)`
- `Forbidden(msg)`
- `NotFound(msg)`
- `MethodNotAllowed(msg)`
- `Conflict(msg)`
- `Gone(msg)`
- `ValidationError(errors)`
- `TooManyRequests(msg...)`
- `InternalError(msg)`
- `ServiceUnavailable(msg)`
- `GatewayTimeout(msg)`
- `ErrorResponse(code, msg)`
- `Problem(status, typeURI, title, detail)` —— RFC 9457
- `WriteProblem(problem)` —— 写入 Problem Detail
- `AbortWithProblem(status, typeURI, title, detail)` —— Problem + Abort
- `ValidationProblem(errors, detail...)` —— 校验错误 Problem
- `PaginatedMasked(data, page, perPage, total, opts...)` —— 脱敏分页响应

**流式响应**

- `Flush()`
- `BeginSSE()` —— 初始化 SSE 响应头
- `SSE(event, data)` —— 输出 SSE 消息
- `SSEComment(comment)` —— SSE 注释
- `SSEHeartbeat()` —— SSE 心跳
- `BeginNDJSON()` —— 初始化 NDJSON 流头
- `StreamNDJSON(data)` —— 输出 NDJSON 记录

**文件与导出**

- `SaveFile`
- `SaveFiles`
- `ValidateFile`
- `ToDir`
- `ToSubDir`
- `AsName`
- `NameBy`
- `StreamFile`
- `StreamFileInline`
- `ExportExcel`
- `ExportCSV`
- `StreamExcel`
- `StreamCSV`

**请求体与 Webhook**

- `RawBody()` —— 读取并缓存原始请求体
- `MustRawBody()` —— 原始请求体，失败 panic
- `RawBodyString()` —— 原始请求体字符串形式
- `WebhookEventID(headers...)`
- `WebhookSignature(headers...)`
- `WebhookTimestamp(headers...)`

**其他高频能力**

- `Auth()` —— 认证门面
- `Mailer()`
- `SMS()`
- `UpgradeWebSocket(userID, opts...)` —— WebSocket 升级
- `Logger()`
- `Cache()`
- `RequestID()` / `SetRequestID(id)`
- `GetBearerToken()`
- `GetBasicAuth()`
- `IsSecure()`
- `TraceID()`
- `SpanID()`
- `GetIP()`
- `GetUserAgent()`
- `IsAjax()`
- `IsJSON()` / `IsForm()` / `IsMultipart()`
- `IsWebSocket()`
- `IsGET` / `IsPOST` / `IsPUT` / `IsPATCH` / `IsDELETE` / `IsOPTIONS`
- `AcceptsJSON()` / `AcceptsHTML()`
- `Copy()` —— 请求外安全副本
- `HasKey(key)`
- `MustGet(key)` —— 断言式取值
- `GetStringOr` / `GetIntOr` / `GetHeaderOr` / `GetCookieOr` —— 带默认值取值
- `SetSecureCookie(name, value, maxAge)`

### Response / Pagination / Upload

源码：

- `response.go`
- `pagination.go`
- `upload.go`

关键类型：

- `type Response struct` —— 标准成功响应（Code / Message / Data / RequestID / Timestamp）
- `type PaginatedResponse struct` —— 分页响应
- `type Pagination struct` —— 分页元信息（Page / PerPage / Total / TotalPages）
- `type ErrorResponse struct` —— 错误响应（支持字段级校验错误）
- `type ValidationError struct` —— 字段级校验错误
- `type PaginationParams struct`
- `type CursorPaginationParams struct`
- `type CursorPageInfo struct`
- `type UploadConfig struct`
- `type UploadResult struct`

## auth 子系统

目录：`auth/`

建议入口：

- `auth/README.md`
- `auth/DESIGN.md`
- `auth/API.md`

高频能力：

- `type AuthContext`
- `type Manager`
- `type Storage`
- `type TokenStyle`（9 种：UUID / Simple / Random32 / Random64 / Random128 / JWT / Hash / Timestamp / Tik）
- `func NewManager(storage, cfg)`
- `func NewMemoryStorage() Storage`
- `func NewRedisStorage(redisURL string) (Storage, error)`
- `func NewKVStorage(store storage.Store) (Storage, error)`
- `func NewRelaxedKVStorage(store storage.Store) Storage`
- `func NewAtomicKVStorage(store kv.AtomicStore) Storage`
- `func NewStpLogic(mgr) *StpLogic`
- `func NewMiddlewareBuilder(mgr) *MiddlewareBuilder`

中间件：

- `AuthRequired(mgr) gin.HandlerFunc`
- `RoleRequired(mgr, roles...) gin.HandlerFunc`
- `RoleRequiredAll(mgr, roles...) gin.HandlerFunc`
- `PermRequired(mgr, permissions...) gin.HandlerFunc`
- `PermRequiredAll(mgr, permissions...) gin.HandlerFunc`
- `DisableCheck(mgr) gin.HandlerFunc`

`NewKVStorage` 是通用 KV 后端进入 auth/session 主链的严格入口；底层必须支持 TTL 与 key 扫描能力。基础 `storage.Store` 更适合先接入 `pkg/cache`。

## middleware 包

目录：`middleware/`

建议入口：

- `middleware/README.md`
- `middleware/DESIGN.md`

高频中间件：

- `RequestID()`
- `Recovery()`
- `Logger()`
- `CORS(...)`
- `RealIP()`
- `RealIPStrict()`
- `Timeout(d)`
- `Secure()`
- `RateLimit(...)`
- `RateLimitByUser(...)`
- `RateLimitByKey(...)`
- `RateLimitTier(...)`
- `Compress(...)`
- `Cache(...)`
- `CacheIf(...)`
- `ETag()`
- `Idempotent(...)`
- `OTel(service, opts...)`
- `Throttle(...)` / `ThrottleBacklog(...)` / `ThrottleWithOpts(...)`
- `Signature(secret, opts...)`
- `ValidateParam(...)`
- `NoCache()`
- `Sunset(at, links...)`
- `RouteHeaders()`
- `URLFormat()`
- `CircuitBreaker(...)`
- `Interceptor(...)`
- `Maybe(mw, fn)`
- `WrapHeadHandler()`

## pkg 子模块

按需查看：

- `pkg/cache/README.md`
- `pkg/storage/README.md`
- `pkg/export/README.md`
- `pkg/lifecycle/README.md`
- `pkg/logger/README.md`
- `pkg/mail/README.md`
- `pkg/mask/README.md`
- `pkg/routes/README.md`
- `pkg/sms/README.md`
- `pkg/validator/README.md`
- `pkg/websocket/README.md`
- `pkg/static/README.md`
- `pkg/swagger/README.md`
- `pkg/image/README.md`
- `pkg/retry/README.md`
- `pkg/concurrency/README.md`
- `pkg/diagnostic/README.md`
- `pkg/circuitbreaker/README.md`

## 示例与测试

如果想确认真实用法，优先看：

- `examples/basic/main.go`
- `examples/advanced/main.go`
- `examples/auto-register/main.go`
- `examples/cache-demo/main.go`
- `examples/swagger-demo/main.go`
- `examples/streaming/main.go`
- `*_test.go`

## 说明

旧版超长 API 汇编已经移除，因为它容易与当前源码漂移。

如果你需要某个具体方法，请直接使用：

```bash
go doc github.com/darkit/gin.Context.<MethodName>
```
