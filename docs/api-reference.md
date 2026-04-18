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

常用配置入口位于：`options.go`

### Router

源码：`router.go`

关键类型与函数：

- `type HandlerFunc func(*Context)`
- `type Router struct`
- `func (r *Router) GET(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) POST(path string, handlers ...HandlerFunc) IRoutes`
- `func (r *Router) Handle(method, path string, handlers ...HandlerFunc) IRoutes`
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
- `func WrapMiddleware(h gin.HandlerFunc) HandlerFunc`

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

高频方法分组：

**参数与绑定**

- 与上游一致的单一来源取值：
  - `Param`
  - `Query`
  - `DefaultQuery`
  - `PostForm`
  - `DefaultPostForm`
- 项目增强的聚合取值：
  - `Input`
  - `ParamInt` / `ParamInt64` / `ParamFloat` / `ParamBool`
  - `ParamIntE` / `ParamInt64E` / `ParamFloatE` / `ParamBoolE`
  - `ParamTime`
- `BindAndValidate`
- `BindJSONOrAbort`
- `BindQueryOrAbort`
- `ParsePagination`
- `ParseCursorPagination`

说明：

- `Param(key string) string` 仅表示路径参数，行为与上游 `gin.Context.Param` 一致。
- `Input(key, def...)` 会按“路径参数 -> query -> form”的顺序统一取值。
- `ParamInt/ParamBool` 这类增强 helper 也基于 `Input(...)`，因此语义是“聚合输入解析”，而不是“只解析路径参数”。

**成功响应**

- `Success`
- `SuccessWithMessage`
- `Created`
- `Accepted`
- `NoContent`
- `Paginated`
- `CursorPaginated`

**错误响应**

- `BadRequest`
- `Unauthorized`
- `Forbidden`
- `NotFound`
- `Conflict`
- `ValidationError`
- `InternalError`
- `TooManyRequests`
- `ServiceUnavailable`
- `GatewayTimeout`
- `Problem`
- `WriteProblem`
- `ValidationProblem`

**文件与导出**

- `SaveFile`
- `SaveFiles`
- `ValidateFile`
- `StreamFile`
- `StreamFileInline`
- `ExportExcel`
- `ExportCSV`
- `StreamExcel`
- `StreamCSV`

**其他高频能力**

- `Auth()`
- `UpgradeWebSocket(...)`
- `Logger()`
- `Cache()`
- `RequestID()`
- `GetBearerToken()`
- `IsSecure()`
- `TraceID()`
- `SpanID()`
- `RawBody()`
- `WebhookEventID()`
- `WebhookSignature()`
- `WebhookTimestamp()`

### Response / Pagination / Upload

源码：

- `response.go`
- `pagination.go`
- `upload.go`

关键类型：

- `type Response struct`
- `type Pagination struct`
- `type ErrorResponse struct`
- `type PaginationParams struct`
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
- `func NewManager(...)`
- `func NewStpLogic(...)`
- `func AuthRequired(...) gin.HandlerFunc`

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
- `Throttle(...)`
- `ValidateParam(...)`
- `NoCache()`

## pkg 子模块

按需查看：

- `pkg/cache/README.md`
- `pkg/export/README.md`
- `pkg/lifecycle/README.md`
- `pkg/logger/README.md`
- `pkg/mail/README.md`
- `pkg/mask/README.md`
- `pkg/routes/README.md`
- `pkg/sms/README.md`
- `pkg/validator/README.md`
- `pkg/websocket/README.md`

## 示例与测试

如果想确认真实用法，优先看：

- `examples/basic/main.go`
- `examples/advanced/main.go`
- `examples/auto-register/main.go`
- `examples/cache-demo/main.go`
- `examples/swagger-demo/main.go`
- `*_test.go`

## 说明

旧版超长 API 汇编已经移除，因为它容易与当前源码漂移。

如果你需要某个具体方法，请直接使用：

```bash
go doc github.com/darkit/gin.Context.<MethodName>
```
