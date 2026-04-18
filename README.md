# Darkit/GIN

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

`darkit/gin` 是一个基于 `gin-gonic/gin` 的增强版 Go Web 框架。它保留 Gin 的高性能与生态兼容性，在其上增加了增强型 `Context`、可组合的 `Engine` 配置、认证子系统、丰富中间件、Chi 风格正则路由、自动注册路由，以及一组可直接复用的基础能力包。

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [架构概览](#架构概览)
- [配置说明](#配置说明)
- [路由组织](#路由组织)
- [中间件生态](#中间件生态)
- [认证子系统](#认证子系统)
- [工具能力包](#工具能力包)
- [API 文档](#api-文档)
- [性能基准](#性能基准)
- [与 Gin 的关系](#与-gin-的关系)
- [开发建议](#开发建议)
- [许可证](#许可证)

## 项目简介

`darkit/gin` 适合希望继续使用 Gin 编程模型，但又希望获得更多"开箱即用"能力的项目：

- **兼容 Gin 模型**：核心入口仍然是 `Engine`、`Router`、`Context`
- **增强 API 体验**：通过扩展 `Context` 与 `Router`，减少样板代码
- **面向生产场景**：内置认证、缓存、日志、优雅停机、限流、签名校验等能力
- **强调渐进式采用**：可以只使用局部特性，不需要一次接入全部子模块

### 模块结构

```
github.com/darkit/gin
├── engine.go            # Engine 聚合与运行入口
├── context.go           # 核心增强 Context
├── context_*.go         # Context 的分能力扩展
├── router.go            # Router 增强
├── regex_router.go      # Chi 风格正则路由
├── auto_register.go     # 控制器自动注册
├── options.go           # OptionFunc 配置模式
├── binding/             # 绑定类型导出
├── auth/                # 认证子系统
├── middleware/          # 中间件生态 (30+)
├── pkg/                 # 基础能力工具包
│   ├── cache/           # 缓存抽象与实现
│   ├── circuitbreaker/  # 熔断控制
│   ├── concurrency/     # 并发工具
│   ├── diagnostic/      # 诊断辅助
│   ├── export/          # 导出能力
│   ├── image/           # 图片处理
│   ├── lifecycle/       # 生命周期管理
│   ├── logger/          # 日志抽象
│   ├── mail/            # 邮件发送
│   ├── mask/            # 数据脱敏
│   ├── retry/           # 重试工具
│   ├── routes/          # 路由辅助
│   ├── sms/             # 短信能力
│   ├── static/          # 静态资源
│   ├── swagger/         # Swagger/OpenAPI
│   ├── validator/       # 校验辅助
│   └── websocket/       # WebSocket 能力
├── docs/                # 参考文档
└── examples/            # 示例代码
```

## 核心特性

### 增强型 Engine

`engine.go` 与 `options.go` 提供以下核心能力：

- `New(opts ...OptionFunc)`：创建增强引擎
- `Default(opts ...OptionFunc)`：创建默认引擎，自动挂载 `RequestID`、`Recovery`、`Logger` 中间件
- 内置默认组件：
  - `logger.NewNoop()` - 空日志器
  - `cache.NewMemoryCache()` - 内存缓存
  - `lifecycle.NewManager()` - 生命周期管理器
  - `middleware.NewRegistry()` - 中间件注册表
- 支持生命周期 Hook：`OnStart()`、`OnShutdown()`、`OnStopped()`
- 通过 `sync.Pool` 复用增强型 `Context`

### 增强型 Context

`context.go` 提供丰富的请求/响应处理能力：

#### 参数获取

```go
// 与上游 gin 一致的单一来源取值
id := c.Param("id")
name := c.Query("name")
email := c.PostForm("email")
pageText := c.DefaultQuery("page", "1")
status := c.DefaultPostForm("status", "draft")

// 本项目增强的聚合取值：按 路径参数 -> query -> form 的顺序读取
keyword := c.Input("keyword", "")
page := c.ParamInt("page", 1)
debug := c.ParamBool("debug", false)

// 带错误返回的聚合解析
id, err := c.ParamIntE("id")
if err != nil {
    c.BadRequest("invalid id")
    return
}
```

说明：

- `c.Param("id")` 仅表示路径参数，行为与上游 `gin.Context.Param` 一致
- `c.Query(...)`、`c.PostForm(...)`、`c.DefaultQuery(...)`、`c.DefaultPostForm(...)` 也保持上游用法
- `c.Input(key, def...)` 是本项目增强入口，用于统一读取路径参数、query 和 form
- `c.ParamInt/ParamInt64/ParamFloat/ParamBool` 这类增强 helper 内部同样基于 `Input(...)`，语义是“聚合输入解析”，不是“仅路径参数解析”

#### 标准化响应

```go
// 成功响应
c.Success(data)              // 200 OK
c.Created(data)              // 201 Created
c.Accepted(data)             // 202 Accepted
c.NoContent()                // 204 No Content

// 错误响应
c.BadRequest("message")              // 400
c.Unauthorized("message")            // 401
c.Forbidden("message")               // 403
c.NotFound("message")                // 404
c.Conflict("message")                // 409
c.ValidationError(errors)            // 422
c.InternalError("message")          // 500
c.TooManyRequests()                 // 429
```

#### 分页支持

```go
// 解析分页参数
page, perPage := c.ParsePagination()

// 分页响应
c.Paginated(data, page, perPage, total)

// 游标分页
cursor, limit := c.ParseCursorPagination()
c.CursorPaginated(data, cursor, limit, hasMore)
```

#### 流式响应

```go
// Server-Sent Events
c.BeginSSE()
c.SSE(event, data)
c.SSEHeartbeat()

// NDJSON
c.BeginNDJSON()
c.StreamNDJSON(obj)
```

#### 请求信息

```go
ip := c.GetIP()
ua := c.GetUserAgent()
requestID := c.RequestID()
traceID := c.TraceID()
spanID := c.SpanID()
token := c.GetBearerToken()
```

### Router 增强

`router.go` 提供增强型路由能力：

```go
// 增强型处理器签名
type HandlerFunc func(*Context)

// REST 资源路由
r.Resource("users", userController)
r.CRUD("articles", articleController)

// 版本化 API
v1 := r.Version("1")
v1.GET("/users", listUsers)

// 健康检查
r.HealthCheck()
r.Liveness()
r.Readiness()

// 静态资源
r.Static("/static", "./public")
r.Assets("/assets", "./public")
r.Site("/app", "./dist")
e.FallbackSite("./dist")
r.StaticFile("/favicon.ico", "./public/favicon.ico")
r.EmbedFS("/static", embedFS, "dist")
```

说明：

- `Static*` / `Embed*` 与上游 Gin 一样，直接注册普通路由
- `Assets*` 用于“静态资源目录”语义，文件未命中时不会自动回退到站点首页
- `Site*` 用于“前端站点”语义，支持 `index.html`、history fallback 与自定义 `404.html`
- `FallbackSite*` 通过 `NoRoute` 受控兜底，不会抢占普通路由；优先级为“普通路由 -> regex 路由 -> 受控静态挂载 -> 用户 NoRoute”

### Chi 风格正则路由

支持 `/{param}` 和 `/{param:regex}` 模式的路由：

```go
// 直接在路由中使用 Chi 风格模式
r.GET("/users/{id:[0-9]+}", handler)
r.GET("/posts/{slug}", handler)
r.GET("/files/*path", handler)

// 高级控制
rx := app.RegexRouter()
rx.NotFound(func(c *Context) {
    c.JSON(404, gin.H{"error": "not found"})
})
```

### 自动注册路由

根据控制器方法名自动推断 HTTP 方法与路由路径：

```go
type UserController struct{}

func (u *UserController) GetUsers(c *gin.Context) { /* ... */ }
func (u *UserController) GetUser(c *gin.Context)  { /* ... */ }
func (u *UserController) CreateUser(c *gin.Context) { /* ... */ }
func (u *UserController) UpdateUser(c *gin.Context) { /* ... */ }
func (u *UserController) DeleteUser(c *gin.Context) { /* ... */ }

// 自动注册
r.AutoRegister(&UserController{}, gin.WithPrefix("/api"))
// GET    /api/users
// GET    /api/users/:id
// POST   /api/users
// PUT    /api/users/:id
// DELETE /api/users/:id
```

## 安装

### 环境要求

- Go `1.25+`

### 安装命令

```bash
go get github.com/darkit/gin@latest
```

## 快速开始

### 最小可运行示例

```go
package main

import (
	"log"

	gin "github.com/darkit/gin"
)

func main() {
	app := gin.Default()
	r := app.Router()

	r.GET("/ping", func(c *gin.Context) {
		c.Success(gin.H{
			"message":    "pong",
			"request_id": c.RequestID(),
		})
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
```

### 带配置的完整示例

```go
package main

import (
	"log"
	"time"

	gin "github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
)

func main() {
	app := gin.New(
		gin.WithAddr(":9090"),
		gin.WithReadTimeout(10*time.Second),
		gin.WithWriteTimeout(10*time.Second),
		gin.WithGracefulShutdown(15*time.Second),
		gin.Production(),
	)

	r := app.Router()
	r.Use(
		middleware.CORS(),
		middleware.Secure(),
	)

	v1 := r.Version("1")
	v1.HealthCheck()
	v1.GET("/users/:id", func(c *gin.Context) {
		id, err := c.ParamIntE("id")
		if err != nil {
			c.BadRequest("invalid id")
			return
		}
		c.Success(gin.H{"id": id})
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
```

## 架构概览

```
┌──────────────────────────────────────────────┐
│ Application Handlers / Controllers          │  <- 用户代码
├──────────────────────────────────────────────┤
│ Router / RegexRouter / AutoRegister         │  <- 路由层
├──────────────────────────────────────────────┤
│ Enhanced Context                            │  <- Context 层
├──────────────────────────────────────────────┤
│ Engine + OptionFunc + Middleware Registry   │  <- Engine 层
├──────────────────────────────────────────────┤
│ auth/* + middleware/* + pkg/*               │  <- 能力层
└──────────────────────────────────────────────┘
```

### 组件职责

| 层级       | 组件                                   | 职责                   |
| ---------- | -------------------------------------- | ---------------------- |
| 应用层     | Handlers                               | 业务逻辑处理           |
| 路由层     | Router, RegexRouter, AutoRegister      | 路由注册与匹配         |
| Context 层 | Enhanced Context                       | 参数解析、响应封装     |
| Engine 层  | Engine, OptionFunc, MiddlewareRegistry | 组件聚合、生命周期管理 |
| 能力层     | auth, middleware, pkg                  | 认证、中间件、基础设施 |

## 配置说明

### 基础配置

```go
app := gin.New(
	gin.WithAddr(":8080"),
	gin.WithReadTimeout(10*time.Second),
	gin.WithWriteTimeout(10*time.Second),
	gin.WithGracefulShutdown(30*time.Second),
)
```

### 环境预设

```go
// 开发环境
app := gin.New(gin.Development())

// 生产环境
app := gin.New(gin.Production())
```

### 代理与安全

```go
app := gin.New(
	gin.WithTrustedProxies([]string{"127.0.0.1", "10.0.0.0/8"}),
)
```

### 基础设施注入

```go
app := gin.New(
	gin.WithLogger(customLogger),
	gin.WithCache(customCache),
)
```

### 上传配置

```go
app := gin.New(
	gin.WithUploadDir("./uploads"),
	gin.WithMaxFileSize(10<<20),       // 10MB
	gin.WithMaxMultipartMemory(32<<20), // 32MB
	gin.WithAllowedExts("jpg", "png", "pdf"),
)
```

### Auth 配置

```go
app := gin.New(
	gin.WithAuth(auth.AuthConfig{
		Secret:     "your-secret-key",
		Expiry:     24 * time.Hour,
		TokenStyle: auth.TokenStyleJWT,
	}),
)
```

### Swagger 配置

```go
app := gin.New(
	gin.EnableSwagger(swagger.SwaggerConfig{
		Title:       "Example API",
		Description: "API Documentation",
		Version:     "v1.0.0",
	}),
)
```

## 路由组织

### 资源路由

```go
r.Resource("users", userController)
```

自动注册以下路由：

- `GET /users` - 列表
- `POST /users` - 创建
- `GET /users/:id` - 详情
- `PUT /users/:id` - 更新
- `PATCH /users/:id` - 部分更新
- `DELETE /users/:id` - 删除

### 正则路由

```go
// 直接使用 Chi 风格 pattern
app.GET("/orders/{id:[0-9]+}", func(c *gin.Context) {
	c.Success(gin.H{"order_id": c.Param("id")})
})
```

### 自动注册

```go
type UserController struct{}

func (u *UserController) GetProfile(c *gin.Context) {
	c.Success(gin.H{"ok": true})
}

func main() {
	app := gin.Default()
	r := app.Router()
	r.AutoRegister(&UserController{}, gin.WithPrefix("/api/users"))
}
```

## 中间件生态

框架提供 30+ 生产级中间件：

### 核心中间件

| 中间件      | 说明               |
| ----------- | ------------------ |
| `RequestID` | 请求 ID 生成与传递 |
| `Recovery`  | Panic 恢复         |
| `Logger`    | 访问日志           |
| `OTel`      | OpenTelemetry 接入 |

### 安全中间件

| 中间件            | 说明         |
| ----------------- | ------------ |
| `CORS`            | 跨域资源共享 |
| `Secure`          | 安全响应头   |
| `RateLimit`       | 访问限流     |
| `SignatureVerify` | 签名校验     |
| `Throttle`        | 并发节流     |

### 性能中间件

| 中间件     | 说明         |
| ---------- | ------------ |
| `Cache`    | 响应缓存     |
| `Compress` | 压缩传输     |
| `Timeout`  | 请求超时控制 |

### 业务中间件

| 中间件        | 说明          |
| ------------- | ------------- |
| `Idempotent`  | 幂等控制      |
| `Interceptor` | 请求/响应拦截 |

### Chi 兼容中间件

支持直接使用 Chi/标准库风格的中间件：

```go
import chimw "github.com/go-chi/chi/v5/middleware"

r.Use(chimw.RequestID)
r.Use(chimw.Logger)
r.Use(chimw.Recoverer)
```

详细文档请参考 [middleware/README.md](middleware/README.md)。

## 认证子系统

`auth` 模块提供完整的认证、授权、会话管理能力：

### 集成模式

#### 1. 引擎层级集成

```go
e := ginx.New(
	ginx.WithAuth(auth.AuthConfig{
		Secret:     "replace-me",
		Expiry:     24 * time.Hour,
		TokenStyle: auth.TokenStyleJWT,
	}),
)

e.POST("/login", func(c *ginx.Context) {
	token, err := c.Auth().Login("user-1001", "web")
	if err != nil {
		c.InternalError(err.Error())
		return
	}
	c.Success(ginx.H{"token": token})
})
```

#### 2. 请求层级集成

```go
func handleProfile(c *gin.Context) {
	if err := c.Auth().CheckLogin(); err != nil {
		c.Unauthorized(err.Error())
		return
	}

	loginID, _ := c.Auth().LoginID()

	if err := c.Auth().CheckAnyPermission("user:read", "profile:read"); err != nil {
		c.Forbidden(err.Error())
		return
	}

	c.Success(gin.H{"login_id": loginID})
}
```

#### 3. 全局 API

```go
cfg := auth.DefaultAuthConfig()
mgr := auth.NewManager(auth.NewMemoryStorage(), &cfg)
auth.SetGlobalManager(mgr)
defer auth.CloseGlobalManager()

token, _ := auth.Login("user-1001", "web")
ok := auth.IsLogin(token)
```

### 存储选项

- **内存存储**：`auth.NewMemoryStorage()` - 适用于开发/测试
- **Redis 存储**：`auth.NewRedisStorage(redisURL)` - 适用于生产环境

详细文档请参考 [auth/README.md](auth/README.md) 和 [auth/DESIGN.md](auth/DESIGN.md)。

## 工具能力包

### pkg/cache - 缓存抽象

```go
c := cache.NewMemoryCache(
	cache.WithMaxSize(1000),
	cache.WithDefaultTTL(5*time.Minute),
)

// 使用接口
c.Set(ctx, "key", value, time.Minute)
val, _ := c.Get(ctx, "key")
```

### pkg/lifecycle - 生命周期管理

```go
mgr := lifecycle.NewManager()
mgr.SetShutdownTimeout(10 * time.Second)

mgr.OnStart(func(ctx context.Context) error {
	return nil // 启动任务
})

mgr.OnShutdown(func(ctx context.Context) error {
	return db.Close() // 清理任务
})

mgr.Run(server, nil)
```

### pkg/logger - 日志接口

```go
type MyLogger struct{}

func (l *MyLogger) Debug(msg string, args ...any) {}
func (l *MyLogger) Info(msg string, args ...any) {}
func (l *MyLogger) Warn(msg string, args ...any) {}
func (l *MyLogger) Error(msg string, args ...any) {}
func (l *MyLogger) WithContext(ctx context.Context) logger.Logger { return l }
func (l *MyLogger) WithFields(fields map[string]any) logger.Logger { return l }

app := gin.New()
app.WithLogger(&MyLogger{})
```

### pkg/websocket - WebSocket 支持

```go
ws, err := c.UpgradeWebSocket("user-1")
defer ws.Close()

go ws.StartPingPong()

for {
	msg, err := ws.ReadText()
	if err != nil {
		break
	}
	ws.WriteText("echo: " + msg)
}
```

### pkg/export - 数据导出

```go
// CSV 导出
err := export.CSV(w, data, export.CSVConfig{
	Headers: []string{"ID", "Name", "Email"},
	Fields:  []string{"id", "name", "email"},
})

// Excel 导出
err := export.Excel(w, data, export.ExcelConfig{
	SheetName: "Users",
})
```

### pkg/sms - 短信服务

```go
// 阿里云 SMS
aliyun := sms.NewAliyunProvider(sms.AliyunConfig{
	AccessKey:    "your-access-key",
	AccessSecret: "your-access-secret",
	SignName:     "YourSignName",
})

err := aliyun.Send(ctx, "13800138000", "SMS_123456", map[string]string{"code": "1234"})
```

详细文档请参考各子包的 README.md。

## API 文档

### Engine API

```go
// 创建引擎
app := gin.New(opts ...OptionFunc)
app := gin.Default(opts ...OptionFunc)

// 启动服务
err := app.Run()           // 监听默认 :8080
err := app.Run(":9090")    // 监听指定地址

// 优雅关闭
err := app.Shutdown(ctx)

// 生命周期钩子
app.OnStart(hooks ...HookFunc)
app.OnShutdown(hooks ...HookFunc)
app.OnStopped(hooks ...HookFunc)

// 获取路由器
r := app.Router()
rx := app.RegexRouter()
```

### Context API

```go
// 与上游 gin 一致的单一来源取值
c.Param(key string) string
c.Query(key string) string
c.DefaultQuery(key, defaultValue string) string
c.PostForm(key string) string
c.DefaultPostForm(key, defaultValue string) string

// 本项目增强的聚合取值
c.Input(key string, defaults ...string) string
c.ParamInt(key string, defaults ...int) int
c.ParamInt64(key string, defaults ...int64) int64
c.ParamFloat(key string, defaults ...float64) float64
c.ParamBool(key string, defaults ...bool) bool
c.ParamIntE(key string) (int, error)
c.ParamInt64E(key string) (int64, error)
c.ParamFloatE(key string) (float64, error)
c.ParamBoolE(key string) (bool, error)

// 响应方法
c.Success(data any)
c.Created(data any)
c.Accepted(data any)
c.NoContent()
c.BadRequest(message string)
c.Unauthorized(message string)
c.Forbidden(message string)
c.NotFound(message string)
c.Conflict(message string)
c.ValidationError(errors any)
c.InternalError(message string)
c.TooManyRequests()
c.Error(code int, message string)

// 分页
c.ParsePagination() (page, perPage int)
c.Paginated(data any, page, perPage, total int)
c.ParseCursorPagination() (cursor string, limit int)
c.CursorPaginated(data any, cursor string, limit int, hasMore bool)

// 流式响应
c.BeginSSE()
c.SSE(event string, data any)
c.SSEHeartbeat()
c.BeginNDJSON()
c.StreamNDJSON(obj any)

// 请求信息
c.GetIP() string
c.GetUserAgent() string
c.RequestID() string
c.TraceID() string
c.SpanID() string
c.GetBearerToken() string
c.IsAjax() bool
c.IsJSON() bool
c.IsSecure() bool

// WebSocket
c.UpgradeWebSocket(userID string, opts ...WSOption) (*websocket.WebSocket, error)

// 获取组件
c.Logger() logger.Logger
c.Cache() cache.Cache
c.Auth() *auth.AuthContext
```

### Router API

```go
// HTTP 方法
r.GET(path string, handlers ...HandlerFunc)
r.POST(path string, handlers ...HandlerFunc)
r.PUT(path string, handlers ...HandlerFunc)
r.PATCH(path string, handlers ...HandlerFunc)
r.DELETE(path string, handlers ...HandlerFunc)
r.HEAD(path string, handlers ...HandlerFunc)
r.OPTIONS(path string, handlers ...HandlerFunc)
r.Any(path string, handlers ...HandlerFunc)
r.Match(methods []string, path string, handlers ...HandlerFunc)

// 分组
group := r.Group(prefix string, middleware ...HandlerFunc)

// 资源路由
r.Resource(name string, ctrl ResourceController, opts ...ResourceOption)
r.CRUD(name string, ctrl ResourceController)

// 版本化
v := r.Version(v string) *Router
r.VersionedAPI(version string, setup func(*Router))

// 健康检查
r.HealthCheck(paths ...string)
r.Liveness(path ...string)
r.Readiness(checks ...ProbeCheck)
r.Startup(checks ...ProbeCheck)

// 静态资源
r.Static(relativePath string, root string)
r.StaticFile(relativePath string, filepath string)
r.StaticFS(relativePath string, sys http.FileSystem)
r.Assets(relativePath string, root string, opts ...static.Option)
r.AssetsFS(relativePath string, sys http.FileSystem, opts ...static.Option)
r.Site(relativePath string, root string, opts ...static.Option)
r.SiteFS(relativePath string, sys http.FileSystem, opts ...static.Option)
r.SiteZip(relativePath string, zipPath string, opts ...static.Option)
r.SiteEmbeddedZip(relativePath string, archive fs.FS, archivePath string, opts ...static.Option)
r.EmbedFS(relativePath string, fsys embed.FS, subPath ...string)
r.EmbedFile(relativePath string, file embed.FS, filePath string)

e.FallbackSite(root string, opts ...static.Option)
e.FallbackSiteFS(sys http.FileSystem, opts ...static.Option)
e.FallbackSiteZip(zipPath string, opts ...static.Option)
e.FallbackSiteEmbeddedZip(archive fs.FS, archivePath string, opts ...static.Option)

// 自动注册
r.AutoRegister(controller any, opts ...OptionFunc)
r.WithPrefix(prefix string) OptionFunc
r.WithMiddleware(mw ...HandlerFunc) OptionFunc
```

详细 API 文档请参考 [docs/api-reference.md](docs/api-reference.md)。

## 性能基准

框架提供了路由基准测试文件 [routing_bench_test.go](routing_bench_test.go)，用于对比不同路由场景的性能：

```bash
go test -run '^$' -bench '^BenchmarkRouting$|^BenchmarkRoutingParallel$' -benchmem -benchtime=1s .
```

测试场景包括：

- 普通路由命中
- Regex-only 路由命中
- 混合路由下的标准命中、regex fallback 与 miss
- 复杂 regex 与同段多参数 pattern

## 与 Gin 的关系

该模块并不是替代 Gin 的"重写版"，而是基于 Gin 的增强层：

- 底层仍使用 `github.com/gin-gonic/gin`
- 路由匹配、HTTP 处理、上下文基础能力仍沿用 Gin
- 根模块在此基础上增加更适合业务项目的工程化能力

如果你已经熟悉 Gin，这个模块的上手成本会很低。

## 开发建议

- 若只是轻量 API，可直接从 `gin.Default()` + `Router()` 开始
- 若有认证需求，优先使用 `WithAuth()`，并在生产环境切换到 Redis 存储
- 若需要统一化运维能力，可优先组合 `WithLogger()`、`WithCache()`、`Production()` 与中间件栈
- 若需要复杂 URL 约束，优先直接在 `GET/POST/Match/Any` 中使用 chi 风格 pattern；仅在需要高级控制时再使用 `RegexRouter()`

## 文档索引

### 根模块文档

- [使用指南](docs/usage.md)
- [API 参考](docs/api-reference.md)
- [缓存中间件说明](docs/cache_middleware.md)
- [静态资源设计说明](docs/static-design.md)
- [Swagger 实现说明](SWAGGER_IMPLEMENTATION.md)
- [darkit-gin Skill 包](docs/darkit-gin/SKILL.md)
- [变更记录](CHANGELOG.md)

### Auth 子模块

- [auth/README.md](auth/README.md) - 认证模块使用指南
- [auth/DESIGN.md](auth/DESIGN.md) - 认证模块设计文档

### pkg 子模块文档

- [pkg/cache/README.md](pkg/cache/README.md) - 缓存抽象
- [pkg/circuitbreaker/README.md](pkg/circuitbreaker/README.md) - 熔断器
- [pkg/concurrency/README.md](pkg/concurrency/README.md) - 并发工具
- [pkg/diagnostic/README.md](pkg/diagnostic/README.md) - 诊断辅助
- [pkg/export/README.md](pkg/export/README.md) - 数据导出
- [pkg/image/README.md](pkg/image/README.md) - 图片处理
- [pkg/lifecycle/README.md](pkg/lifecycle/README.md) - 生命周期管理
- [pkg/logger/README.md](pkg/logger/README.md) - 日志接口
- [pkg/mail/README.md](pkg/mail/README.md) - 邮件发送
- [pkg/mask/README.md](pkg/mask/README.md) - 数据脱敏
- [pkg/retry/README.md](pkg/retry/README.md) - 重试机制
- [pkg/routes/README.md](pkg/routes/README.md) - 路由辅助
- [pkg/sms/README.md](pkg/sms/README.md) - 短信服务
- [pkg/static/README.md](pkg/static/README.md) - 静态资源
- [pkg/swagger/README.md](pkg/swagger/README.md) - Swagger/OpenAPI
- [pkg/validator/README.md](pkg/validator/README.md) - 校验辅助
- [pkg/websocket/README.md](pkg/websocket/README.md) - WebSocket 支持

### 中间件文档

- [middleware/README.md](middleware/README.md) - 中间件生态总览

### 示例文档

- [examples/basic/README.md](examples/basic/README.md) - 基础示例
- [examples/advanced/README.md](examples/advanced/README.md) - 高级示例
- [examples/streaming/README.md](examples/streaming/README.md) - 流式响应示例
- [examples/probes/README.md](examples/probes/README.md) - 健康检查示例
- [examples/static/README.md](examples/static/README.md) - 静态资源示例
- [examples/swagger-demo/README.md](examples/swagger-demo/README.md) - Swagger 示例

## 许可证

本项目基于 MIT 许可证开源。
