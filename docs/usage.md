# Darkit Gin 使用指南

本文档提供 `github.com/darkit/gin` 的**当前用法总览**。

它不再试图充当超长百科；源码注释与 `go doc` 才是最终权威。此文档只负责：

- 快速建立模型
- 指向正确入口
- 给出与当前代码一致的常用示例

## 快速开始

### 创建 Engine

```go
package main

import (
	"time"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
)

func main() {
	e := engine.Default(
		engine.WithAddr(":8080"),
		engine.WithReadTimeout(30*time.Second),
		engine.WithWriteTimeout(30*time.Second),
	)

	e.Use(middleware.CORS())

	r := e.Router()
	r.GET("/ping", func(c *engine.Context) {
		c.Success(engine.H{"message": "pong"})
	})

	_ = e.Run()
}
```

### 默认中间件

`engine.Default(...)` 会自动挂载：

- `middleware.RequestID()`
- `middleware.Recovery()`
- `middleware.Logger()`

如果你想从空白引擎开始，使用 `engine.New(...)`。

## 核心结构

### Engine

入口位于：

- `engine.go`
- `options.go`

最常用能力：

- `New(opts ...OptionFunc)`
- `Default(opts ...OptionFunc)`
- `Router()`
- `Run()` / `Shutdown()`
- `OnStart()` / `OnShutdown()` / `OnStopped()`

进阶能力：

- `RegexRouter()`，用于 `Match()`、`NotFound()`、纯 regex `Group/Use`

### Router

入口位于：

- `router.go`
- `auto_register.go`
- `regex_router.go`

最常用能力：

- `GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS`
- `Group()`
- `Resource()` / `CRUD()`
- `Version()` / `VersionedAPI()`
- `HealthCheck()`
- `Use()`
- `AutoRegister()`

说明：

- 当路径写成 chi 风格 pattern 时，以上常规方法会自动接入 regex 路由层。

### Context

入口位于：

- `context.go`
- `context_upload.go`
- `context_export.go`
- `context_image.go`
- `context_mask.go`
- `context_auth.go`
- `context_websocket.go`

最常用能力：

- 参数：`Param`、`ParamInt`、`ParamBool`、`ParsePagination`
- 绑定：`BindAndValidate`、`BindJSONOrAbort`、`BindQueryOrAbort`
- 响应：`Success`、`Created`、`NoContent`、`ValidationError`、`InternalError`
- 文件：`SaveFile`、`SaveFiles`、`StreamFile`、`StreamFileInline`
- 导出：`ExportExcel`、`ExportCSV`、`StreamExcel`、`StreamCSV`
- 认证：`Auth()`
- WebSocket：`UpgradeWebSocket(...)`

## 常用配置

常见 `Option` 包括：

- `WithAddr(addr)`
- `WithReadTimeout(d)`
- `WithWriteTimeout(d)`
- `WithTrustedProxies(proxies)`
- `WithGracefulShutdown(timeout)`
- `WithStartupTimeout(timeout)`
- `WithLogger(l)`
- `WithCache(c)`
- `WithUploadDir(dir)`
- `WithMaxFileSize(size)`
- `WithUploadConfig(cfg)`
- `WithMail(cfg)`
- `WithSMS(cfg)`
- `EnableSwagger(cfg)`
- `WithAuth(cfg)`
- `Development()` / `Production()`

## 路由与中间件

### 普通路由

```go
r := e.Router()

r.GET("/users/:id", func(c *engine.Context) {
	id := c.ParamInt("id")
	c.Success(engine.H{"id": id})
})
```

### 路由分组

```go
api := r.Group("/api")
api.GET("/healthz", func(c *engine.Context) {
	c.Success(engine.H{"ok": true})
})
```

### 混用中间件

`Router.Use(...)` 支持：

- 增强型 `func(*Context)`
- 原始 `gin.HandlerFunc`
- `func(http.Handler) http.Handler`

例如：

```go
r.Use(
	middleware.CORS(),
	middleware.RealIP(),
	middleware.Timeout(5*time.Second),
)
```

### 路由级原始 middleware

当某个 API 只想局部使用一个原始 `gin.HandlerFunc` 中间件时，可包装后再挂：

```go
e.GET(
	"/articles/:id",
	engine.WrapMiddleware(middleware.Cache(5*time.Minute)),
	func(c *engine.Context) {
		c.Success(engine.H{"id": c.Param("id")})
	},
)
```

## 正则路由

当路径包含 chi 风格的 `{param:regex}` 模式时，常规 `GET/POST/...` 会自动接入 regex 路由层：

```go
r.GET("/users/{id:[0-9]+}", func(c *engine.Context) {
    id := c.ParamInt("id")
    c.Success(engine.H{"id": id})
})

r.GET("/articles/{slug:[a-z0-9-]+}", func(c *engine.Context) {
    c.Success(engine.H{"slug": c.Param("slug")})
})
```

支持的 pattern 格式：

- `{name}` — 无限制通配
- `{name:regex}` — 正则约束
- `{name:word}` — `\w+`
- `{*rest}` — 贪心匹配

说明：

- 自动区分标准路由与正则路由，不需要手动选择使用哪个 Router
- 高级控制（`Match()`、`Handler()`、纯 regex `Group/Use`）请使用 `e.RegexRouter()`

## 流式输出

### SSE (Server-Sent Events)

```go
r.GET("/events", func(c *engine.Context) {
    c.BeginSSE()
    for i := 0; i < 10; i++ {
        if err := c.SSE("update", engine.H{"count": i}); err != nil {
            return
        }
        time.Sleep(time.Second)
    }
    _ = c.SSEHeartbeat()
})
```

### NDJSON

```go
r.GET("/logs", func(c *engine.Context) {
    for _, log := range logs {
        if err := c.StreamNDJSON(log); err != nil {
            return
        }
    }
})
```

## Problem Details 错误响应（RFC 9457）

对外 API 推荐使用标准 `problem+json` 错误模型：

```go
r.GET("/users/:id", func(c *engine.Context) {
    user, err := findUser(c.Param("id"))
    if err != nil {
        c.Problem(
            http.StatusNotFound,
            "https://api.example.com/errors/user-not-found",
            "用户不存在",
            "无法找到指定 ID 的用户",
        )
        return
    }
    c.Success(user)
})

// 校验错误
r.POST("/users", func(c *engine.Context) {
    var req CreateUserReq
    if err := c.BindAndValidate(&req); err != nil {
        c.ValidationProblem(engine.ExtractValidationErrors(err), "请求参数验证失败")
        return
    }
    // ...
})
```

## 脱敏响应

```go
r.GET("/users/:id/profile", func(c *engine.Context) {
    profile := loadProfile(c.Param("id"))
    // OKMasked 自动根据结构体 mask tag 脱敏敏感字段
    c.OKMasked(profile)
})
```

结构体中使用 `mask` 标签声明脱敏规则：

```go
type Profile struct {
    Name   string `json:"name"`
    Phone  string `json:"phone" mask:"middle:4"`     // 138****1234
    Email  string `json:"email" mask:"prefix:3"`     // abc***@example.com
    IDCard string `json:"id_card" mask:"middle:6"`   // 110***********1234
}
```

## Webhook 接收器

```go
r.POST("/webhook", func(c *engine.Context) {
    eventID := c.WebhookEventID()
    signature := c.WebhookSignature()
    body, _ := c.RawBody()
    log.Printf("webhook: event=%s sig=%s body=%s", eventID, signature, body)
    c.NoContent()
})
```

其他辅助方法：

- `c.WebhookTimestamp()` — 提取常见 webhook 时间戳头
- `c.RawBodyString()` — 原始请求体字符串形式
- `c.MustRawBody()` — 原始请求体，失败 panic

## 认证接入

```go
e := engine.New(
	engine.WithAuth(auth.AuthConfig{
		Secret:     "replace-me",
		Expiry:     24 * time.Hour,
		TokenStyle: auth.TokenStyleJWT,
	}),
)

r := e.Router()
r.POST("/login", func(c *engine.Context) {
	token, err := c.Auth().Login("user-1001", "web")
	if err != nil {
		c.InternalError(err.Error())
		return
	}
	c.Success(engine.H{"token": token})
})
```

说明：

- `WithAuth(...)` 在构造阶段只做配置声明与校验
- `auth.Manager` 会在 `Run()` 前或首个请求进入前自动初始化
- 请求内继续直接使用 `c.Auth()`

## Mail / SMS 接入

```go
e := engine.New(
	engine.WithMail(mail.MailConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}),
	engine.WithSMS(sms.SMSConfig{
		Provider:  "tencent",
		AccessKey: "ak",
		SecretKey: "sk",
		SignName:  "Demo",
		AppID:     "1400000000",
	}),
)
```

请求内入口：

- `c.Mailer()`
- `c.SMS()`

进一步阅读：

- `auth/README.md`
- `auth/DESIGN.md`
- `auth/API.md`

## 上传、导出与 WebSocket

### 文件上传

```go
r.POST("/upload", func(c *engine.Context) {
	file, err := c.SaveFile(
		"file",
		engine.ToSubDir("images/avatars"),
		engine.AsName("user-1001.png"),
	)
	if err != nil {
		c.BadRequest(err.Error())
		return
	}
	c.Created(file)
})
```

说明：

- `AsName(...)` 只接收纯文件名，不承载路径。
- 如需分类落盘，请显式使用 `ToSubDir(...)`。
- `SaveFiles(...)` 不要配固定 `AsName(...)`；如需批量自定义命名，请使用 `NameBy(...)` 生成唯一目标名。
- 返回结果中的 `RelativePath` 是相对上传根目录的稳定路径，适合入库与拼接访问 URL。

### 文件下载

```go
r.GET("/download/:name", func(c *engine.Context) {
	name := c.Param("name")
	c.StreamFile("./uploads/"+name, name)
})
```

### Excel/CSV 导出

```go
r.GET("/export/users.xlsx", func(c *engine.Context) {
	rows := []User{{ID: 1, Name: "alice"}}
	if err := c.ExportExcel(rows, "users.xlsx"); err != nil {
		c.InternalError(err.Error())
	}
})
```

### WebSocket

```go
r.GET("/ws", func(c *engine.Context) {
	ws, err := c.UpgradeWebSocket("user-1")
	if err != nil {
		return
	}
	defer ws.Close()
})
```

## 缓存中间件

缓存文档已独立整理：

- `docs/cache_middleware.md`
- `examples/cache-demo/main.go`

如果要复用 Fiber storage 生态中的 bbolt、badger、etcd、s3 等后端，推荐走统一适配层：

```go
raw := newFiberCompatibleStorage()

e := engine.New(
	engine.WithCache(cache.NewFiberStorage(raw)),
)
```

说明：

- `pkg/storage` 只定义稳定的字节型 KV 抽象与适配接口
- `cache.NewFiberStorage(...)` 通过结构兼容方式接入 Fiber storage 后端，不把具体 driver 作为框架硬依赖
- `cache.NewStorageCache(...)` 仍可接入任意 `storage.Store`
- auth 存储语义更重，依赖 `Keys`、`TTL`、`Expire`、`SetKeepTTL` 等能力；需要接入通用 KV 后端时，使用 `auth.NewKVStorage(store)` 或 `auth/storage/kv.NewStrict(store)` 做严格能力探测

## 进一步阅读

- `README.md`
- `DESIGN.md`
- `docs/api-reference.md`
- `docs/cache_middleware.md`
- `docs/static-design.md`
- `docs/extension-compat-mapping.md`
- `middleware/README.md`
- `middleware/DESIGN.md`
- `pkg/cache/README.md`
- `pkg/storage/README.md`
- `pkg/export/README.md`
- `pkg/mail/README.md`
- `pkg/mask/README.md`
- `pkg/sms/README.md`
- `pkg/swagger/README.md`
- `pkg/validator/README.md`
- `pkg/websocket/README.md`
- `pkg/static/README.md`

## 查看权威 API 的方式

推荐顺序：

1. `go doc github.com/darkit/gin`
2. `go doc github.com/darkit/gin.Context`
3. `go doc github.com/darkit/gin/auth`
4. 直接阅读对应源码文件与测试

如果文档和源码冲突，以源码和测试为准。
