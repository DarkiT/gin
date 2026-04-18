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

进一步阅读：

- `auth/README.md`
- `auth/DESIGN.md`
- `auth/API.md`

## 上传、导出与 WebSocket

### 文件上传

```go
r.POST("/upload", func(c *engine.Context) {
	file, err := c.SaveFile("file")
	if err != nil {
		c.BadRequest(err.Error())
		return
	}
	c.Created(file)
})
```

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

## 进一步阅读

- `README.md`
- `DESIGN.md`
- `docs/api-reference.md`
- `middleware/README.md`
- `middleware/DESIGN.md`
- `pkg/cache/README.md`
- `pkg/export/README.md`
- `pkg/mail/README.md`
- `pkg/mask/README.md`
- `pkg/sms/README.md`
- `pkg/validator/README.md`
- `pkg/websocket/README.md`

## 查看权威 API 的方式

推荐顺序：

1. `go doc github.com/darkit/gin`
2. `go doc github.com/darkit/gin.Context`
3. `go doc github.com/darkit/gin/auth`
4. 直接阅读对应源码文件与测试

如果文档和源码冲突，以源码和测试为准。
