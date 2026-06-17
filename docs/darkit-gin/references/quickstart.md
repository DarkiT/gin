# Quickstart

这份 quickstart 面向“正在业务项目中接入 `github.com/darkit/gin` 的调用方”。目标是在 3 到 5 分钟内完成第一轮可运行接入，而不是解释框架内部实现。

## 目录

- 固定接入流程
- 先记住 6 个入口
- 最小服务骨架
- 三种接入模式
- 第一个 handler 怎么写
- 参数读取边界
- 常见场景下一步
- 推荐直接复制的模板
- 不要在 quickstart 阶段做的事

## 固定接入流程

把本 Skill 当成函数调用时，按下面顺序稳定执行：

1. **读调用方项目**：检查 `go.mod`、入口文件、现有 Gin/HTTP 路由、中间件和配置方式。
2. **定模式**：选择 Gin-compatible、Enhanced 或 Infrastructure mode。
3. **取模板**：从 `assets/examples/*.tmpl` 选最接近的起点。
4. **最小改造**：先让一个路由、一个中间件链或一个 provider 跑通。
5. **验证闭环**：`gofmt`、`go test ./...`，必要时补 `go vet ./...` 和一条最小请求验证。
6. **回报接口**：列出改动文件、使用方式、配置项、后续生产化建议。

## 先记住 6 个入口

- `gin.Default(...)`：带默认中间件的增强引擎
- `gin.New(...)`：空白增强引擎
- `e.Router()`：拿到增强 `Router`
- `func(c *gin.Context)`：增强 handler 签名
- `c.Success(...)` / `c.Created(...)` / `c.BadRequest(...)`：标准 JSON 响应
- `c.Problem(...)` / `c.ValidationProblem(...)`：标准 `problem+json` 错误响应

## 最小服务骨架

直接从模板开始：

- [assets/examples/basic_server.go.tmpl](../assets/examples/basic_server.go.tmpl)

最小心智流程：

1. `gin.Default(...)` 或 `gin.New(...)` 创建引擎
2. `e.Router()` 获取增强路由器
3. 用 `r.GET/POST/...` 注册路由
4. 在 handler 内使用增强 `*gin.Context`
5. `e.Run()` 启动服务

## 三种接入模式

### 1. Gin-compatible mode：低风险迁移

适合已有 `gin-gonic/gin` 项目，先保持业务写法不变：

```go
import gin "github.com/darkit/gin"

r := gin.Default()
r.GET("/ping", func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "pong"})
})
```

优先目标是编译通过和行为稳定，增强能力后置。

### 2. Enhanced mode：使用 darkit/gin 推荐写法

```go
e := gin.Default(
    gin.WithAddr(":8080"),
)
r := e.Router()

r.GET("/ping", func(c *gin.Context) {
    c.Success(gin.H{"message": "pong"})
})
```

推荐用于新服务或愿意采用增强 `Engine/Router/Context` 的模块。

### 3. Infrastructure mode：接入生产基础能力

```go
e := gin.New(
    gin.WithAddr(":8080"),
    gin.WithReadTimeout(30*time.Second),
    gin.WithWriteTimeout(30*time.Second),
)

e.UseAny(
    middleware.CORS(),
    middleware.Secure(),
    middleware.Timeout(5*time.Second),
)
```

说明：

- `Use(...)` 只接增强 `HandlerFunc`
- `middleware.CORS()`、`middleware.Timeout(...)` 这类大多数返回的是 `gin.HandlerFunc`
- 混合签名时请用 `UseAny(...)`

## 第一个 handler 怎么写

最稳妥的写法是：

```go
r.GET("/users/:id", func(c *gin.Context) {
    id, err := c.ParamIntE("id")
    if err != nil {
        c.BadRequest("invalid id")
        return
    }

    c.Success(gin.H{"id": id})
})
```

## 参数读取边界

- `c.Param("id")`：只读路径参数
- `c.Query("q")`：只读 query
- `c.PostForm("name")`：只读 form
- `c.Input("key", def...)`：聚合读取，顺序是“路径参数 -> query -> form”

如果从旧写法迁过来，最容易出错的是把 `Param(...)` 当成聚合入口；现在应该改用 `Input(...)`。

## 常见场景下一步

| 当前任务 | 下一步 |
| --- | --- |
| 想系统查 `Context` 能力 | [context-cheatsheet.md](./context-cheatsheet.md) |
| 要做版本路由、自动注册、regex | [router-patterns.md](./router-patterns.md) |
| 要接认证 | [auth-integration.md](./auth-integration.md) |
| 要接缓存、Fiber storage、auth KV 后端 | [cache-storage-integration.md](./cache-storage-integration.md) |
| 要做 Problem / SSE / webhook / probes / OpenAPI | [feature-recipes.md](./feature-recipes.md) |
| 要做静态站点 / SPA / ZIP / embed | [static-site-recipes.md](./static-site-recipes.md) |
| 要排障 | [troubleshooting.md](./troubleshooting.md) |

## 推荐直接复制的模板

- 基础服务：[basic_server.go.tmpl](../assets/examples/basic_server.go.tmpl)
- 中间件链：[middleware_chain.go.tmpl](../assets/examples/middleware_chain.go.tmpl)
- 缓存与 Fiber storage：[cache_storage.go.tmpl](../assets/examples/cache_storage.go.tmpl)
- 完整型起步：[full_featured.go.tmpl](../assets/examples/full_featured.go.tmpl)

## 不要在 quickstart 阶段做的事

- 不要先读完整仓库所有 README
- 不要把 `RegexRouter()` 当常规路由第一入口
- 不要把 `c.Error(...)` 当作统一错误响应
- 不要用 `Use(...)` 混塞 Gin/标准库中间件
- 不要在调用方项目中运行框架本仓的 `internal/tools/gincompat`

先起服务、先跑通一个接口，再进入专项 reference。
