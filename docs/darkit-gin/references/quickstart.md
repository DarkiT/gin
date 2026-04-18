# Quickstart

这份 quickstart 的目标不是覆盖全部能力，而是让上层调用方在 3 到 5 分钟内完成第一轮接入判断：

- 服务怎么起
- 路由怎么写
- `Context` 怎么用
- 哪个模板最接近当前任务

## 目录

- 先记住 6 个入口
- 最小服务骨架
- 最常见起手式
- 第一个 handler 怎么写
- 参数读取要记住的边界
- 常见场景怎么找下一份参考
- 推荐直接复制的模板
- 不要在 quickstart 阶段做的事

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

## 最常见起手式

### 1. 标准 JSON API

```go
e := gin.Default(
    gin.WithAddr(":8080"),
)
r := e.Router()

r.GET("/ping", func(c *gin.Context) {
    c.Success(gin.H{"message": "pong"})
})
```

### 2. 需要自定义初始化项

```go
e := gin.New(
    gin.WithAddr(":8080"),
    gin.WithReadTimeout(30*time.Second),
    gin.WithWriteTimeout(30*time.Second),
)
```

### 3. 需要加常见 gin 风格中间件

默认优先用：

```go
e.UseAny(
    middleware.CORS(),
    middleware.RealIP(),
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

## 参数读取要记住的边界

- `c.Param("id")`：只读路径参数
- `c.Query("q")`：只读 query
- `c.PostForm("name")`：只读 form
- `c.Input("key", def...)`：聚合读取，顺序是“路径参数 -> query -> form”

如果你从旧写法迁过来，最容易出错的是把 `Param(...)` 当成聚合入口；现在应该改用 `Input(...)`。

## 常见场景怎么找下一份参考

| 当前任务 | 下一步 |
| --- | --- |
| 想系统查 `Context` 能力 | [context-cheatsheet.md](./context-cheatsheet.md) |
| 要做版本路由、自动注册、regex | [router-patterns.md](./router-patterns.md) |
| 要接认证 | [auth-integration.md](./auth-integration.md) |
| 要做 Problem / SSE / webhook / probes / OpenAPI | [feature-recipes.md](./feature-recipes.md) |
| 要做静态站点 / SPA / ZIP / embed | [static-site-recipes.md](./static-site-recipes.md) |
| 要排障 | [troubleshooting.md](./troubleshooting.md) |

## 推荐直接复制的模板

- 基础服务：[basic_server.go.tmpl](../assets/examples/basic_server.go.tmpl)
- 中间件链：[middleware_chain.go.tmpl](../assets/examples/middleware_chain.go.tmpl)
- 完整型起步：[full_featured.go.tmpl](../assets/examples/full_featured.go.tmpl)

## 不要在 quickstart 阶段做的事

- 不要先读完整仓库所有 README
- 不要把 `RegexRouter()` 当常规路由第一入口
- 不要把 `c.Error(...)` 当作统一错误响应
- 不要用 `Use(...)` 混塞 gin middleware

先起服务、先跑通一个接口，再进入专项 reference。
