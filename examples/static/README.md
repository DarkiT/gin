# 静态资源用法说明

本目录当前提供的是静态资源能力的说明文档，用来帮助选择不同入口的使用场景。

如果你更关注完整框架说明，可同时参考：

- [根目录 README](../../README.md)
- [pkg/static/README.md](../../pkg/static/README.md)
- [静态资源设计说明](../../docs/static-design.md)

## 先看结论

### 1. 与上游兼容的直接路由注册

适合“明确挂一个目录或文件”的场景。

```go
r.Static("/assets", "./public")
r.StaticFS("/downloads", http.Dir("./files"))
r.StaticFile("/favicon.ico", "./public/favicon.ico")
r.EmbedFS("/static", embedFS, "dist")
r.EmbedFile("/robots.txt", embedFS, "dist/robots.txt")
```

特点：

- 与上游 Gin 模型一致
- 直接注册普通路由
- 适合后台资源、下载文件、嵌入式只读资源

### 2. 受控静态资源挂载

适合“希望静态资源只在路由未命中时兜底，但不要影响普通路由和 regex 路由”的场景。

```go
r.Assets("/assets", "./public")
r.AssetsFS("/files", http.Dir("./uploads"))
```

特点：

- 通过 `NoRoute` 受控兜底，不注册 catch-all 普通路由
- 不会抢占普通路由与 regex 路由
- 更适合构建产物、管理后台资源目录、带子路径隔离的资源树

### 3. 受控站点挂载

适合前端站点、SPA、后台控制台。

```go
r.Site("/app", "./dist")
e.FallbackSite("./dist")
```

特点：

- 支持 `index.html`
- 支持 history fallback
- 可通过 `WithNotFoundFile("404.html")` 提供自定义 404 页面
- 仍然遵守“普通路由 -> regex 路由 -> 站点兜底”的优先级

## 路由优先级

新的 `Assets*` / `Site*` / `FallbackSite*` 入口不会和普通路由、正则路由冲突，顺序固定为：

1. 普通 Gin 路由
2. regex 路由
3. 受控静态挂载
4. 用户自定义 `NoRoute`

这意味着：

- `/api/ping` 这种普通业务路由始终优先
- `/orders/{id:[0-9]+}` 这种 regex 路由也会优先于站点兜底
- `FallbackSite("./dist")` 更像“最后一层前端接管”，而不是“注册一个全局 catch-all 路由”

## 常见写法

### 目录资源

```go
e := gin.New()
r := e.Router()

r.Assets("/assets", "./public")
```

### SPA 站点

```go
e := gin.New()
r := e.Router()

r.Site("/app", "./dist")
```

### 全站前端兜底

```go
e := gin.New()

e.GET("/api/ping", func(c *gin.Context) {
    c.Success(gin.H{"ok": true})
})

e.FallbackSite("./dist")
```

### ZIP 站点

```go
e := gin.New()
r := e.Router()

if err := r.SiteZip("/admin", "./admin.zip"); err != nil {
    panic(err)
}
```

### 嵌入式 ZIP

```go
package main

import (
    "embed"

    gin "github.com/darkit/gin"
)

//go:embed ui/app.zip
var assets embed.FS

func main() {
    e := gin.New()
    if err := e.FallbackSiteEmbeddedZip(assets, "ui/app.zip"); err != nil {
        panic(err)
    }
}
```

## Option 示例

```go
r.Site(
    "/app",
    "./dist",
    static.WithIndexFile("index.html"),
    static.WithHistoryFallback(),
    static.WithNotFoundFile("404.html"),
)
```

ZIP / 嵌入式 ZIP 额外支持：

```go
cfg := static.NewZipFSConfig(
    "./app.zip",
    "/app",
    static.WithPassword("secret"),
    static.WithSubPaths("admin/"),
    static.WithHotReload(3*time.Second),
)
```

## 什么时候还用旧入口

- 只需要和上游 Gin 完全一致时，用 `Static*`
- 只需要单个嵌入文件或目录时，用 `EmbedFS` / `EmbedFile`
- 已有代码基于 `pkg/static.RegisterZipFS` 时，可以继续保留，当前仍兼容

## 推荐实践

1. 前端站点优先使用 `Site` / `FallbackSite`
2. 资源目录优先使用 `Assets`
3. 用户上传目录与前端构建产物建议分开挂载
4. 多站点场景优先使用更具体的前缀，例如 `/app`、`/admin`
5. 若同一棵路径下既有业务路由又有站点兜底，让业务路由先注册到普通路由或 regex 路由即可
