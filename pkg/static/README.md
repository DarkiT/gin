# pkg/static

`pkg/static` 提供统一的静态资源服务基础设施，覆盖以下几类来源与语义：

- 本地目录 / 任意 `http.FileSystem`
- ZIP 文件
- 嵌入式 ZIP 文件
- 普通静态资源目录语义
- 前端站点语义：`index.html`、history fallback、自定义 `404.html`

它既可以作为根包 `Engine` / `Router` 的底层能力使用，也可以单独拿出来作为 `http.Handler` 复用。

## 设计目标

- 让“资源来源”与“挂载语义”分离
- 保持上层调用简洁：同一套 `Assets / Site / FallbackSite` 入口可以接本地目录、ZIP、嵌入式 ZIP
- 避免静态站点挂载和普通路由、正则路由互相抢占

在根包中，新静态挂载的优先级为：

1. 普通 Gin 路由
2. regex 路由
3. `Assets*` / `Site*` / `FallbackSite*`
4. 用户自定义 `NoRoute`

也就是说，`SiteFS("/app", ...)` 或 `FallbackSiteFS(...)` 不会直接注册 catch-all 普通路由，而是通过 `NoRoute` 链路受控兜底。

## 核心类型

### Service

统一的静态资源服务实现，可直接作为 `http.Handler` 使用。

```go
type Service struct { /* ... */ }

func NewAssetsService(fileSystem http.FileSystem, opts ...Option) *Service
func NewSiteService(fileSystem http.FileSystem, opts ...Option) *Service
```

- `Assets` 模式：适合图片、JS、CSS、下载文件等普通静态资源
- `Site` 模式：适合前端构建产物，支持 `index.html`、history fallback、自定义 404 文件

### ServeConfig

```go
type ServeConfig struct {
    Mode            ServeMode
    IndexFile       string
    NotFoundFile    string
    HistoryFallback bool
}
```

### ZipFSConfig

```go
type ZipFSConfig struct {
    ZipPath         string
    URLPrefix       string
    SubPaths        []string
    Password        string
    HotReload       bool
    CheckInterval   time.Duration
    IndexFile       string
    StripPrefix     bool
    HistoryFallback bool
    NotFoundFile    string
    FallbackFS      http.FileSystem
    FallbackHandler gin.HandlerFunc
}
```

说明：

- `FallbackFS` / `FallbackHandler` 只用于“ZIP 资源源不可用”时的回退
- “文件未命中时回退到首页 / 404 文件”属于站点语义，由 `HistoryFallback` / `NotFoundFile` 控制

## 主要入口

### 在根包中使用

这是最推荐的方式，上层语义最清晰。

```go
package main

import (
    "embed"

    gin "github.com/darkit/gin"
    "github.com/darkit/gin/pkg/static"
)

//go:embed dist/* ui/admin.zip
var assets embed.FS

func main() {
    e := gin.New()
    r := e.Router()

    // 普通静态资源目录
    r.Assets("/assets", "./public")

    // 前端站点目录
    r.Site("/app", "./dist", static.WithHistoryFallback())

    // 基于 ZIP 的前端站点
    _ = r.SiteZip("/admin", "./admin.zip")

    // 全局 SPA 兜底
    _ = e.FallbackSiteEmbeddedZip(assets, "ui/admin.zip")

    _ = e.Run(":8080")
}
```

### 单独作为 `http.Handler` 使用

```go
dist := http.Dir("./dist")

assetsHandler := static.NewAssetsService(dist)
siteHandler := static.NewSiteService(
    dist,
    static.WithHistoryFallback(),
    static.WithNotFoundFile("404.html"),
)
```

### ZIP 文件系统

```go
cfg := static.NewZipFSConfig(
    "./app.zip",
    "/app",
    static.WithHotReload(3*time.Second),
    static.WithIndexFile("index.html"),
)

zfs, err := static.NewZipFileSystem(cfg)
if err != nil {
    panic(err)
}
defer zfs.Stop()
```

兼容旧用法时，仍可继续使用：

```go
static.RegisterZipFS(router, "/app", zfs)
static.RegisterZipFile(router, "/favicon.ico", zf)
```

### 嵌入式 ZIP

```go
package main

import (
    "embed"

    "github.com/darkit/gin/pkg/static"
)

//go:embed ui/app.zip
var archive embed.FS

func main() {
    fsys, err := static.NewEmbeddedZipFS(archive, "ui/app.zip")
    if err != nil {
        panic(err)
    }

    _ = static.NewSiteService(fsys, static.WithHistoryFallback())
}
```

## Option

| 选项 | 作用 |
| --- | --- |
| `WithIndexFile(filename string)` | 设置首页文件，默认 `index.html` |
| `WithNotFoundFile(filename string)` | 设置未命中时返回的静态文件 |
| `WithHistoryFallback()` | 启用 history fallback |
| `WithoutHistoryFallback()` | 关闭 history fallback |
| `WithSubPaths(paths ...string)` | 限制 ZIP / 嵌入式 ZIP 仅暴露指定子路径 |
| `WithPassword(password string)` | 设置 ZIP 文件密码 |
| `WithStripPrefix(enabled bool)` | 控制 ZIP 服务是否移除 URL 前缀 |
| `WithHotReload(interval time.Duration)` | 启用 ZIP 热更新 |
| `WithFallback(handler gin.HandlerFunc)` | 设置 ZIP 源不可用时的回退处理器 |

## 语义建议

- 只想“暴露一个目录/文件”时，优先使用根包的 `Static*` / `Embed*`
- 想避免 catch-all 路由与业务路由冲突时，优先使用 `Assets*`
- 想托管前端构建产物、SPA、后台站点时，优先使用 `Site*`
- 想接管整站未命中路由时，使用 `FallbackSite*`
- 需要把前端产物打成单文件分发时，使用 `SiteZip` / `FallbackSiteZip` 或 `NewEmbeddedZipFS`

## 测试覆盖

当前已覆盖的关键场景包括：

- 普通路由优先于 `SiteFS`
- regex 路由优先于 `SiteFS`
- `FallbackSiteFS` 不会误处理非 HTML 请求
- 更具体的 `AssetsFS("/assets", ...)` 不会错误落到根级 `FallbackSiteFS("/")`
- 嵌入式 ZIP 的站点兜底与资源文件读取
- ZIP 子路径限制与 `StripPrefix` 行为

## 进一步阅读

- [根目录 README](../../README.md)
- [静态资源示例说明](../../examples/static/README.md)
- [静态资源设计说明](../../docs/static-design.md)
