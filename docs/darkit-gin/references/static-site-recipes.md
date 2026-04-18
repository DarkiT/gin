# Static & Site Recipes

这份文件帮助你在 1 分钟内判断应该用哪套静态资源入口。

## 目录

- 先做选择
- 当前优先级一定要记住
- 典型写法
- Option 怎么选
- 常见误区
- 什么时候继续看 repo 代码

## 先做选择

### 1. 只想暴露目录或文件

用：

- `Static`
- `StaticFS`
- `StaticFile`
- `EmbedFS`
- `EmbedFile`

特点：

- 与上游 Gin 心智一致
- 直接注册普通路由

### 2. 想托管静态资源树，但不想抢业务路由

用：

- `Assets`
- `AssetsFS`
- `AssetsZip`
- `AssetsEmbeddedZip`

特点：

- 文件未命中不会自动回退到首页
- 通过 `NoRoute` 受控兜底
- 不会抢普通路由和 regex 路由

### 3. 想托管前端站点 / SPA

用：

- `Site`
- `SiteFS`
- `SiteZip`
- `SiteEmbeddedZip`

特点：

- 支持 `index.html`
- 支持 history fallback
- 可配 `WithNotFoundFile("404.html")`

### 4. 想让前端接管全站未命中路由

用：

- `FallbackSite`
- `FallbackSiteFS`
- `FallbackSiteZip`
- `FallbackSiteEmbeddedZip`

特点：

- 更像“最后一层前端接管”
- 不是普通 catch-all 路由

## 当前优先级一定要记住

1. 普通路由
2. regex 路由
3. `Assets*` / `Site*` / `FallbackSite*`
4. 用户 `NoRoute`

所以：

- `/api/ping` 这类业务接口会优先
- `/orders/{id:[0-9]+}` 这类 regex 路由也会优先
- `FallbackSite("./dist")` 不会抢掉前面两类

## 典型写法

### 普通资源目录

```go
r.Assets("/assets", "./public")
```

### 前端子站点

```go
r.Site("/app", "./dist")
```

### 全站 SPA

```go
e.FallbackSite("./dist")
```

### ZIP 站点

```go
if err := r.SiteZip("/admin", "./admin.zip"); err != nil {
    panic(err)
}
```

### 嵌入式 ZIP

```go
if err := e.FallbackSiteEmbeddedZip(assets, "ui/app.zip"); err != nil {
    panic(err)
}
```

模板：

- `../assets/examples/static_site.go.tmpl`

repo 文档：

- `docs/static-design.md`
- `pkg/static/README.md`
- `examples/static/README.md`

## Option 怎么选

通用高频选项：

- `WithIndexFile("index.html")`
- `WithHistoryFallback()`
- `WithoutHistoryFallback()`
- `WithNotFoundFile("404.html")`

ZIP 相关附加选项：

- `WithHotReload(...)`
- `WithPassword(...)`
- `WithSubPaths(...)`
- `WithStripPrefix(...)`

## 常见误区

- 用 `Static` 做 SPA history fallback
- 以为 `Assets` 命不中会自动回首页
- 把 `FallbackSite` 理解成普通路由级别的 catch-all
- 忘了 HTML 请求判定，结果误以为站点兜底失效

## 什么时候继续看 repo 代码

当你需要确认这些边界时，再进 repo：

- 静态优先级是否和业务路由冲突
- ZIP / embedded ZIP 的具体行为
- `WithNotFoundFile` 与 `HistoryFallback` 的交互

对应入口：

- `engine_static.go`
- `router_static_ext.go`
- `pkg/static/service.go`
- `pkg/static/embedded_zipfs.go`
- `pkg/static/zipfs.go`
