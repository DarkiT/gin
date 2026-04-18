# 静态资源设计说明

本文说明当前静态资源重构后的设计边界、优先级以及推荐用法。

## 背景

原有静态资源能力主要分为两类：

- 根包中的 `Static` / `StaticFS` / `StaticFile` / `EmbedFS`
- `pkg/static` 中面向 ZIP 的 `RegisterZipFS` / `RegisterZipFile`

这套能力能覆盖基本文件暴露场景，但在“前端站点兜底”“嵌入式 ZIP”“避免 catch-all 路由抢占业务路由”这几个高频需求上不够顺手。

本次重构的目标是：

- 区分“普通静态资源”和“前端站点”两类语义
- 让资源来源与路由挂载方式解耦
- 在不影响普通路由与 regex 路由的前提下提供站点兜底

## 语义分层

### 1. `Static*` / `Embed*`

与上游 Gin 对齐，直接注册普通路由。

适合：

- 明确的目录映射
- 单文件暴露
- 不需要 history fallback 的只读资源

### 2. `Assets*`

表示“静态资源目录”语义。

适合：

- JS / CSS / 图片 / 字体 / 下载文件
- 管理后台资源目录
- 不希望未命中时自动落回首页的路径

特点：

- 通过 `NoRoute` 受控兜底
- 文件未命中时直接放弃处理，不自动回退到 `index.html`

### 3. `Site*`

表示“前端站点”语义。

适合：

- SPA
- 后台控制台
- 前端构建产物托管

特点：

- 支持 `index.html`
- 支持 history fallback
- 支持自定义 `404.html`
- 同样通过 `NoRoute` 受控兜底

### 4. `FallbackSite*`

表示“全站未命中时交给前端站点”。

适合：

- 前后端同服务部署
- 除 `/api/*` 外全部交给前端路由
- 单页应用全局接管

## 资源来源

当前统一支持以下来源：

- 本地目录
- 任意 `http.FileSystem`
- ZIP 文件
- 嵌入式 ZIP

对应入口包括：

- `Assets` / `AssetsFS` / `AssetsZip` / `AssetsEmbeddedZip`
- `Site` / `SiteFS` / `SiteZip` / `SiteEmbeddedZip`
- `FallbackSite` / `FallbackSiteFS` / `FallbackSiteZip` / `FallbackSiteEmbeddedZip`

## 路由优先级

为了避免静态站点挂载与业务路由互相冲突，当前顺序固定为：

1. 普通 Gin 路由
2. regex 路由
3. `Assets*` / `Site*` / `FallbackSite*`
4. 用户 `NoRoute`

这意味着：

- `SiteFS("/app", ...)` 不会抢 `/app/health` 这样的普通路由
- regex 路由例如 `/app/{id:[0-9]+}` 也会优先于站点兜底
- `FallbackSiteFS("/")` 更像“最终前端接管层”，而不是全局 catch-all 普通路由

## 具体行为

### `Assets`

- 命中具体文件则返回文件
- 命中目录时可返回目录下的 `index.html`
- 文件不存在时直接放弃处理

### `Site`

- 命中具体文件则返回文件
- 命中目录时返回目录下的 `index.html`
- 未命中且请求明确接受 HTML 时，可回退到首页
- 若配置了 `WithNotFoundFile("404.html")`，则在未命中时返回该文件

### HTML 请求判定

为了避免把普通 API 请求错误地回退到前端首页，history fallback 只在以下情况下生效：

- 请求方法为 `GET` 或 `HEAD`
- 路径不带文件扩展名
- `Accept` 头显式包含 `text/html` 或 `application/xhtml+xml`

## ZIP 能力

### ZIP 文件

`NewZipFileSystem` 仍然保留，适合：

- 运行时加载 ZIP 包
- 密码保护 ZIP
- 热更新 ZIP

### 嵌入式 ZIP

新增 `NewEmbeddedZipFS`，适合：

- 单二进制分发
- 通过 `embed.FS` 承载前端构建产物 ZIP
- 不希望运行时依赖外部文件

当前嵌入式 ZIP 暂不支持密码保护。

## Option 语义

### 站点 / 资源通用

- `WithIndexFile(...)`
- `WithHistoryFallback()`
- `WithoutHistoryFallback()`
- `WithNotFoundFile(...)`

### ZIP 专用

- `WithHotReload(...)`
- `WithPassword(...)`
- `WithSubPaths(...)`
- `WithStripPrefix(...)`
- `WithFallback(...)`

其中 `WithFallback(...)` 用于“ZIP 文件系统不可用”时的回退，不等同于“文件未命中时的站点兜底”。

## 推荐用法

### 场景 1：纯资源目录

```go
r.Assets("/assets", "./public")
```

### 场景 2：前端子站点

```go
r.Site("/app", "./dist")
```

### 场景 3：全站 SPA 接管

```go
e.FallbackSite("./dist")
```

### 场景 4：单文件分发的后台站点

```go
_ = r.SiteZip("/admin", "./admin.zip")
```

### 场景 5：单二进制嵌入前端

```go
_ = e.FallbackSiteEmbeddedZip(assets, "ui/app.zip")
```

## 兼容策略

- 旧的 `Static*` / `Embed*` 全部保留
- `pkg/static.RegisterZipFS` / `RegisterZipFile` 保留兼容
- 新增 `Assets*` / `Site*` / `FallbackSite*` 作为更高层、更安全的推荐入口
