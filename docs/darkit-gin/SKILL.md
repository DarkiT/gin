---
name: darkit-gin
description: Use this skill when building, modifying, documenting, or debugging services that use `github.com/darkit/gin`, including enhanced `Engine`/`Router`/`Context`, auth flows, middleware composition, regex routes, uploads/downloads/exports, image or masking handlers, WebSocket handlers, static or SPA delivery, streaming/webhook handlers, probes, Swagger/OpenAPI, and framework integration issues.
---

# darkit-gin

这个 Skill 的定位不是“全文 API 手册”，而是：

- 帮你快速判断任务落在哪个能力面
- 只加载最小必要资料
- 直接给出可复制的上手模板
- 避免被旧语义、旧示例、上游 Gin 与本项目增强语义的差异误导

## 默认工作方式

1. 先从调用方视角理解任务，而不是从内部实现视角展开
2. 优先读取 `references/` 中最少量、最贴近任务的文件
3. 优先复用 `assets/examples/` 的模板，而不是临时凭记忆写一份
4. 需要核对真实行为时，再到当前 workspace 搜索 live code 和测试

## 什么时候触发

当任务涉及以下任一场景时使用：

- 基于 `github.com/darkit/gin` 新建或修改 HTTP 服务
- 设计或调整 `Engine`、`Router`、`Context` 用法
- 需要先盘点这个框架到底提供哪些真实能力
- 接入 `auth`、`middleware`、`pkg/*` 能力
- 使用 `Resource`、`CRUD`、`AutoRegister`、`RegexRouter`
- 接入 `Problem Details`、SSE、NDJSON、cursor pagination、webhook helper
- 处理上传、下载、导出、图片处理、脱敏、WebSocket
- 处理静态资源、SPA、ZIP、嵌入式前端交付
- 配探针、OpenAPI、Swagger、默认错误模型、OTel
- 为该框架编写模板、文档、示例或排查集成问题

## 最小心智模型

先记住 6 块：

1. `Engine`：服务入口、Option、provider、生命周期
2. `Router`：路由注册、分组、regex、静态挂载、OpenAPI 路由文档
3. `Context`：参数、绑定、响应、文件、导出、认证、流式能力
4. `auth/`：登录、权限、session、token
5. `middleware/`：请求治理、安全、观测、流量控制
6. `pkg/*`：static、swagger、cache、routes、mail、sms 等能力

## 先读什么

### 通用起步

优先只读：

- `./references/capability-inventory.md`
- `./references/quickstart.md`
- `./references/context-cheatsheet.md`

### 任务路由

| 任务 | 先读这些 |
| --- | --- |
| 先判断框架有哪些真实能力 | `./references/capability-inventory.md` |
| 最小服务 / 标准 API | `./references/quickstart.md` |
| `Engine` 初始化、Option、provider 注入 | `./references/engine-options.md` |
| `Context` 高频用法 | `./references/context-cheatsheet.md` |
| 路由、版本化、自动注册、regex | `./references/router-patterns.md` |
| 认证登录流 | `./references/auth-integration.md` |
| 中间件与 OTel | `./references/middleware-catalog.md` |
| Problem Details / SSE / NDJSON / webhook / cursor pagination / probes / OpenAPI | `./references/feature-recipes.md` |
| 上传 / 下载 / 导出 / 图片 / 脱敏 / WebSocket | `./references/context-cheatsheet.md` + `./references/feature-recipes.md` |
| 静态资源 / SPA / ZIP / embed | `./references/static-site-recipes.md` |
| 排障 | `./references/troubleshooting.md` |
| 需要进入本仓细节文档 | `./references/repo-doc-map.md` |

### 配套模板

- `./assets/examples/basic_server.go.tmpl`
- `./assets/examples/auth_flow.go.tmpl`
- `./assets/examples/middleware_chain.go.tmpl`
- `./assets/examples/file_upload_download.go.tmpl`
- `./assets/examples/export_excel_csv.go.tmpl`
- `./assets/examples/auto_register_routes.go.tmpl`
- `./assets/examples/streaming_webhook.go.tmpl`
- `./assets/examples/static_site.go.tmpl`
- `./assets/examples/full_featured.go.tmpl`

## 当前必须遵守的语义边界

这些点最容易受旧文档或上游 Gin 心智影响，回答和实现时必须按当前项目代码处理：

- `Param(key)` 只读路径参数；聚合读取请用 `Input(key, def...)`
- `ParamInt` / `ParamBool` 等增强 helper 实际也是基于 `Input(...)`
- `Error(...)` 是上游 Gin 错误收集语义；统一错误响应请用 `ErrorResponse(...)` 或 `Problem(...)`
- `Negotiate(code, config)` 保持上游兼容；项目增强自动协商请用 `AutoNegotiate(...)`
- `Use(...)` 只接增强 `HandlerFunc`
- 需要混用 `gin.HandlerFunc`、标准 `http` middleware 时，用 `UseAny(...)`
- `Static*` / `Embed*` 是直接路由注册
- `Assets*` / `Site*` / `FallbackSite*` 是通过 `NoRoute` 受控兜底，不应描述成普通 catch-all 路由
- `GET(...).Doc(...)` 不再是推荐链路，使用 `GETDoc/POSTDoc/...`

## 读取策略

### 第一层：Skill 内 references

先看 Skill 内文件，不要一次性把整个仓库文档都塞进上下文。

### 第二层：模板优先

如果任务属于常见接入场景，优先从 `assets/examples/*.tmpl` 复制改写。

### 第三层：live code

需要确认真实签名、返回值、行为边界时，在当前 workspace 搜索：

- `engine.go`
- `router.go`
- `router_static_ext.go`
- `router_probes.go`
- `context*.go`
- `options.go`
- `auto_register.go`
- `regex_router.go`
- `middleware/`
- `pkg/static/`
- `pkg/swagger/`
- `examples/`

### 第四层：repo 文档

只有在你确认当前 workspace 就是 `github.com/darkit/gin` 本仓时，再读：

- `./references/repo-doc-map.md`

## 回答与实现风格

- 先给接入方能直接使用的结论
- 再补最小必要解释
- 优先给“推荐写法”，其次才是“兼容旧写法”
- 如果某处旧语义已经回收给上游 Gin，要明确指出替代入口
- 如果示例有多种可能，默认给更简单、更稳、更贴近当前项目推荐路径的一种
