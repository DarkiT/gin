---
name: darkit-gin
description: "Work with github.com/darkit/gin as a framework Skill. Use when integrating the framework into application projects or maintaining this repository: service bootstrap, migration from gin-gonic/gin, Engine/Router/Context usage, auth, middleware, cache/storage, uploads/downloads/exports, streaming/webhooks, static or SPA delivery, probes, Swagger/OpenAPI, upstream compatibility, public API changes, docs/examples sync, tests, and release gates."
---

# darkit-gin

这个 Skill 是 `github.com/darkit/gin` 的可复用操作手册：既服务上层应用接入，也服务本仓维护。每次先确认当前 workspace 是“调用方项目”还是“框架仓库”，再选择对应链路。

## 上下文判定

先看 `go.mod`：

```bash
go list -m
```

- 输出为 `github.com/darkit/gin`：进入 **本仓维护模式**，以源码、测试、docs、`internal/tools/gincompat` 为准。
- 其他 module：进入 **应用接入模式**，优先保持调用方目录结构，不默认读取框架内部源码。

## 固定工作流

1. **先读后写**
   - 先读 `go.mod`、入口、相关源码、近邻测试、当前 docs。
   - 用 `rg`、`go doc`、聚焦文件读取定位事实；不要凭记忆改公共 API。
2. **选择 lane**
   - Gin 迁移 / 新服务：从 `references/quickstart.md` 开始。
   - Engine / Router / Context：从对应 reference 开始，再查 live code。
   - auth / cache / middleware / static / streaming / Swagger：只读对应专项 reference。
   - 上游兼容或公共 API：进入本仓维护门禁，先查兼容文档与 `gincompat`。
3. **保持契约**
   - 与上游 `github.com/gin-gonic/gin` 同名 API 优先保持上游调用形态。
   - Darkit 增强能力用显式扩展入口承载，不抢占上游语义。
   - 导出符号必须有准确 Go doc；公共行为变化必须同步 docs 和模板。
4. **最小落刀**
   - 行为修复与重构分离。
   - 不引入未要求的新依赖。
   - 安全路径、上传、静态资源等敏感逻辑优先复用仓内已有 helper。
5. **验证闭环**
   - 先跑最小相关测试，再按影响面升级验证。
   - 改公共 API、示例或 docs 时，同时更新 `docs/darkit-gin/` 下 references/assets。

## 任务路由表

| 任务 | 先读 | 可复用模板 / 继续查 |
| --- | --- | --- |
| 3-5 分钟跑通服务 | `references/quickstart.md` | `assets/examples/basic_server.go.tmpl` |
| 从 `gin-gonic/gin` 迁移 | `references/quickstart.md`、`references/context-cheatsheet.md` | `docs/gin-upstream-compat.md` |
| Engine 配置、生命周期、provider | `references/engine-options.md` | `engine.go`、`options.go` |
| 路由分组、资源路由、regex、AutoRegister | `references/router-patterns.md` | `router.go`、`regex_router.go`、`auto_register.go` |
| Context、参数、响应、上传下载 | `references/context-cheatsheet.md` | `context*.go`、`upload.go`、相关 tests |
| Auth / session / permission | `references/auth-integration.md` | `auth/README.md`、`auth/DESIGN.md` |
| Cache / storage / idempotency | `references/cache-storage-integration.md` | `pkg/cache`、`pkg/storage`、`middleware/cache.go` |
| Middleware 组合 | `references/middleware-catalog.md` | `middleware/README.md`、`middleware/` |
| Problem / SSE / NDJSON / webhook / probes / OpenAPI | `references/feature-recipes.md` | `examples/streaming`、`examples/probes`、`pkg/swagger` |
| 静态资源 / SPA / ZIP / embed | `references/static-site-recipes.md` | `docs/static-design.md`、`pkg/static`、`engine_static.go` |
| 能力盘点与误用排查 | `references/capability-inventory.md` | `docs/api-reference.md`、`README.md` |
| 应用侧排障 | `references/troubleshooting.md` | 失败日志、请求复现、调用方测试 |
| 本仓结构与文档地图 | `references/repo-doc-map.md` | `DESIGN.md`、`internal/DESIGN.md` |

## 应用接入模式

默认保持调用方项目结构，按三种接入强度选一条：

- **Gin-compatible mode**：尽量沿用上游 Gin 写法，只把 import 切到 `gin "github.com/darkit/gin"`。
- **Enhanced mode**：使用 `gin.New/Default`、`Router()`、增强 `Context`、标准响应、regex、auto-register。
- **Infrastructure mode**：接入 auth、cache/storage、middleware、static、Swagger、probes 等生产能力。

交付应用侧改动时给出：改动文件、核心代码、配置项、验证命令、最小 `curl` / `httptest`、生产风险点。

## 本仓维护模式

确认当前 module 是 `github.com/darkit/gin` 后，再使用仓内维护门禁。

### 公共 API 兼容规则

- `Context.Param`、`Query`、`PostForm`、`DefaultQuery`、`DefaultPostForm` 保持上游单一来源语义。
- 聚合读取使用 `Input(...)`；`ParamInt` 等增强 helper 基于聚合输入解析。
- `Context.Error(err error) *gin.Error` 保持上游错误收集语义；统一错误响应使用 `ErrorResponse(...)`、`Problem(...)` 或 typed helpers。
- `Negotiate(code, gin.Negotiate)` 保持上游语义；自动协商使用 `AutoNegotiate(...)`。
- `Use(...)`、`GET(...)`、`Group(...)`、`Static*` 保持 Gin-like 调用形态；混合中间件签名使用 `UseAny(...)`。
- Wrapper 类型身份可不同，但参数、返回值、使用方式必须是有意映射，并在兼容文档中说明。

### 上传安全规则

- `ToDir(...)`：上传根目录。
- `ToSubDir(...)`：安全相对子目录。
- `AsName(...)`：纯文件名。
- `NameBy(...)`：批量上传逐文件命名。
- 复用 `internal/pathutil.SafePath(...)`，不要另造目录穿越校验。
- `SaveFiles(...)` 必须先规划全部目标，再以 `ErrDuplicateUploadTarget` 拒绝重复解析目标。
- `UploadResult.RelativePath` 是相对上传根目录、slash-normalized 的应用侧稳定路径。

## 验证门禁

按影响面选择，公共 API / 行为变更默认跑全：

```bash
gofmt -w <changed-go-files>
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
git diff --check
```

上游兼容工作追加：

```bash
GOWORK=off go run ./internal/tools/gincompat -format markdown
GOWORK=off go run ./internal/tools/gincompat -format json
```

兼容门禁关注：根包 / 子包 `missing == 0`，核心方法 `upstream_only == 0`，`incompatible == 0`；新增映射必须同步 `internal/tools/gincompat`、契约测试和 `docs/gin-upstream-compat.md`。

## 文档同步面

公共用法或 API 变化时，同步检查：

- `README.md`
- `docs/usage.md`
- `docs/api-reference.md`
- `docs/gin-upstream-compat.md`
- `docs/extension-compat-mapping.md`
- `docs/darkit-gin/references/*.md`
- `docs/darkit-gin/assets/examples/*.tmpl`

上传 API 变化尤其要同步 `references/context-cheatsheet.md` 与 `assets/examples/file_upload_download.go.tmpl`。
