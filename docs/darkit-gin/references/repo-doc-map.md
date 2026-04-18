# Repo Doc Map

这份文件只在你已经确认当前 workspace 就是 `github.com/darkit/gin` 本仓时使用。

## 目录

- 使用前提
- 先看哪些仓库文档
- 优先看的示例
- 核心源码入口
- 当你在查什么时，先看哪里
- 使用建议

## 使用前提

先确认：

- 当前目录存在 `go.mod`
- `go.mod` 中的 `module` 为 `github.com/darkit/gin`

如果不满足，请停止使用下面这些 repo-local 路径，改为搜索 live code。

## 先看哪些仓库文档

### 根文档

- `README.md`
- `docs/usage.md`
- `docs/api-reference.md`
- `docs/gin-upstream-compat.md`
- `docs/extension-compat-mapping.md`
- `docs/static-design.md`
- `docs/cache_middleware.md`
- `SWAGGER_IMPLEMENTATION.md`

### auth 子系统

- `auth/README.md`
- `auth/DESIGN.md`
- `auth/API.md`

### middleware 子系统

- `middleware/README.md`
- `middleware/DESIGN.md`

### pkg 子模块

- `pkg/static/README.md`
- `pkg/swagger/README.md`
- `pkg/routes/README.md`
- `pkg/cache/README.md`
- `pkg/export/README.md`
- `pkg/lifecycle/README.md`
- `pkg/logger/README.md`
- `pkg/mail/README.md`
- `pkg/mask/README.md`
- `pkg/sms/README.md`
- `pkg/validator/README.md`
- `pkg/websocket/README.md`

## 优先看的示例

- `examples/basic/main.go`
- `examples/advanced/main.go`
- `examples/auto-register/main.go`
- `examples/swagger-demo/main.go`
- `examples/streaming/main.go`
- `examples/probes/main.go`
- `examples/static/README.md`

说明：

- 示例 README 方便理解场景
- 真实签名、返回值和行为边界仍以对应 `main.go` 与测试为准

## 核心源码入口

- `engine.go`
- `engine_static.go`
- `router.go`
- `router_static_ext.go`
- `router_probes.go`
- `options.go`
- `auto_register.go`
- `regex_router.go`
- `context.go`
- `context_problem.go`
- `context_stream.go`
- `context_cursor_pagination.go`
- `context_webhook_helpers.go`
- `context_trace.go`
- `context_upload.go`
- `context_export.go`
- `context_image.go`
- `context_mask.go`
- `context_auth.go`
- `context_websocket.go`

## 当你在查什么时，先看哪里

| 你要确认什么 | 先看哪里 |
| --- | --- |
| Gin 兼容边界 | `docs/gin-upstream-compat.md` |
| 老增强入口改名关系 | `docs/extension-compat-mapping.md` |
| 静态站点 / SPA / ZIP 设计 | `docs/static-design.md`、`pkg/static/README.md` |
| Swagger / OpenAPI | `SWAGGER_IMPLEMENTATION.md`、`examples/swagger-demo/main.go` |
| 流式 / webhook / cursor | `examples/streaming/main.go` |
| 探针 | `examples/probes/main.go` |

## 使用建议

- 先用 Skill 内 references 建立方向
- 再用这里的 repo 文档做现场核对
- 最后去 live code / 测试确认边界
