# Gin 上游公开面对齐说明

本文档记录 `github.com/darkit/gin` 与上游 `github.com/gin-gonic/gin v1.12.0` 的当前对齐状态。

目标不是模糊地说“差不多兼容”，而是把以下三件事说清楚：

1. 现在是否已经补齐上游根包与公开子包的缺失导出。
2. 现在是否已经把最影响迁移的同名高频 API 调整回上游签名。
3. 还剩下哪些无法仅靠表层别名彻底抹平的结构性差异。

## 本次对齐后的结论

截至当前仓库状态：

- 上游根包公开名缺失已经清零。
- 上游公开子包 `binding`、`render`、`codec/json`、`ginS` 已全部可导入。
- `Engine` / `Router` / `Context` 上最关键的不兼容高频方法已经回到上游形状：
  - `Context.Param(key string) string`
  - `Context.Error(err error) *gin.Error`
  - `Context.Negotiate(code int, config gin.Negotiate)`
  - `Context.MustGet(key any) any`
  - `Engine.Use(...HandlerFunc) IRoutes`
  - `Engine/Router.GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Match|Handle`
  - `Static` / `StaticFS` / `StaticFile` / `StaticFileFS`
- 上游包级函数不再只是 `var` 桥接，而是恢复为真正的 `func` 声明，并返回本项目自己的 `HandlerFunc`。

## 已补齐的上游公开子包

当前仓库中，以下上游公开包已经可直接导入：

- `github.com/darkit/gin`
- `github.com/darkit/gin/binding`
- `github.com/darkit/gin/render`
- `github.com/darkit/gin/codec/json`
- `github.com/darkit/gin/ginS`

其中：

- `render` 已补齐上游公开的 `BSON` 导出。
- `codec/json` 直接补入了上游 codec 包公开面。
- `ginS` 已提供与上游同名的快捷入口包装。

## 仍然存在的结构性差异

虽然高频 API 形状已经大幅收敛，但因为本项目仍然保留“增强包装层”设计，仍有两类差异无法通过简单别名完全抹平：

### 1. 同名核心类型的类型身份仍不同

以下类型在“名字”上与上游一致，但类型身份不是同一个：

- `Context`
- `Engine`
- `HandlerFunc`
- `OptionFunc`
- `IRoutes`
- `IRouter`
- `RouterGroup`

这意味着：

- 从“把 import 从上游改成当前模块”这个角度看，高频调用方式已经基本兼容。
- 但从“二进制/反射层面与上游完全等同”这个角度看，仍不是纯粹的 type alias replacement。

### 2. `Context.Copy` 与 `Context.Handler` 仍保留 wrapper 痕迹

兼容扫描目前剩余的根包高风险方法差异主要集中在：

- `Context.Copy`
- `Context.Handler`

根因是当前项目仍然通过增强 `Context` 包装上游 `*gin.Context`，因此这两个方法返回值不可能在保留增强能力的同时与上游底层类型完全同构。

## 为兼容性新增的扩展入口

为了在恢复上游签名的同时保留原有增强能力，本次对齐把原本“挤占上游名字”的扩展能力迁移到了新的入口：

完整对照表与迁移示例，见 [扩展能力与兼容迁移对照表](extension-compat-mapping.md)。

- `Context.Input(...)`
  - 保留原先“路径 + query + form + 默认值”的聚合取参能力。
- `Context.ErrorResponse(code, message)`
  - 保留原先统一错误响应能力。
- `Context.AutoNegotiate(data)`
  - 保留原先按 `Accept` 自动协商响应格式的能力。
- `Engine.UseAny(...)`
- `Router.UseAny(...)`
  - 保留多种中间件类型自动适配能力。
- `Router.GETDoc` / `POSTDoc` / `PUTDoc` / `PATCHDoc` / `DELETEDoc` / `HEADDoc` / `OPTIONSDoc`
  - 在恢复上游 `GET/POST/...` 返回 `IRoutes` 后，保留 Swagger 文档链式注解能力。

## 仓库内联动调整

为保证兼容层真正闭环，而不是只改根包签名，本次还同步做了这些联动：

- `middleware/*` 已切换到使用本项目自己的 `gin.HandlerFunc` / `*gin.Context`
- 示例代码已更新到新的兼容 API 形状
- 旧的“记录不兼容差异”的契约测试，已改为新的“锁定当前兼容形状”的契约测试

## 复跑方式

### 全量测试

```bash
go test ./...
```

### 根包兼容扫描

```bash
GOWORK=off go run ./internal/tools/gincompat -format markdown
GOWORK=off go run ./internal/tools/gincompat -format json
```

注意：

- 当前 `gincompat` 工具主要扫描根包公开名与方法集。
- `codec/json`、`ginS` 这类公开子包的存在性需要结合 `go list ./...` 一起核对。

## 当前判断

如果以“迁移应用源码到 `github.com/darkit/gin` 并保持常见 Gin 用法尽量不改”为目标，当前兼容性已经进入可用状态。

如果目标是“对上游 `github.com/gin-gonic/gin` 做完全 type-identity 级替身”，当前设计仍受增强 wrapper 方案约束，剩余差异主要集中在核心类型身份以及 `Context.Copy/Handler` 这类天然绑定底层类型的方法上。
