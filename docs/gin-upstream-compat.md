# Gin 上游公开面对齐说明

本文档记录 `github.com/darkit/gin` 与上游 `github.com/gin-gonic/gin v1.12.0` 的当前对齐状态。

目标不是模糊地说“差不多兼容”，而是把以下三件事说清楚：

1. 现在是否已经补齐上游根包与公开子包的缺失导出。
2. 现在是否已经把最影响迁移的同名高频 API 调整回上游签名。
3. 哪些差异属于增强 wrapper 的“显式映射”，而不是缺失或未实现。

## 本次对齐后的结论

截至当前仓库状态：

- 上游根包公开名缺失已经清零。
- 上游公开子包 `binding`、`render`、`codec/json`、`ginS` 已全部可导入。
- `gincompat` 兼容矩阵已把“缺失 / 已映射 / 本地新增”分开呈现，当前根包方法集已无 `incompatible` / `upstream_only` 项。
- `Engine` / `Router` / `Context` 上最关键的不兼容高频方法已经回到上游形状：
  - `Context.Param(key string) string`
  - `Context.Error(err error) *gin.Error`
  - `Context.Negotiate(code int, config gin.Negotiate)`
  - `Context.MustGet(key any) any`
  - `Engine.Use(...HandlerFunc) IRoutes`
  - `Engine/Router.GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Match|Handle`
  - `Engine/Router.Group`
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

- `binding` 已补齐上游公开的 `MIMEBSON`、`BSON`，并将 `Default`、`MapFormWithTag` 恢复为真正的 `func` 声明。
- `render` 已补齐上游公开的 `BSON` 导出。
- `render.WriteJSON`、`render.WriteMsgPack`、`render.WriteString` 已恢复为真正的 `func` 声明。
- `codec/json` 直接补入了上游 codec 包公开面。
- `ginS` 已提供与上游同名的快捷入口包装。

## 显式映射的结构性差异

虽然高频 API 形状已经大幅收敛，但因为本项目仍然保留“增强包装层”设计，仍有两类差异需要按“映射兼容”理解：

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

### 2. 核心方法返回增强 wrapper 类型

兼容扫描会把以下方法标为 `mapped`，而不是 `incompatible`：

- `Context.Copy`
- `Context.Handler`
- `Engine/Router.Group`
- `Engine/Router.Use|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Match|Handle|Static*`

根因是当前项目仍然通过增强 `Context` / `Engine` / `Router` 包装上游类型。
这些方法的调用形态与上游一致，但参数或返回值会落在本项目增强类型上，以便继续提供扩展能力。

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

### 子包公开面扫描

`gincompat` 当前同时扫描：

- 根包导出符号
- 根包核心类型方法集
- `binding`
- `render`
- `codec/json`
- `ginS`

## 当前判断

如果以“迁移应用源码到 `github.com/darkit/gin` 并保持常见 Gin 用法尽量不改”为目标，当前兼容性已经进入可用状态。

如果目标是“对上游 `github.com/gin-gonic/gin` 做完全 type-identity 级替身”，当前设计仍受增强 wrapper 方案约束；这不是缺失实现，而是本项目保留增强能力所需的公开映射边界。
