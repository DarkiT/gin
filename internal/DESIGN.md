# internal 设计说明

`internal/` 目录放置只服务本仓实现与维护流程的内部能力，不作为对外公共 API 承诺。当前包含两类能力：

1. `internal/pathutil`：安全路径解析工具。
2. `internal/tools/gincompat`：Gin 上游公开面兼容矩阵生成工具。

## 设计原则

- **不外泄公共契约**：内部包可被本模块使用，但调用方不应依赖这些路径。
- **证据优先**：兼容性判断以当前源码、`go list`、AST 与 reflect 结果为准。
- **差异分级**：将 `synced`、`mapped`、`missing`、`local_only`、`incompatible` 分开，避免把增强 wrapper 的有意映射误判为缺失。
- **可复跑**：所有输出都应能通过命令本地重放，便于代码审查和 release gate 使用。

## `internal/pathutil`

`pathutil.SafePath(baseDir, userPath)` 用于将用户输入的相对路径安全落到指定根目录内。

核心约束：

- 拒绝空路径、`.`、绝对路径、UNC 路径、Windows drive 路径。
- 拒绝任何 `..` segment，避免目录穿越。
- 使用 `filepath.Clean` / `filepath.Rel` 二次确认最终路径没有越过 `baseDir`。

`pathutil.SafeTemplateName(name)` 用于校验模板名，拒绝空值、路径分隔符与 `..`。

## `internal/tools/gincompat`

`gincompat` 用于对照当前模块与 `github.com/gin-gonic/gin` 的公开面。它不是运行时逻辑，而是维护者工具。

### 输入来源

- 当前模块：`go list -m -json`
- 上游模块：`go list -m -json github.com/gin-gonic/gin`
- 包目录：`go list -f {{.Dir}} <import>`
- 导出符号：`go/parser` + `go/ast`
- 核心方法集：`reflect.Type`

### 扫描范围

当前工具覆盖：

- 根包 `github.com/darkit/gin`
- `binding`
- `render`
- `codec/json`
- `ginS`
- 核心类型方法集：`Context`、`Engine`、`Router` 对上游 `Context`、`Engine`、`RouterGroup`

### 状态语义

| 状态 | 含义 |
| --- | --- |
| `synced` | 名称、声明种类或方法签名已直接对齐 |
| `mapped` | 名称或方法存在，但因增强 wrapper 设计映射到本项目类型 |
| `missing` / `upstream_only` | 上游公开面在本地缺失，原则上应修复 |
| `local_only` | 本项目新增扩展能力 |
| `incompatible` | 同名方法存在但不在允许映射集合内，属于兼容风险 |

### 允许映射边界

允许映射集中在增强 wrapper 无法 type-identity 对齐的区域：

- `Context.Copy` 返回增强 `*Context`。
- `Context.Handler` 返回增强 `HandlerFunc`。
- `Engine` / `Router` 的路由注册方法使用增强 `HandlerFunc` / `IRoutes`。
- `Engine.Group` / `Router.Group` 返回增强 `RouterGroup` wrapper。

这些项必须在报告中标为 `mapped`，不得混入 `incompatible`。

### 复跑命令

```bash
GOWORK=off go run ./internal/tools/gincompat -format markdown
GOWORK=off go run ./internal/tools/gincompat -format json
```

推荐发布前门禁：

```bash
GOWORK=off go run ./internal/tools/gincompat -format json > /tmp/gincompat.json
```

然后检查：

- 根包 `missing == 0`
- 子包 `missing == 0`
- 子包 `mapped == 0`
- 子包 `local_only == 0`
- 核心方法集 `incompatible == 0`
- 核心方法集 `upstream_only == 0`

## 维护约束

1. 升级 `github.com/gin-gonic/gin` 后，必须先复跑 `gincompat`，再判断是否需要补 API。
2. 若新增上游公开子包镜像，应把它加入 `compareSubpackages(...)`。
3. 若新增 wrapper 映射，必须同步：
   - `compatibleMappedMethods(...)`
   - `docs/gin-upstream-compat.md`
   - 对应契约测试
4. 若 `gincompat` 出现 `missing`、`upstream_only` 或 `incompatible`，不能只改文档压制；必须先确认是否真实兼容缺口。
