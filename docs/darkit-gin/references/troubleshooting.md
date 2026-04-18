# Troubleshooting

这份文件用于第一轮排障，重点是快速发现“你是不是用了旧语义或错误入口”。

## 目录

- 总体顺序
- 高频问题
- 现场搜索建议
- 一个简单的判断原则

## 总体顺序

1. 先判断问题落在哪层：Engine / Router / Context / auth / middleware / static / swagger
2. 再确认是不是用了过期写法或错误入口
3. 然后搜索 live code 与测试
4. 若当前 workspace 就是 gin 本仓，再进入 `repo-doc-map.md`

## 高频问题

### 1. 参数取值不对

优先检查：

- 你是不是把 `Param(...)` 当成聚合取值了
- 你真正想要的是不是 `Input(...)`
- `ParamInt/ParamBool` 等增强 helper 是否更适合当前场景

典型现象：

- 路径参数能读到，query/form 读不到
- 文本默认值逻辑和预期不一致

先读：

- `./context-cheatsheet.md`

### 2. 错误响应结构不对

优先检查：

- 是否误用了 `c.Error(...)`
- 是否应该改用 `ErrorResponse(...)`
- 对外 API 是否更适合 `Problem(...)` / `ValidationProblem(...)`

先读：

- `./context-cheatsheet.md`
- `./feature-recipes.md`

### 3. 中间件挂不上或类型不匹配

优先检查：

- 你是不是把 gin middleware 直接传给了 `Use(...)`
- 当前场景是否应该用 `UseAny(...)`
- 是否有 middleware 已经提前写响应并 `Abort`

先读：

- `./middleware-catalog.md`

### 4. 路由命中了但不是你想要的 handler

优先检查：

- 是普通路由、regex 路由还是静态挂载在生效
- 是否理解错了优先级
- `AutoRegister` 的方法名是否真的会推导成你想要的路径

当前优先级要记住：

1. 普通路由
2. regex 路由
3. `Assets*` / `Site*` / `FallbackSite*`
4. 用户 `NoRoute`

先读：

- `./router-patterns.md`
- `./static-site-recipes.md`

### 5. SPA / 静态站点没有按预期兜底

优先检查：

- 你是否用了 `Static*`，而其实应该用 `Site*` 或 `FallbackSite*`
- 当前请求是否真的是 HTML 请求
- 是否把静态资源树和站点兜底挂在了错误前缀

先读：

- `./static-site-recipes.md`

### 6. Swagger / OpenAPI 不够机器友好

优先检查：

- 是否还在使用旧的链式文档心智
- 是否缺少 `OperationID`
- 是否没有补 `DefaultErrors(...)` / `ProblemResponse(...)`
- 是否缺少 request / response examples

先读：

- `./feature-recipes.md`

### 7. `c.Auth()` 不可用

优先检查：

- 是否通过 `WithAuth(...)` 初始化了引擎
- 当前 handler 是否运行在该 `Engine` 上

先读：

- `./auth-integration.md`

### 8. 探针 / webhook / 流式行为不对

优先检查：

- 探针是否用 `NamedProbe(...)` 正确挂载
- webhook 是否使用了 `RawBody()` 而不是先把 body 消耗掉
- SSE / NDJSON 是否在写出后又继续返回普通 JSON

先读：

- `./feature-recipes.md`

## 现场搜索建议

优先搜索：

- `engine.go`
- `engine_static.go`
- `router.go`
- `router_static_ext.go`
- `router_probes.go`
- `context*.go`
- `pkg/static/`
- `examples/streaming/main.go`
- `examples/probes/main.go`
- `examples/swagger-demo/main.go`

## 一个简单的判断原则

如果你发现“代码看起来像 Gin，但行为又不像 Gin”，先检查这是不是：

- 上游兼容入口
- 项目增强入口
- 旧增强入口的迁移点

很多问题的根源其实不是实现 bug，而是入口用错了。
