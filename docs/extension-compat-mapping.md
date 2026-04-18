# 扩展能力与兼容迁移对照表

本文档整理 `github.com/darkit/gin` 当前仍保留的扩展能力，以及为了对齐上游 `github.com/gin-gonic/gin` 而改名的扩展入口。

适用场景：

- 想确认哪些增强能力仍可继续使用
- 想评估兼容上游后，哪些旧写法需要迁移
- 想快速查找“旧入口 -> 新入口”的替换关系

与上游公开面对齐状态，见 [Gin 上游公开面对齐说明](gin-upstream-compat.md)。

## 对照表

| 类别 | 能力或旧习惯 | 当前入口 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 保留 | chi 风格正则路由直接注册 | `Engine.GET/POST/...`、`Router.GET/POST/...` 直接传 `"/users/{id:[0-9]+}"` 这类 pattern | 保留 | 仍会自动接入 regex 路由层，标准 Gin 路由优先，未命中后再 fallback 到 regex |
| 保留 | 高级正则路由器 | `Engine.RegexRouter()` | 保留 | `Group()`、`Use()`、`Handle()`、`Match()`、`NotFound()`、`Handler()` 都还在 |
| 保留 | 资源路由 | `Router.Resource()`、`Router.CRUD()` | 保留 | RESTful 批量注册能力还在 |
| 保留 | 版本化路由 | `Router.Version()`、`Router.VersionedAPI()` | 保留 | 用法没有让位给上游 |
| 保留 | 健康检查 | `Router.HealthCheck()` | 保留 | 默认仍是 `/health` |
| 保留 | 静态资源扩展 | `Static()`、`StaticFS()`、`StaticFile()`、`StaticFileFS()` | 保留 | 包括 `StaticFileFS()` 这种扩展入口 |
| 保留 | 嵌入式静态资源 | `EmbedFS()`、`EmbedFile()` | 保留 | `embed.FS` 相关能力还在 |
| 保留 | 自动注册路由 | `AutoRegister()` | 保留 | 仍支持按控制器方法名推断 HTTP 方法和路径 |
| 保留 | 自动注册的 regex 定制 | `WithRegexPattern()`、控制器 `RegexPatterns()` | 保留 | 方法名以 `Regex` 结尾的规则仍然有效 |
| 保留 | 自动注册的前缀和中间件 | `WithPrefix()`、`WithMiddleware()` | 保留 | 自动注册场景下的扩展配置仍在 |
| 保留 | 增强参数解析和分页辅助 | `ParamInt()`、`ParamFloat()`、`ParamBool()`、`ParamSlice()`、`ParamTime()`、`ParsePagination()`、`PaginationParams()` | 保留 | 这些增强 helper 还在；其中 `ParamInt/ParamFloat/ParamBool` 等虽然保留了 `Param` 前缀，但读取语义实际基于 `Input(...)` 的聚合取值 |
| 保留 | 标准化响应 | `Success()`、`Created()`、`Accepted()`、`NoContent()`、`BadRequest()`、`ValidationError()`、`InternalError()` 等 | 保留 | 不属于上游同名冲突区，继续可用 |
| 保留 | 请求级组件透出 | `c.Auth()`、`c.Cache()`、`c.Logger()` | 保留 | 认证、缓存、日志能力仍能从增强 `Context` 直接拿 |
| 保留但行为调整 | 默认引擎组合 | `gin.Default()` | 保留但行为调整 | 默认仍会挂请求 ID、恢复、日志，但 `Logger()` 和 `Recovery()` 现在更接近上游兼容语义，不完全等同旧自定义 middleware 实现 |
| 改名 | 宽松输入获取 | `c.Input(key, def...)` | 已改名 | 原来把 `c.Param(...)` 当“路径 + query + form + 默认值”入口的写法，需要迁到 `Input()` |
| 改名 | 统一错误响应 | `c.ErrorResponse(code, message)` | 已改名 | 原增强 `c.Error(...)` 已让回给上游错误收集语义 |
| 改名 | 自动内容协商输出 | `c.AutoNegotiate(data)` | 已改名 | 原增强 `c.Negotiate(...)` 已让回给上游 `Negotiate(code, config)` 语义 |
| 改名 | 多签名中间件适配 | `Engine.UseAny(...)`、`Router.UseAny(...)` | 已改名 | 原增强 `Use(...)` 能混收增强处理器、原生 gin 处理器、`func(http.Handler) http.Handler`，现在迁到 `UseAny(...)` |
| 改名 | Swagger 路由文档链 | `GETDoc()`、`POSTDoc()`、`PUTDoc()`、`PATCHDoc()`、`DELETEDoc()`、`HEADDoc()`、`OPTIONSDoc()`，或 `LastRouteDoc()` | 已改名 | 不再使用 `GET(...).Doc(...)` 这种链式返回方式 |

## 常见迁移写法

下面这些替换最值得优先关注：

| 旧写法 | 新写法 |
| --- | --- |
| `c.Param("id", "0")` 或把 `Param` 当聚合输入读取 | `c.Input("id", "0")` |
| `c.Error(code, message)` 这类统一错误响应写法 | `c.ErrorResponse(code, message)` |
| `c.Negotiate(data)` 自动按 `Accept` 协商 | `c.AutoNegotiate(data)` |
| `r.Use(httpMw, enhancedMw, ginMw)` 混合签名中间件 | `r.UseAny(httpMw, enhancedMw, ginMw)` |
| `e.Use(httpMw, enhancedMw, ginMw)` 混合签名中间件 | `e.UseAny(httpMw, enhancedMw, ginMw)` |
| `r.GET("/x", h).Doc(...)` | `r.GETDoc("/x", h)` 或 `r.LastRouteDoc()` |

## 判断原则

可以用一个简单规则快速判断某个入口是否受本次兼容调整影响：

- 如果它本来就是本项目特有扩展，且没有占用上游 Gin 的同名高频 API，通常仍保持原名保留
- 如果它占用了上游 Gin 已存在且高频的名字，本次会优先把原名字让回上游语义，再为扩展行为提供新入口

## 代码与实现位置

这份对照表对应的核心实现主要分布在：

- `context.go`
- `engine.go`
- `router.go`
- `regex_router.go`
- `auto_register.go`

如果要核对当前仓库里的真实行为，应以源码和测试为准。
