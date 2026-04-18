# Router Patterns

这份文件从“如何组织对外接口”出发，而不是从内部实现出发。

## 目录

- 路由入口怎么选
- regex 路由的真实心智
- 中间件注册怎么选
- 健康检查与探针
- 静态资源与站点交付
- Swagger / OpenAPI 路由文档
- 选择建议
- 常见误区

## 路由入口怎么选

### 1. 普通路由

最常用，也应该是默认入口：

- `GET`
- `POST`
- `PUT`
- `PATCH`
- `DELETE`
- `HEAD`
- `OPTIONS`
- `Any`
- `Match`

处理器签名：

```go
func(c *gin.Context)
```

### 2. 分组与版本化

- `Group(path, handlers...)`
- `Version(v)`
- `VersionedAPI(v, setup)`

适合：

- `/api`
- `/api/v1`
- 按业务域拆路由组

### 3. 资源路由

- `Resource(name, ctrl, opts...)`
- `CRUD(name, ctrl)`

适合：

- 标准 REST 风格控制器
- 明确有 `Index/Show/Create/Update/Patch/Destroy` 这组动作

### 4. 自动注册

- `AutoRegister(controller, opts...)`

适合：

- 后台 / 管理面控制器
- 想减少显式路由样板代码

不适合：

- 对 URL 设计要求非常明确、非常稳定的公开 API

### 5. regex 路由

最推荐的写法不是先拿 `RegexRouter()`，而是直接在普通注册方法里写 chi 风格 pattern：

```go
r.GET("/users/{id:[0-9]+}", handler)
```

只有在你需要这些高级控制时，才显式用 `RegexRouter()`：

- `Match()`
- `NotFound()`
- `Handler()`
- 纯 regex `Group/Use`

## regex 路由的真实心智

- 普通路由优先
- regex 路由在 `NoRoute` 链路中作为 fallback
- 命中后的参数仍通过 `c.Param("id")` 读取

也就是说，不要把 regex 路由理解成“比普通路由更高优先级”的另一套路由表。

## 中间件注册怎么选

### `Use(...)`

只接增强 `HandlerFunc`。

### `UseAny(...)`

混合签名时使用，支持：

- 增强 `HandlerFunc`
- 原生 `gin.HandlerFunc`
- `func(http.Handler) http.Handler`

如果你要接 `middleware.CORS()`、`middleware.Timeout(...)`、Chi 风格中间件，默认用 `UseAny(...)`。

## 健康检查与探针

### 快速接口

- `HealthCheck(path...)`
- `Liveness(path...)`
- `Readiness(checks...)`
- `ReadinessAt(path, checks...)`
- `Startup(checks...)`
- `StartupAt(path, checks...)`

### 推荐写法

```go
r.Readiness(
    gin.NamedProbe("database", func(c *gin.Context) error { ... }),
    gin.NamedProbe("cache", func(c *gin.Context) error { ... }),
)
```

## 静态资源与站点交付

### 直接注册型

- `Static*`
- `Embed*`

特点：

- 与上游 Gin 更接近
- 直接注册普通路由

### 受控挂载型

- `Assets*`
- `Site*`
- `FallbackSite*`

特点：

- 不会抢普通路由
- 不会抢 regex 路由
- 更适合 SPA、前端构建产物、ZIP/嵌入式交付

静态交付细节请直接看：

- `./static-site-recipes.md`

## Swagger / OpenAPI 路由文档

推荐入口：

- `GETDoc`
- `POSTDoc`
- `PUTDoc`
- `PATCHDoc`
- `DELETEDoc`
- `HEADDoc`
- `OPTIONSDoc`
- `LastRouteDoc()`

高频链式能力：

- `OperationID(...)`
- `RequestExample(...)`
- `RequestExamples(...)`
- `ResponseExample(...)`
- `ResponseExamples(...)`
- `ProblemResponse(...)`
- `DefaultError(...)`
- `DefaultErrors(...)`
- `Tag(...)`
- `Security(...)`
- `Deprecated()`

说明：

- 不要再沿用 `GET(...).Doc(...)` 这类旧链式心智
- 需要机器友好 OpenAPI 时，优先补 `OperationID`、示例和默认错误模型

## 选择建议

- 标准 API：手写 `GET/POST/...`
- REST 资源控制器：`Resource/CRUD`
- 后台快速控制器：`AutoRegister`
- 路径约束复杂：直接在普通路由方法里写 regex pattern
- 需要高级 regex 控制：`RegexRouter()`
- 前端站点：`Site/FallbackSite`
- 纯静态资源树：`Assets`

## 常见误区

- 以为 regex 路由会盖过普通路由
- 把 `Use(...)` 当作万能中间件入口
- 用 `Static` 去做全站 SPA 兜底
- 继续使用旧的 Swagger 链式用法

下一步通常读：

- 现代能力配方：`./feature-recipes.md`
- 静态站点：`./static-site-recipes.md`
