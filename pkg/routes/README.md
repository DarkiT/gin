# pkg/routes

`pkg/routes` 是对 `Engine.Router` 常用路由能力的轻量包装，便于按功能导入。

## 模块用途

- 暴露资源路由、版本路由、健康检查/探针等便捷入口。
- 复用 `Engine` 已有实现，不重复发明路由逻辑。

## 关键类型与函数

### 类型别名

- `ResourceController = engine.ResourceController`
- `ResourceOption = engine.ResourceOption`

### 函数

- `Resource(r, name, ctrl, opts...)`
- `CRUD(r, name, ctrl)`
- `HealthCheck(r, path...)`
- `Liveness(r, path...)`
- `Readiness(r, checks...)`
- `ReadinessAt(r, path, checks...)`
- `Startup(r, checks...)`
- `StartupAt(r, path, checks...)`
- `Version(r, v)`
- `VersionedAPI(r, v, setup)`
- `NamedProbe(...)`
- `WithIDParam`：资源路由 ID 参数配置

## 配置项

- `WithIDParam(...)`：控制资源路由的 ID 参数名/形式（复用 `engine.WithIDParam`）
- `HealthCheck` 可选自定义路径
- `Liveness` / `Readiness` / `Startup` 用于容器探针路由
- `Version` / `VersionedAPI` 使用版本字符串生成前缀

## 使用示例

```go
r := e.Router()

routes.HealthCheck(r)
routes.Liveness(r)

v1 := routes.Version(r, "1")
v1.GET("/users", listUsers)
```

```go
routes.Readiness(r,
    routes.NamedProbe("database", func(c *gin.Context) error {
        return pingDB(c)
    }),
)
```

```go
routes.VersionedAPI(r, "1", func(v *gin.Router) {
    v.GET("/users", listUsers)
})
```

```go
routes.Resource(r, "users", userController, routes.WithIDParam("user_id"))
```

## 与 Engine 的集成

- 该包的所有入口都直接接收 `*gin.Router`。
- 本质上是 `Engine.Router()` 上层的语义化快捷方法。
- 没有独立状态，也不需要单独初始化。
