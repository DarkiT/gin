# Swagger / OpenAPI 说明

本文档说明 `github.com/darkit/gin` 当前的 Swagger / OpenAPI 能力，以及应该从哪里继续查看真实实现。

## 能力概览

框架当前提供：

- `EnableSwagger(cfg)`：在 `Engine` 初始化时启用 Swagger/OpenAPI
- 路由链式注解方法（详见下方完整列表）
- `/swagger`：Swagger UI 页面
- `/swagger/doc.json`：OpenAPI JSON 文档

## 链式注解方法完整列表

`GETDoc` / `POSTDoc` / `PUTDoc` / `PATCHDoc` / `DELETEDoc` 等路由注册方法返回 `*SwaggerRouteInfo`，支持以下链式调用：

| 方法 | 功能 |
|---|---|
| `Doc(summary)` | 接口摘要 |
| `Description(desc)` | 详细描述 |
| `Param(name, in, typ, desc, required)` | 参数声明（in: query/path/header/body） |
| `ParamModel(name, in, desc, required, model)` | 模型参数 |
| `Response(code, desc, models...)` | 响应声明 |
| `ResponseExample(code, example)` | 带单个示例的响应 |
| `ResponseExamples(code, examples)` | 带多示例的响应 |
| `Tag(tags...)` | 标签分组 |
| `Deprecated()` | 标记为废弃接口 |
| `Security(name)` | 安全方案声明 |
| `OperationID(id)` | 操作 ID |
| `RequestExample(example)` | 请求体示例 |
| `RequestExamples(examples)` | 请求体多示例 |
| `ProblemResponse(code, desc)` | RFC 9457 错误响应声明 |
| `DefaultError(code, desc...)` | 默认错误声明 |
| `DefaultErrors(codes...)` | 批量默认错误声明 |

## 代码位置

核心实现位于：

- `pkg/swagger/spec.go`
- `pkg/swagger/swagger.go`
- `pkg/swagger/ui.go`
- `pkg/swagger/swagger_test.go`

框架接入点位于：

- `options.go` 中的 `EnableSwagger(...)`
- `router.go` 中的路由注解能力（`SwaggerRouteInfo` 定义于 `router.go:30`）
- `engine.go` 中的 Swagger 注册流程

## 最小示例

```go
e := gin.New(
    gin.EnableSwagger(swagger.SwaggerConfig{
        Title:    "My API",
        Version:  "v1.0.0",
        BasePath: "/api",
    }),
)

e.Router().GETDoc("/users", listUsers).
    Doc("获取用户列表").
    Param("page", "query", "integer", "页码", false).
    Response(200, "成功", []User{}).
    Tag("用户管理")
```

### 完整示例

```go
e.Router().GETDoc("/users/{id}", getUser).
    Doc("获取用户详情").
    Description("根据 ID 获取用户详细信息，含权限校验").
    Param("id", "path", "integer", "用户 ID", true).
    Response(200, "成功", User{}).
    Response(404, "用户不存在").
    ProblemResponse(422, "参数校验失败").
    DefaultError(500).
    Tag("用户管理").
    Security("BearerAuth").
    OperationID("getUserById").
    RequestExample(CreateUserReq{Name: "Alice"})
```

## 推荐阅读顺序

1. `examples/swagger-demo/main.go`
2. `examples/swagger-demo/README.md`
3. `pkg/swagger/swagger.go`
4. `pkg/swagger/swagger_test.go`

## 使用建议

- 想快速接入时，直接照 `examples/swagger-demo/` 示例改
- 想查配置结构时，读 `pkg/swagger` 下源码与测试
- 想看整体 API 地图时，回到 `docs/api-reference.md`

## 说明

旧版阶段性实现总结已移除，因为它依赖阶段性计划文件，容易与当前仓库状态漂移。

如文档与源码冲突，以 `pkg/swagger/` 下源码和测试为准。
