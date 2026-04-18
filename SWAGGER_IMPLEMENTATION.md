# Swagger / OpenAPI 说明

本文档说明 `github.com/darkit/gin` 当前的 Swagger / OpenAPI 能力，以及应该从哪里继续查看真实实现。

## 能力概览

框架当前提供：

- `EnableSwagger(cfg)`：在 `Engine` 初始化时启用 Swagger/OpenAPI
- 路由链式注解：`Doc`、`Description`、`Param`、`ParamModel`、`Response`、`Tag`、`Security`、`Deprecated`
- `/swagger`：Swagger UI 页面
- `/swagger/doc.json`：OpenAPI JSON 文档

## 代码位置

核心实现位于：

- `pkg/swagger/spec.go`
- `pkg/swagger/swagger.go`
- `pkg/swagger/ui.go`
- `pkg/swagger/swagger_test.go`

框架接入点位于：

- `options.go` 中的 `EnableSwagger(...)`
- `router.go` 中的路由注解能力
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

e.Router().GET("/users", listUsers).
    Doc("获取用户列表").
    Param("page", "query", "integer", "页码", false).
    Response(200, "成功", []User{}).
    Tag("用户管理")
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
