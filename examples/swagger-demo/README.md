# Swagger 文档生成示例

本示例演示如何使用 `github.com/darkit/gin` 的 Swagger 文档生成功能。

## 功能特性

- ✅ 支持 OpenAPI 3.0 规范
- ✅ 链式调用的路由注解
- ✅ 自动生成 Swagger UI 界面
- ✅ 支持参数、响应、标签定义
- ✅ 支持模型自动解析
- ✅ 支持安全认证定义
- ✅ 支持废弃路由标记
- ✅ 支持 `OperationID`
- ✅ 支持请求/响应 `Example(s)`
- ✅ 支持 `DefaultErrors()` 与 `ProblemResponse()`
- ✅ 自动将 Gin / chi 风格路径参数规范化为 OpenAPI template

## 快速开始

### 1. 启用 Swagger

```go
e := gin.New(
    gin.EnableSwagger(swagger.SwaggerConfig{
        Title:       "我的 API",
        Description: "API 文档描述",
        Version:     "v1.0.0",
        BasePath:    "/api",
        Host:        "localhost:8080",
        Schemes:     []string{"http", "https"},
    }),
)
```

### 2. 添加路由注解

```go
e.Router().GETDoc("/users", listUsers).
    Doc("获取用户列表").
    OperationID("listUsers").
    Description("分页获取所有用户信息").
    Param("page", "query", "integer", "页码", false).
    Param("per_page", "query", "integer", "每页数量", false).
    Response(200, "成功", []User{}).
    ResponseExample(200, []User{}).
    Tag("用户管理")
```

### 3. 访问文档

启动服务器后，访问：

- Swagger UI: `http://localhost:8080/swagger`
- JSON 文档: `http://localhost:8080/swagger/doc.json`

## 路由注解方法

### Doc(summary string)

设置路由的简要说明

```go
.Doc("获取用户列表")
```

### Description(desc string)

设置路由的详细描述

```go
.Description("分页获取所有用户信息，支持按名称搜索")
```

### Param(name, in, typ, desc string, required bool)

添加参数定义

参数位置 (in):

- `query` - 查询参数
- `path` - 路径参数
- `header` - 请求头参数
- `body` - 请求体参数

参数类型 (typ):

- `string` - 字符串
- `integer` - 整数
- `number` - 数字
- `boolean` - 布尔值
- `array` - 数组
- `object` - 对象

示例：

```go
.Param("id", "path", "integer", "用户ID", true)
.Param("page", "query", "integer", "页码", false)
.Param("X-API-Key", "header", "string", "API密钥", true)
```

### ParamModel(name, in, desc string, required bool, model interface{})

添加带模型的参数定义（用于 body 参数）

```go
.ParamModel("body", "body", "用户信息", true, User{})
```

### Response(code int, desc string, model ...interface{})

添加响应定义

```go
.Response(200, "成功", User{})
.Response(400, "参数错误", ErrorResponse{})
.Response(404, "用户不存在", ErrorResponse{})
```

### OperationID(id string)

设置稳定的 OpenAPI `operationId`，便于 SDK 生成与 AI Agent 调用映射。

```go
.OperationID("createUser")
```

### RequestExample(example any) / RequestExamples(examples map[string]swagger.Example)

设置请求体示例。

```go
.RequestExample(User{
    Name:  "赵六",
    Email: "zhaoliu@example.com",
    Age:   28,
})
```

### ResponseExample(code int, example any) / ResponseExamples(code int, examples map[string]swagger.Example)

设置响应示例。

```go
.ResponseExample(201, User{
    ID:    1,
    Name:  "赵六",
    Email: "zhaoliu@example.com",
    Age:   28,
})
```

### DefaultError(code int, desc ...string) / DefaultErrors(codes ...int)

快速为路由补充默认错误模型，输出 `application/problem+json`。

```go
.DefaultErrors(400, 422, 500)
```

### ProblemResponse(code int, desc string)

为指定状态码声明 Problem Details 错误模型。

```go
.ProblemResponse(409, "用户冲突")
```

### Tag(tags ...string)

添加标签（用于分组）

```go
.Tag("用户管理", "权限管理")
```

### Deprecated()

标记为废弃 API

```go
.Deprecated()
```

### Security(name string)

设置安全方案

```go
.Security("apiKey")
```

## 模型定义

使用结构体标签来增强文档：

```go
type User struct {
    ID    int64  `json:"id" description:"用户ID"`
    Name  string `json:"name" binding:"required" description:"用户名"`
    Email string `json:"email" description:"邮箱地址"`
    Age   int    `json:"age" description:"年龄"`
}
```

- `json` - JSON 字段名
- `description` - 字段描述
- `binding:"required"` - 标记为必需字段

## 运行示例

```bash
cd examples/swagger-demo
go run main.go
```

然后访问 http://localhost:8080/swagger 查看 Swagger UI。

## 完整示例

详见 `main.go` 文件，包含：

1. 用户列表（GET /api/users）
2. 用户详情（GET /api/users/{id}）
3. 创建用户（POST /api/users）
4. 更新用户（PUT /api/users/{id}）
5. 删除用户（DELETE /api/users/{id}）
6. 搜索用户（GET /api/users/search）- 带安全认证
7. 冲突示例（GET /api/users/{id}/conflict）- Problem Details
8. 旧版 API（GET /api/v1/users）- 标记为废弃

## 注意事项

1. **链式调用顺序**: 路由注解方法必须在路由定义之后立即调用
2. **模型引用**: Response 和 ParamModel 会自动解析结构体生成 Schema
3. **错误模型**: `DefaultErrors()` 和 `ProblemResponse()` 会生成 `application/problem+json` 文档
4. **动态生成**: 文档在访问时动态生成，确保始终是最新的
5. **性能影响**: 文档生成仅在访问 Swagger 端点时进行，不影响业务 API 性能
6. **路径展示**: `:id`、`{id:[0-9]+}`、`*` 等路径段会在 Swagger 中显示为 `/users/{id}`、`/orders/{id}`、`/files/{_wildcard}`
