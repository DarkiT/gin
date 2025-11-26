# OpenAPI 集成示例

本示例演示了如何使用扩展后的Gin框架的OpenAPI功能，自动生成API文档。

## 功能特性

✅ **自动OpenAPI规范生成** - 从代码自动生成OpenAPI 3.0规范  
✅ **gin-swagger集成** - 自动提供Swagger UI界面  
✅ **类型安全的API定义** - 使用Go泛型提供编译时类型检查  
✅ **链式调用** - 优雅的With*模式API设计  
✅ **零侵入性** - 完全向后兼容，可选择性启用  

## 快速开始

### 1. 启动服务

```bash
cd /workspace/examples/openapi_example
go run main.go
```

### 2. 访问API文档

- **Swagger UI**: http://localhost:8080/swagger/index.html
- **OpenAPI规范**: http://localhost:8080/swagger/doc.json
- **健康检查**: http://localhost:8080/api/public/health

## 使用方式

### 基础配置

```go
router := gin.NewRouter(
    gin.WithOpenAPI(&gin.OpenAPI{
        Title:   "My API",
        Version: "1.0.0",
        Servers: gin.Servers{
            {URL: "http://localhost:8080", Description: "开发服务器"},
        },
        SecuritySchemes: gin.SecuritySchemes{
            {Name: "bearerAuth", Type: "http", Scheme: "bearer"},
        },
    }),
)

// 启用Swagger UI
router.EnableSwagger("/swagger")
```

### 传统方式定义API

```go
router.GET("/users/:id", getUserHandler,
    gin.Summary("获取用户信息"),
    gin.PathParam("id", "int", "用户ID"),
    gin.Response(200, User{}),
    gin.Response(404, ErrorResponse{}),
)
```

### 泛型方式定义API

```go
router.GET("/users/:id", getUserHandler,
    gin.Summary("获取用户信息"),
    gin.PathParam("id", "int", "用户ID"),
    gin.Resp[User](200),         // 类型安全
    gin.Resp[ErrorResponse](404), // 类型安全
)
```

### 链式调用方式

```go
// 创建带默认配置的路由组
users := router.Group("/api/users").
    WithTags("User Management").
    WithSecurity("bearerAuth")

// 路由继承组的默认配置
users.GET("/:id", getUserHandler,
    gin.Summary("获取用户信息"),
    gin.Resp[User](200),
)
```

### 高级用法

```go
// 复杂的API定义
router.POST("/users", createUserHandler,
    gin.Summary("创建用户"),
    gin.Description("创建新用户账户"),
    gin.Tags("User Management"),
    gin.ReqBody[CreateUserRequest](),
    gin.Resp[User](201),
    gin.Resp[ValidationError](400),
    gin.Security("bearerAuth"),
    gin.QueryParam("notify", "bool", "是否发送通知邮件", false),
)

// 标记为已弃用的API
router.DELETE("/users/:id/force", forceDeleteHandler,
    gin.Summary("强制删除用户"),
    gin.Deprecated(),
)
```

## API端点列表

| 方法 | 路径 | 描述 | 认证 |
|------|------|------|------|
| GET | `/api/public/health` | 健康检查 | 否 |
| POST | `/api/auth/login` | 用户登录 | 否 |
| GET | `/api/users/` | 获取用户列表 | 是 |
| GET | `/api/users/:id` | 获取用户详情 | 是 |
| POST | `/api/users/` | 创建用户 | 是 |
| PUT | `/api/users/:id` | 更新用户 | 是 |
| DELETE | `/api/users/:id` | 删除用户 | 是 |
| POST | `/api/users/admin/reset-password/:id` | 重置密码 | 是 (管理员) |

## 数据模型

### User
```go
type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Name     string `json:"name"`
}
```

### CreateUserRequest
```go
type CreateUserRequest struct {
    Username string `json:"username" binding:"required"`
    Email    string `json:"email" binding:"required,email"`
    Name     string `json:"name" binding:"required"`
}
```

### ErrorResponse
```go
type ErrorResponse struct {
    Error   string `json:"error"`
    Code    int    `json:"code"`
    Message string `json:"message"`
}
```

## 注意事项

1. **类型安全**: 使用泛型API可以在编译时检查类型错误
2. **性能**: OpenAPI规范会被缓存，避免重复生成
3. **兼容性**: 完全向后兼容现有代码，无需修改
4. **扩展性**: 支持自定义schema生成和文档格式

## 下一步

- 查看完整API文档: http://localhost:8080/swagger/index.html
- 测试API端点使用工具如 Postman 或 curl
- 探索更多高级功能和配置选项