# pkg/swagger

`pkg/swagger` 提供 Swagger/OpenAPI 文档生成能力。

## 模块用途

- 从 Gin 路由自动生成 OpenAPI 3.0 规范
- 支持手动添加路由文档
- 支持从结构体模型自动生成 Schema
- 支持参数、响应、标签等完整文档

## 关键类型与函数

### SwaggerConfig

```go
type SwaggerConfig struct {
    Title       string   // API 标题
    Description string   // API 描述
    Version     string   // API 版本
    BasePath    string   // 基础路径
    Host        string   // 主机地址
    Schemes     []string // 协议: http, https
    Contact     Contact  // 联系信息
}
```

### Generator

```go
gen := swagger.NewGenerator(cfg swagger.SwaggerConfig)
```

### 方法

| 方法 | 说明 |
|------|------|
| `AddRoute(route *RouteInfo)` | 添加单个路由文档 |
| `AddRoutes(routes []*RouteInfo)` | 批量添加路由文档 |
| `CollectFromGinRoutes(routes gin.RoutesInfo)` | 从 Gin 路由自动收集 |
| `Generate() *OpenAPI` | 生成 OpenAPI 规范 |

### RouteInfo

```go
type RouteInfo struct {
    Path        string              // 路径
    Method      string              // HTTP 方法
    Summary     string              // 简要说明
    Description string              // 详细描述
    OperationID string              // 操作 ID
    Params      []ParamDoc          // 参数列表
    Responses   map[int]ResponseDoc // 响应定义
    Tags        []string            // 标签
    Deprecated  bool                // 是否废弃
    Security    string              // 安全方案名称
}
```

### ParamDoc

```go
type ParamDoc struct {
    Name        string      // 参数名称
    In          string      // 位置: query, header, path, body
    Type        string      // 类型: string, integer, boolean, object, array
    Description string      // 描述
    Required    bool        // 是否必需
    ContentType string      // 请求体内容类型
    Example     interface{} // 示例值
    Examples    map[string]Example
    Model       interface{} // 模型（用于 body 参数）
}
```

### ResponseDoc

```go
type ResponseDoc struct {
    Description string      // 响应描述
    ContentType string      // 响应内容类型
    Example     interface{} // 示例值
    Examples    map[string]Example
    Model       interface{} // 响应模型
}
```

## 使用示例

### 基本用法

```go
package main

import (
	"log"

	gin "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/swagger"
)

func main() {
	app := gin.Default()

	gen := swagger.NewGenerator(swagger.SwaggerConfig{
		Title:       "Example API",
		Description: "An example API",
		Version:     "1.0.0",
		Host:       "api.example.com",
		BasePath:   "/v1",
		Schemes:    []string{"https"},
	})

	// 添加 API 路由
	gen.AddRoute(&swagger.RouteInfo{
		Path:        "/users",
		Method:      "GET",
		Summary:     "获取用户列表",
		Description: "返回所有用户的分页列表",
		OperationID: "listUsers",
		Tags:        []string{"users"},
		Responses: map[int]swagger.ResponseDoc{
			200: {
				Description: "成功",
				Model:       []User{},
			},
		},
	})

	// 从 Gin 路由自动收集
	gen.CollectFromGinRoutes(app.Router().Routes())

	// 生成 OpenAPI 规范
	spec := gen.Generate()
	log.Printf("OpenAPI: %+v", spec)
}
```

### 完整路由文档

```go
gen.AddRoute(&swagger.RouteInfo{
    Path:        "/users/{id}",
    Method:      "GET",
    Summary:     "获取用户详情",
    Description: "根据 ID 获取用户详细信息",
    OperationID: "getUser",
    Tags:        []string{"users"},
    Params: []swagger.ParamDoc{
        {
            Name:        "id",
            In:          "path",
            Type:        "integer",
            Description: "用户 ID",
            Required:    true,
            Example:     123,
        },
    },
    Responses: map[int]swagger.ResponseDoc{
        200: {
            Description: "成功",
            Model:       User{},
        },
        404: {
            Description: "用户不存在",
            Model:       ErrorResponse{},
        },
    },
})
```

### 带请求体的路由

```go
gen.AddRoute(&swagger.RouteInfo{
    Path:        "/users",
    Method:      "POST",
    Summary:     "创建用户",
    Description: "创建新用户",
    Tags:        []string{"users"},
    Params: []swagger.ParamDoc{
        {
            Name:        "body",
            In:          "body",
            Description: "用户信息",
            Required:    true,
            ContentType: "application/json",
            Model:       CreateUserRequest{},
        },
    },
    Responses: map[int]swagger.ResponseDoc{
        201: {
            Description: "创建成功",
            Model:       User{},
        },
        422: {
            Description: "参数错误",
            Model:       ValidationError{},
        },
    },
})
```

### 带标签分组

```go
// 用户相关路由
gen.AddRoute(&swagger.RouteInfo{
    Path:   "/users",
    Method: "GET",
    Tags:   []string{"Users"},
})
gen.AddRoute(&swagger.RouteInfo{
    Path:   "/users/{id}",
    Method: "GET",
    Tags:   []string{"Users"},
})

// 订单相关路由
gen.AddRoute(&swagger.RouteInfo{
    Path:   "/orders",
    Method: "GET",
    Tags:   []string{"Orders"},
})
```

### 带安全方案

```go
gen.AddRoute(&swagger.RouteInfo{
    Path:        "/profile",
    Method:      "GET",
    Summary:     "获取个人资料",
    Security:    "BearerAuth",
    Responses: map[int]swagger.ResponseDoc{
        200: {
            Description: "成功",
            Model:       Profile{},
        },
    },
})
```

### 与 Engine 集成

框架内置 Swagger 支持：

```go
app := gin.New(
    gin.EnableSwagger(swagger.SwaggerConfig{
        Title:       "My API",
        Description: "API Documentation",
        Version:     "v1.0.0",
    }),
)
```

## 数据模型

### User

```go
type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name" binding:"required"`
    Email string `json:"email" binding:"required,email"`
}
```

### CreateUserRequest

```go
type CreateUserRequest struct {
    Name  string `json:"name" binding:"required"`
    Email string `json:"email" binding:"required,email"`
    Age   int    `json:"age"`
}
```

### ErrorResponse

```go
type ErrorResponse struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
}
```

### ValidationError

```go
type ValidationError struct {
    Code    int        `json:"code"`
    Message string     `json:"message"`
    Errors  []FieldError `json:"errors"`
}

type FieldError struct {
    Field   string `json:"field"`
    Message string `json:"message"`
}
```

## OpenAPI 输出格式

生成的规范遵循 OpenAPI 3.0.0 标准：

```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "Example API",
    "version": "1.0.0"
  },
  "paths": {
    "/users": {
      "get": {
        "summary": "获取用户列表",
        "responses": {
          "200": {
            "description": "成功"
          }
        }
      }
    }
  }
}
```

## 与 Engine 的集成

框架通过 `Engine.EnableSwagger()` 提供内置支持：

```go
app := gin.New(
    gin.EnableSwagger(swagger.SwaggerConfig{
        Title:       "API Documentation",
        Description: "Generated by darkit/gin",
        Version:     "v1.0.0",
    }),
)
```

访问文档：

- Swagger UI: `http://localhost:8080/swagger`
- OpenAPI JSON: `http://localhost:8080/swagger/doc.json`

## 注意事项

1. **路由收集**：`CollectFromGinRoutes` 自动从 Gin 路由收集信息，但只会添加基本路由信息
2. **参数提取**：路径参数会从路由路径自动提取
3. **Schema 生成**：结构体模型会自动转换为 JSON Schema
4. **循环引用**：检测到循环引用时会输出警告并使用 `$ref`
