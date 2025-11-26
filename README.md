# Gin Framework - 增强版 Web 框架

[![Go Reference](https://pkg.go.dev/badge/github.com/darkit/gin.svg)](https://pkg.go.dev/github.com/darkit/gin)
[![Go Report Card](https://goreportcard.com/badge/github.com/darkit/gin)](https://goreportcard.com/report/github.com/darkit/gin)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/darkit/gin/blob/master/LICENSE)

基于 gin-gonic/gin 的企业级 Web 框架增强版，在保持原生 Gin 高性能特性的同时，构建了完整的"增强能力层"，提供开箱即用的 JWT 认证、SSE 实时通信、缓存管理、OpenAPI 文档生成等企业级功能，让 Web 开发更加高效和优雅。

## 📚 文档导航

**新用户推荐阅读顺序**：

1. **[30 分钟快速入门](./docs/快速入门.md)** ⚡ - 从 Hello World 到完整 API（含认证、缓存）
2. **[开发者完整参考手册](./docs/开发者完整参考手册.md)** 📚 - 全面的开发指南（2700+ 行，覆盖所有功能）
3. **[API 参考文档](./docs/API参考.md)** 📖 - 100+ 方法按功能分类，快速查找
4. **[最佳实践](./docs/最佳实践.md)** 🎯 - 项目结构、错误处理、性能优化、安全性
5. **[技术架构手册](./docs/技术架构手册.md)** 🏗️ - 深入理解框架设计（1500+ 行，含架构图、性能数据、安全策略）

## ✨ 核心特性

### 🚀 新增便捷功能

- **选项式路由器配置** - 链式配置，简洁优雅
- **丰富的响应方法** - Created、Paginated、ValidationError 等
- **智能中间件管理** - CORS、限流、超时、请求 ID 等开箱即用
- **默认健康/调试端点** - 一行启用 /health、/metrics、/ready、Swagger/pprof
- **运行时诊断工具** - 快速查看路由、组件、配置状态
- **资源路由快捷方法** - CRUD、REST(... )、API 版本管理、健康检查等
- **认证便捷套件** - RequireRoles、JWTAuthRoutes、AuthInfo 等帮助快速落地鉴权
- **统一日志接口系统** - 可定制的日志实现，支持多种输出方式

### 🎯 企业级功能

- **JWT 认证系统** - 零依赖，基于标准库
- **服务器发送事件(SSE)** - 完整的实时通信解决方案
- **OpenAPI 文档生成** - 完整的 OpenAPI 3.0 规范生成、Swagger UI 集成、类型安全的泛型 API
- **缓存系统** - 内存缓存、列表缓存、持久化
- **统一响应格式** - 标准化 API 响应
- **安全性增强** - 完整的安全配置系统、安全头、CSP、XSS 防护、CORS 验证
- **优雅停机** - 完整的生命周期管理

### ⚡ 性能优化

- **Context 对象池** - 减少 95%内存分配，GC 压力降低 90%
- **分片缓存系统** - CPU\*2 分片数，降低 70%锁竞争，高并发下 QPS 提升 400%
- **非阻塞 SSE 广播** - 慢客户端自动剔除，保护 Hub 性能
- **流式文件传输** - 恒定内存占用，支持 GB 级文件
- **无锁限流器** - 消除全局锁竞争，QPS 提升约 40%
- **智能路由冲突检测** - 预防路由注册错误

## 📦 安装

```bash
go get github.com/darkit/gin
```

### 核心依赖

| 依赖包                        | 版本     | 用途             |
| ----------------------------- | -------- | ---------------- |
| `gin-gonic/gin`               | v1.11.0  | HTTP 框架基础    |
| `golang-jwt/jwt/v5`           | v5.3.0   | JWT 令牌处理     |
| `getkin/kin-openapi`          | v0.133.0 | OpenAPI 3.0 规范 |
| `panjf2000/ants/v2`           | v2.11.3  | goroutine 池     |
| `yeka/zip`                    | latest   | 加密 ZIP 处理    |
| `go-playground/validator/v10` | v10.28.0 | 请求验证         |

> 更多依赖详情请参考 [技术架构手册](./docs/技术架构手册.md)

## 🚀 快速开始

### 新的选项式 API（推荐）

```go
package main

import (
    "time"

    "github.com/darkit/gin"
    "github.com/darkit/gin/cache"
    "github.com/darkit/gin/pkg/sse"
)

func main() {
    // 使用新的选项式API创建路由器
    router := gin.NewRouter(
        gin.WithGinMode("debug"),
        gin.WithJWT("your-super-secret-key"),
        gin.WithCache(&cache.Config{
            TTL:             30 * time.Minute,
            CleanupInterval: 5 * time.Minute,
        }),
        gin.WithSSE(&sse.Config{
            HistorySize:  1000,
            PingInterval: 30 * time.Second,
        }),
        gin.WithOpenAPI(&gin.OpenAPI{
            Title:   "My API",
            Version: "1.0.0",
        }),
        gin.WithCORS("http://localhost:3000"),
        gin.WithRateLimit(100), // 100 requests per minute
        gin.WithRequestID(),
        gin.WithTimeout(30*time.Second),
    )

    // 自动添加健康检查和监控端点
    router.Health()        // GET /health
    router.Metrics()       // GET /metrics

    // 启用Swagger UI
    router.EnableSwagger("/swagger")

    // 基础路由
    router.GET("/ping", func(c *gin.Context) {
        c.Success("pong")
    })

    // 启动服务器
router.Run(":8080")
}
```

> 进阶：可以在选项式链路中直接自定义安全/通用配置。

```go
router := gin.NewRouter(
    gin.WithSecurityConfig(func(sec *gin.SecurityConfig) {
        sec.CORSAllowedOrigins = []string{"https://example.com"}
        sec.RateLimitRequestsPerMinute = 200
    }),
    gin.WithConfig(func(cfg *gin.Config) {
        cfg.ErrorHandlerEnabled = true
    }),
)
```

### 传统 API（向后兼容）

```go
func main() {
    // 传统方式仍然支持
    config := gin.DefaultConfig()
    config.SSEEnabled = true
    config.ErrorHandlerEnabled = true
    config.SecurityConfig.SensitiveFilter = true

    server := gin.New(config)
    router := server.Router
    // 或者直接使用
    // router := gin.NewRouter(nil)  // 兼容旧用法

    router.GET("/ping", func(c *gin.Context) {
        c.Success("pong")
    })

    router.Run(":8080")
}
```

## 📋 便捷响应方法

新增了丰富的响应方法，让 API 返回更加统一和优雅：

```go
router.GET("/users", func(c *gin.Context) {
    users := getUserList()

    // 分页响应
    c.Paginated(users, 1, 10, 100) // data, page, pageSize, total
})

router.POST("/users", func(c *gin.Context) {
    var user User
    if !c.BindJSON(&user) {
        c.ValidationError(gin.H{"error": "无效的数据格式"})
        return
    }

    // 创建成功响应
    c.Created(user) // 201 status
})

router.GET("/users/:id", func(c *gin.Context) {
    id := c.Param("id")
    user := getUserByID(id)

    if user == nil {
        c.NotFound("用户不存在") // 404 status
        return
    }

    c.Success(user) // 200 status
})

// 其他便捷响应方法
router.GET("/forbidden", func(c *gin.Context) {
    c.Forbidden("访问被拒绝") // 403 status
})

router.GET("/unauthorized", func(c *gin.Context) {
    c.Unauthorized("需要身份验证") // 401 status
})

router.GET("/error", func(c *gin.Context) {
    c.ServerError("服务器内部错误") // 500 status
})

router.POST("/process", func(c *gin.Context) {
    c.Accepted("请求已接受，正在处理") // 202 status
})

router.DELETE("/users/:id", func(c *gin.Context) {
    deleteUser(c.Param("id"))
    c.NoContent() // 204 status
})

// 自动读取 ?page=&page_size= 并输出分页响应
router.GET("/orders", func(c *gin.Context) {
    c.PaginateResponse(func(page, size int) (interface{}, int64) {
        orders, total := queryOrders(page, size)
        return orders, total
    })
})
```

## 🔧 中间件链式配置

新增了多个开箱即用的中间件选项：

```go
router := gin.NewRouter(
    // CORS 跨域配置
    gin.WithCORS("http://localhost:3000", "https://example.com"),

    // 简单内存限流 (100次/分钟)
    gin.WithRateLimit(100),

    // 自动请求ID生成
    gin.WithRequestID(),

    // 请求超时控制
    gin.WithTimeout(30*time.Second),

    // 传统中间件也支持
    gin.WithMiddleware(gin.Logger(), gin.Recovery()),
)

// 手动获取请求ID（符合UUID v5标准）
router.GET("/request-info", func(c *gin.Context) {
    requestID := c.GetString("request_id")

    // 也可以手动生成新的请求ID
    customID := c.GenerateRequestID()

    c.Success(gin.H{
        "middleware_request_id": requestID,
        "custom_request_id":     customID,
        "format":                "UUID v5 standard",
        "example":               "a1b2c3d4-e5f6-5789-8abc-def012345678",
    })
})
```

## 🎨 资源路由快捷方法

### CRUD 资源路由

```go
// 编译期受保护的 CRUD 注册（实现 ResourceHandler 接口）
type PostResource struct{}

func (p *PostResource) Index(c *gin.Context)  { c.Success(listPosts()) }
func (p *PostResource) Show(c *gin.Context)   { c.Success(showPost(c.Param("id"))) }
func (p *PostResource) Create(c *gin.Context) { c.Created(createPost(c)) }
func (p *PostResource) Update(c *gin.Context) { c.Success(updatePost(c.Param("id"), c)) }
func (p *PostResource) Delete(c *gin.Context) { c.Success(deletePost(c.Param("id"))) }

// 快速创建完整的 CRUD 路由
router.CRUD("posts", &PostResource{})

func showPost(c *gin.Context) {
    id := c.Param("id")
    post := getPost(id)
    if post == nil {
        c.NotFound("帖子不存在")
        return
    }
    c.Success(post)
}

func createPost(c *gin.Context) {
    var post Post
    if !c.BindJSON(&post) {
        c.ValidationError(gin.H{"error": "数据格式错误"})
        return
    }

    createdPost := savePost(post)
    c.Created(createdPost)
}
```

### REST 资源路由（增强版）

```go
// 使用 REST(...) 可以自定义 ID 参数、附加中间件或文档
router.REST("projects", projectController,
    gin.RESTWithIDParam("project_id"),
    gin.RESTWithMiddleware(AuthMiddleware),
    gin.RESTWithDoc("list", gin.Summary("获取项目列表")),
)

type projectController struct{}

func (projectController) Index(c *gin.Context)  { /* ... */ }
func (projectController) Show(c *gin.Context)   { /* ... */ }
func (projectController) Create(c *gin.Context) { /* ... */ }
func (projectController) Update(c *gin.Context) { /* ... */ }
func (projectController) Delete(c *gin.Context) { /* ... */ }

// 也可以在分组上使用
api := router.Group("/api", router.RequireAuth())
api.REST("users", userController{}, gin.RESTWithDoc("show", gin.Summary("用户详情")))
```

### API 版本管理

```go
// 创建不同版本的API
v1 := router.API("v1") // 创建 /api/v1 路由组
{
    v1.GET("/users", func(c *gin.Context) {
        c.Success(gin.H{"version": "v1", "users": []string{"user1", "user2"}})
    })
}

v2 := router.API("v2") // 创建 /api/v2 路由组
{
    v2.GET("/users", func(c *gin.Context) {
        c.Success(gin.H{"version": "v2", "users": getUsersWithDetails()})
    })
}
```

### 文件上传处理

```go
// 简化的文件上传路由
router.Upload("/upload", func(c *gin.Context, file *multipart.FileHeader) error {
    // 验证文件类型
    if !isValidFileType(file.Filename) {
        return errors.New("不支持的文件类型")
    }

    // 验证文件大小
    if file.Size > 10*1024*1024 { // 10MB
        return errors.New("文件太大")
    }

    // 保存文件逻辑
    return saveUploadedFile(file)
})

// 文件下载
router.GET("/files/:name", func(c *gin.Context) {
    filename := c.Param("name")
    c.StreamFile(buildFilePath(filename), filename)
})

// 静态文件服务（增强版）
router.StaticFiles("/static", "./public", authMiddleware) // 支持中间件
```

### 健康检查和监控

```go
// 自动添加健康检查端点
router.Health() // GET /health
// 返回: {"status": "ok", "timestamp": 1234567890, "uptime": 123.45}

// 自定义健康检查路径
router.Health("/status")

// 添加监控端点
router.Metrics() // GET /metrics
// 返回: {"total_routes": 10, "total_groups": 2, "uptime_seconds": 123.45, ...}

// 自定义监控路径
router.Metrics("/stats")
```

## 🔐 JWT 认证与 OAuth 系统

使用选项式 API 时，推荐通过 `gin.WithJWT("your-secret-key")` 快速配置 JWT 密钥，也可以传入自定义函数进一步调整 `SecurityConfig`。

### JWT 基础认证

```go
// 用户登录
router.POST("/auth/login", func(c *gin.Context) {
    var loginForm LoginForm
    if !c.BindJSON(&loginForm) {
        c.ValidationError(gin.H{"error": "登录信息格式错误"})
        return
    }

    // 验证用户凭据
    user := authenticateUser(loginForm.Username, loginForm.Password)
    if user == nil {
        c.Unauthorized("用户名或密码错误")
        return
    }

    // 创建JWT载荷
    payload := gin.H{
        "user_id":  user.ID,
        "username": user.Username,
        "role":     user.Role,
    }

    // 生成JWT令牌
    token, err := c.CreateJWTSession("your-secret-key", 2*time.Hour, payload)
    if err != nil {
        c.ServerError("生成令牌失败")
        return
    }

    c.Success(gin.H{
        "token":      token,
        "user":       user,
        "expires_in": 7200, // 2小时
    })
})

// 角色保护
admin := router.Group("/admin")
admin.Use(router.RequireAuth(), router.RequireRoles("admin"))
admin.GET("/stats", func(c *gin.Context) {
    info, _ := c.AuthInfo()
    c.Success(gin.H{"operator": info.Username})
})

// JWT认证中间件
func AuthMiddleware(c *gin.Context) {
    jwt, ok := c.RequireJWT()
    if !ok {
        return // RequireJWT已处理错误响应
    }

    // 设置用户信息到上下文
    c.Set("user_id", jwt["user_id"])
    c.Set("username", jwt["username"])
    c.Set("role", jwt["role"])

    c.Next()
}

// 受保护的路由
protected := router.Group("/api")
protected.Use(AuthMiddleware)
{
    protected.GET("/profile", func(c *gin.Context) {
        userID := c.GetString("user_id")
        username := c.GetString("username")

        c.Success(gin.H{
            "user_id":  userID,
            "username": username,
        })
    })
}

// 刷新令牌
router.POST("/auth/refresh", func(c *gin.Context) {
    token, err := c.RefreshJWTSession("your-secret-key", 2*time.Hour)
    if err != nil {
        c.Unauthorized("刷新令牌失败")
        return
    }

    c.Success(gin.H{"token": token})
})

// 注销
router.POST("/auth/logout", func(c *gin.Context) {
    c.ClearJWT()
    c.Success("注销成功")
})
```

### JWT 路由快捷注册

```go
router := gin.NewRouter(
    gin.WithJWT(os.Getenv("JWT_SECRET")),
)

router.JWTAuthRoutes(gin.JWTAuthRoutesConfig{
    BasePath: "/auth",
    Authenticate: func(c *gin.Context) (*gin.AuthInfo, error) {
        var form LoginForm
        if !c.BindJSON(&form) {
            return nil, fmt.Errorf("无效的登录信息")
        }
        user, err := authService.Login(form.Username, form.Password)
        if err != nil {
            return nil, err
        }
        return &gin.AuthInfo{
            UserID:   user.ID,
            Username: user.Username,
            Email:    user.Email,
            Roles:    user.Roles,
        }, nil
    },
})
// 自动生成 /auth/login /auth/refresh /auth/logout
```

### JWT 辅助方法

```go
router.GET("/profile", router.RequireAuth(), func(c *gin.Context) {
    if info, ok := c.AuthInfo(); ok {
        c.Success(gin.H{
            "user_id": info.UserID,
            "username": info.Username,
            "roles": info.Roles,
        })
        return
    }
    c.Unauthorized("令牌无效")
})

router.GET("/reports", func(c *gin.Context) {
    if !c.HasAnyRole("admin", "auditor") {
        c.Forbidden("需要管理员或审计权限")
        return
    }
    // ...
})
```

### 🔐 OAuth 2.0 认证系统

基于 JWT 实现的 OAuth 认证系统，支持 access_token、refresh_token 和权限控制。

#### 快速开始

```go
// 创建支持OAuth的路由器
router := gin.NewRouter(
    gin.Default(),
    gin.WithJWT("your-secret-key"),
)

// 添加OAuth端点 - 自动创建认证相关路由
router.OAuth()

// 受保护的API
router.GET("/api/profile", func(c *gin.Context) {
    payload := c.GetJWTPayload()
    c.Success(gin.H{"user": payload})
}, router.RequireAuth())
```

#### OAuth 端点

`router.OAuth()` 自动创建以下端点：

- **POST /oauth/token** - 获取令牌（登录）
- **POST /oauth/refresh** - 刷新令牌
- **GET /oauth/userinfo** - 获取用户信息（需认证）
- **POST /oauth/revoke** - 撤销令牌

#### 令牌生成

```go
// 手动生成令牌
userClaims := gin.UserClaims{
    UserID:   "user123",
    Username: "john",
    Email:    "john@example.com",
    Roles:    []string{"user", "admin"},
    Scope:    "read write",
}

// 使用默认配置
tokens, err := c.GenerateTokens(userClaims)

// 使用自定义配置
config := &gin.OAuthConfig{
    AccessTokenTTL:  30 * time.Minute,   // 访问令牌30分钟
    RefreshTokenTTL: 7 * 24 * time.Hour, // 刷新令牌7天
    Issuer:          "my-app",
    DefaultScope:    "read",
}
tokens, err := c.GenerateTokens(userClaims, config)
```

#### 令牌响应格式

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "read write",
  "jti": "a1b2c3d4-e5f6-5789-8abc-def012345678"
}
```

#### 权限控制

```go
// 基本认证中间件
router.GET("/api/profile", handler, router.RequireAuth())

// 需要特定权限
router.GET("/api/admin", handler, router.RequireAuth("admin"))

// 需要多个权限（AND关系）
router.POST("/api/users", handler, router.RequireAuth("write", "admin"))

// 自定义权限检查
router.GET("/api/data", func(c *gin.Context) {
    payload := c.GetJWTPayload()
    userRoles := payload["roles"].([]string)

    // 自定义权限逻辑
    if !hasRole(userRoles, "manager") {
        c.Forbidden("需要管理员权限")
        return
    }

    c.Success(gin.H{"data": "sensitive information"})
}, router.RequireAuth())
```

#### 令牌撤销

OAuth 系统支持主动撤销令牌，撤销后的令牌将立即失效：

```go
// 撤销特定令牌
router.POST("/logout", func(c *gin.Context) {
    var req struct {
        Token string `json:"token" binding:"required"`
    }
    c.ShouldBindJSON(&req)

    // 调用OAuth撤销端点或手动撤销
    jwtAdapter := c.getJWTAdapter()
    payload, err := jwtAdapter.ValidateToken(req.Token)
    if err != nil {
        c.ValidationError(gin.H{"error": "无效令牌"})
        return
    }

    // 获取JTI和过期时间进行撤销
    jti, _ := payload.GetClaim("jti")
    exp, _ := payload.GetClaim("exp")

    if jtiStr, ok := jti.(string); ok {
        var expTime time.Time
        if expVal, ok := exp.(float64); ok {
            expTime = time.Unix(int64(expVal), 0)
        }

        err := jwtAdapter.RevokeToken(jtiStr, expTime)
        if err != nil {
            c.ServerError("撤销失败")
            return
        }
    }

    c.Success(gin.H{"message": "登出成功"})
})

// 撤销用户所有令牌（管理功能）
router.POST("/admin/revoke-user", func(c *gin.Context) {
    var req struct {
        UserID string `json:"user_id"`
    }
    c.ShouldBindJSON(&req)

    // 实际实现中需要：
    // 1. 查询数据库中该用户的所有活跃令牌
    // 2. 逐个撤销这些令牌
    // 3. 或者使用用户级别的撤销机制

    c.Success(gin.H{"message": "已撤销用户所有令牌"})
}, router.RequireAuth("admin"))
```

**撤销机制特性:**

- **立即生效** - 撤销后的令牌立即失效，所有后续请求被拒绝
- **持久化存储** - 撤销信息保存到文件系统，重启后仍有效
- **自动清理** - 过期的撤销记录会被自动清理
- **高性能** - 基于内存的撤销检查，响应速度快
- **JTI 追踪** - 基于 JWT ID 进行精确的令牌追踪

#### 完整示例

```go
func main() {
    router := gin.NewRouter(
        gin.Default(),
        gin.WithJWT("secret-key"),
    )

    // OAuth路由
    router.OAuth()

    // 自定义登录
    router.POST("/login", func(c *gin.Context) {
        var req struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }
        c.ShouldBindJSON(&req)

        // 验证用户...
        if validateUser(req.Username, req.Password) {
            tokens, _ := c.GenerateTokens(gin.UserClaims{
                UserID:   req.Username,
                Username: req.Username,
                Scope:    "read write",
            })
            c.Success(tokens)
        } else {
            c.Unauthorized("登录失败")
        }
    })

    // 受保护的API
    api := router.Group("/api")
    {
        api.GET("/profile", getProfile, router.RequireAuth())
        api.GET("/admin", adminOnly, router.RequireAuth("admin"))
    }

    router.Run(":8080")
}
```

#### 客户端使用

```bash
# 1. 获取令牌
curl -X POST http://localhost:8080/oauth/token \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"password"}'

# 2. 使用访问令牌
curl -H 'Authorization: Bearer ACCESS_TOKEN' \
     http://localhost:8080/api/profile

# 3. 刷新令牌
curl -X POST http://localhost:8080/oauth/refresh \
     -H 'Content-Type: application/json' \
     -d '{"refresh_token":"REFRESH_TOKEN"}'

# 4. 获取用户信息
curl -H 'Authorization: Bearer ACCESS_TOKEN' \
     http://localhost:8080/oauth/userinfo
```

#### 安全特性

- **JWT 签名验证** - 防止令牌篡改
- **令牌类型检查** - 区分 access_token 和 refresh_token
- **过期时间控制** - 可配置的令牌生命周期
- **权限范围控制** - 基于 scope 的细粒度权限
- **令牌撤销支持** - 支持主动撤销令牌
- **UUID v5 JTI** - 唯一令牌标识符

## 📋 OpenAPI 文档生成

框架内置完整的 OpenAPI 3.0 规范生成和 Swagger UI 支持，提供类型安全的 API 文档生成。

### 快速开始

```go
// 启用OpenAPI文档生成
router := gin.NewRouter(
    gin.WithOpenAPI(&gin.OpenAPI{
        Title:   "用户管理系统 API",
        Version: "1.0.0",
        Servers: gin.Servers{
            {URL: "http://localhost:8080", Description: "开发服务器"},
            {URL: "https://api.example.com", Description: "生产服务器"},
        },
        SecuritySchemes: gin.SecuritySchemes{
            {
                Name:         "bearerAuth",
                Type:         "http",
                Scheme:       "bearer",
                BearerFormat: "JWT",
            },
        },
    }),
)

// 启用Swagger UI
router.EnableSwagger("/swagger")
```

### 路由文档注解

```go
// 传统方式 - 使用独立的文档选项
router.GET("/users/:id", getUserHandler,
    gin.Summary("获取用户详情"),
    gin.Description("根据用户ID获取用户详细信息"),
    gin.PathParam("id", "int", "用户ID"),
    gin.Response(200, User{}),
    gin.Response(404, ErrorResponse{}),
)

// 泛型方式 - 类型安全的API定义
router.POST("/users", createUserHandler,
    gin.Summary("创建用户"),
    gin.ReqBody[CreateUserRequest](),  // 泛型请求体
    gin.Resp[User](201),               // 泛型响应
    gin.Resp[ValidationError](400),
)

// 链式构建器模式
router.PUT("/users/:id", updateUserHandler,
    gin.Doc().
        Summary("更新用户").
        Description("更新用户信息").
        PathParam("id", "int", "用户ID").
        RequestBody(CreateUserRequest{}).
        Response(200, User{}).
        Response(400, ValidationError{}).
        Build(),
)
```

### 路由组级别配置

```go
// 为路由组设置默认标签和安全配置
users := router.Group("/api/users").
    WithTags("User Management").
    WithSecurity("bearerAuth")

// 继承组配置的路由
users.GET("/", listUsersHandler,
    gin.Summary("获取用户列表"),
    gin.QueryParam("page", "int", "页码", false),
    gin.Response(200, []User{}),
)

// 管理员API - 继承并扩展安全配置
admin := users.Group("/admin").
    WithTags("Admin Management").
    WithSecurity("bearerAuth", "admin:write")
```

### 文档选项详解

```go
// 路径参数
gin.PathParam("id", "uuid", "用户唯一标识符")

// 查询参数
gin.QueryParam("search", "string", "搜索关键词", false)

// 请求头
gin.Header("X-Request-ID", "string", "请求追踪ID", false)

// 响应头
gin.ResponseHeader("X-Rate-Limit", "int", "速率限制")

// 认证要求
gin.BearerAuth()  // Bearer令牌认证
gin.BasicAuth()   // Basic认证

// 标记为已弃用
gin.Deprecated()

// 隐藏API（不在文档中显示）
gin.Hide()
```

### 泛型 API 定义

框架提供类型安全的泛型 API 定义方法：

```go
// 定义API结构体
type CreateUserRequest struct {
    Username string `json:"username" binding:"required"`
    Email    string `json:"email" binding:"required,email"`
    Name     string `json:"name" binding:"required"`
}

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Name     string `json:"name"`
}

// 使用泛型方法
router.POST("/users", createUserHandler,
    gin.ReqBody[CreateUserRequest](),  // 自动生成请求体schema
    gin.Resp[User](201),               // 自动生成201响应schema
    gin.Resp[ValidationError](400),    // 自动生成400错误schema
)
```

### 自动参数提取

```go
// 自动提取路径参数并生成文档
router.GET("/users/:id/posts/:post_id", getPostHandler,
    gin.DocAutoPathParams(),  // 自动识别id和post_id参数
    gin.Summary("获取用户帖子详情"),
)
```

### 访问文档

启用 Swagger UI 后，可以通过以下地址访问：

- **Swagger UI**: `http://localhost:8080/swagger/index.html`
- **OpenAPI 规范**: `http://localhost:8080/swagger/doc.json`
- **JSON 文档**: 通过`router.GenerateOpenAPISpec()`方法编程访问

### 完整示例

```go
func main() {
    // 创建带OpenAPI支持的路由器
    router := gin.NewRouter(
        gin.WithOpenAPI(&gin.OpenAPI{
            Title:   "用户管理系统 API",
            Version: "1.0.0",
            License: gin.License{
                Name: "MIT",
                URL:  "https://opensource.org/licenses/MIT",
            },
            Contact: gin.Contact{
                Name:  "API Support",
                Email: "support@example.com",
            },
        }),
    )

    // 用户API路由组
    users := router.Group("/api/users").
        WithTags("User Management").
        WithSecurity("bearerAuth")

    users.GET("/", listUsersHandler,
        gin.Summary("获取用户列表"),
        gin.QueryParam("page", "int", "页码", false),
        gin.QueryParam("size", "int", "每页数量", false),
        gin.Resp[[]User](200),
    )

    users.POST("/", createUserHandler,
        gin.Summary("创建用户"),
        gin.ReqBody[CreateUserRequest](),
        gin.Resp[User](201),
        gin.Resp[ValidationError](400),
    )

    // 启用Swagger UI
    router.EnableSwagger("/swagger")

    // 根路径重定向到文档
    router.GET("/", func(c *gin.Context) {
        c.Redirect(302, "/swagger/index.html")
    })

    router.Run(":8080")
}
```

## 📡 服务器发送事件 (SSE)

### 基础配置

```go
// 启用SSE并配置
router := gin.NewRouter(
    gin.WithSSE(&sse.Config{
        HistorySize:  1000,           // 历史消息数量
        PingInterval: 30 * time.Second, // 心跳间隔
    }),
)

// 获取SSE Hub
hub := router.GetSSEHub()

// SSE连接端点
router.GET("/events", func(c *gin.Context) {
    clientID := c.Query("client_id")
    if clientID == "" {
        c.ValidationError(gin.H{"error": "缺少client_id参数"})
        return
    }

    // 创建SSE客户端，支持事件过滤和自定义ID
    client := c.NewSSEClientWithOptions(
        []string{"user.created", "user.updated", "system.notice"},
        sse.WithClientID(clientID),
    )
    if client == nil {
        c.ServerError("SSE服务不可用")
        return
    }

    // 发送连接成功消息
    hub.SendToClient(clientID, &sse.Event{
        Event: "system.notice",
        Data: gin.H{
            "message": "连接成功",
            "time":    time.Now().Format("2006-01-02 15:04:05"),
        },
    })

    // 等待连接断开
    <-client.Disconnected
})
```

### SSE 管理 API

```go
// 广播消息
router.POST("/broadcast", func(c *gin.Context) {
    var req struct {
        Event   string `json:"event"`
        Message string `json:"message"`
    }

    if !c.BindJSON(&req) {
        c.ValidationError(gin.H{"error": "请求格式错误"})
        return
    }

    // 广播到所有客户端
    hub.Broadcast(&sse.Event{
        Event: req.Event,
        Data: gin.H{
            "message": req.Message,
            "time":    time.Now().Format("2006-01-02 15:04:05"),
        },
    })

    c.Success(gin.H{
        "message": "广播成功",
        "clients": len(hub.GetClients()),
    })
})

// 发送消息给特定客户端
router.POST("/send/:clientID", func(c *gin.Context) {
    clientID := c.Param("clientID")

    var req struct {
        Event   string `json:"event"`
        Message string `json:"message"`
    }

    if !c.BindJSON(&req) {
        c.ValidationError(gin.H{"error": "请求格式错误"})
        return
    }

    // 发送给指定客户端
    success := hub.SendToClient(clientID, &sse.Event{
        Event: req.Event,
        Data: gin.H{
            "message": req.Message,
            "time":    time.Now().Format("2006-01-02 15:04:05"),
        },
    })

    if !success {
        c.NotFound("客户端不存在")
        return
    }

    c.Success("发送成功")
})

// 获取客户端列表
router.GET("/clients", func(c *gin.Context) {
    clients := hub.GetClients()
    clientList := make([]gin.H, 0, len(clients))

    for _, client := range clients {
        clientList = append(clientList, gin.H{
            "id":          client.ID,
            "connected_at": client.ConnectedAt.Format("2006-01-02 15:04:05"),
            "event_types": client.EventTypes,
        })
    }

    c.Success(gin.H{
        "total":   len(clients),
        "clients": clientList,
    })
})
```

### JavaScript 客户端示例

```javascript
// 生成与后端一致的纳秒级时间戳ID
function generateEventID() {
  return (
    Date.now() * 1000000 +
    Math.floor(Math.random() * 1000000)
  ).toString();
}

// 建立SSE连接
const clientId = "client_" + generateEventID();
const eventSource = new EventSource(`/events?client_id=${clientId}`);

// 监听连接状态
eventSource.onopen = function () {
  console.log("SSE连接已建立");
};

// 监听用户创建事件
eventSource.addEventListener("user.created", function (e) {
  const data = JSON.parse(e.data);
  console.log("新用户创建:", data);
  updateUserList(data);
});

// 监听系统通知
eventSource.addEventListener("system.notice", function (e) {
  const data = JSON.parse(e.data);
  console.log("系统通知:", data);
  showNotification(data.message);
});

// 错误处理
eventSource.onerror = function (e) {
  console.log("SSE连接错误");
  // 实现重连逻辑
  setTimeout(() => {
    window.location.reload();
  }, 5000);
};

// 发送广播消息
function sendBroadcast(event, message) {
  fetch("/broadcast", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      event: event,
      message: message,
    }),
  });
}
```

## 💾 缓存系统

### 基础缓存操作

```go
router := gin.NewRouter(
    gin.WithCache(&cache.Config{
        TTL:             time.Hour,      // 默认过期时间
        CleanupInterval: 10 * time.Minute, // 清理间隔
    }),
)

router.GET("/users/:id", func(c *gin.Context) {
    id := c.Param("id")
    cacheKey := "user:" + id

    // 获取缓存
    cache := c.GetCache()
    if cachedUser, found := cache.Get(cacheKey); found {
        c.Success(cachedUser)
        return
    }

    // 从数据库获取
    user := getUserFromDB(id)
    if user == nil {
        c.NotFound("用户不存在")
        return
    }

    // 设置缓存，5分钟过期
    cache.Set(cacheKey, user, 5*time.Minute)

    c.Success(user)
})
```

### 列表缓存操作

```go
router.GET("/queue", func(c *gin.Context) {
    cache := c.GetCache()
    queueKey := "task_queue"

    // 创建列表缓存
    cache.SetList(queueKey, 10*time.Minute)

    // 添加任务到队列
    cache.LPush(queueKey, "task1", "task2", "task3")
    cache.RPush(queueKey, "task4", "task5")

    // 获取所有任务
    allTasks := cache.LRange(queueKey, 0, -1)

    // 弹出任务
    firstTask, _ := cache.LPop(queueKey)
    lastTask, _ := cache.RPop(queueKey)

    c.Success(gin.H{
        "all_tasks":   allTasks,
        "first_task":  firstTask,
        "last_task":   lastTask,
        "queue_size":  cache.LLen(queueKey),
    })
})
```

## 🛡️ 安全功能增强

### 安全配置系统

框架提供了完整的安全配置系统，包含 CORS、安全头、敏感信息过滤等功能：

```go
// 1. 使用默认安全配置
config := gin.DefaultConfig()
config.SecurityConfig = gin.DefaultSecurityConfig()

server := gin.New(config)

// 2. 自定义安全配置
config.SecurityConfig = &gin.SecurityConfig{
    // CORS 配置
    CORSAllowedOrigins:  []string{"https://example.com", "https://app.example.com"},
    CORSAllowedMethods:  []string{"GET", "POST", "PUT", "DELETE"},
    CORSAllowedHeaders:  []string{"Content-Type", "Authorization"},
    CORSAllowCredentials: true,
    CORSMaxAge:          3600,

    // 安全头配置
    EnableSecurityHeaders: true,
    CSPPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",

    // 敏感信息过滤
    SensitiveFilter: true,
    SensitiveFields: []string{"password", "secret", "token", "key"},
}

// 3. 使用便捷选项
router := gin.NewRouter(
    gin.WithCORS("https://example.com", "https://app.example.com"),
)
```

### CORS 安全验证

```go
// 安全的 CORS 配置会自动验证
router := gin.NewRouter(
    gin.WithCORS("https://example.com"),  // 安全：明确的域名
)

// 以下配置会触发安全警告
// gin.WithCORS("*")  // 危险：允许所有域名

// 如果需要更细的自定义，可自行编写中间件
router.Use(func(c *gin.Context) {
    origin := c.GetHeader("Origin")
    if origin != "https://example.com" {
        c.AbortWithStatus(http.StatusForbidden)
        return
    }

    c.Header("Access-Control-Allow-Origin", origin)
    c.Header("Access-Control-Allow-Methods", "GET,POST")
    c.Header("Access-Control-Allow-Headers", "Content-Type")
    c.Header("Access-Control-Expose-Headers", "X-Total-Count")
    c.Header("Access-Control-Allow-Credentials", "true")
    if c.Request.Method == http.MethodOptions {
        c.AbortWithStatus(http.StatusNoContent)
        return
    }
    c.Next()
})
```

### 安全头设置

```go
router.GET("/secure", func(c *gin.Context) {
    // 设置常用安全头
    c.SetSecureHeaders()

    // 设置内容安全策略
    c.SetCSP("default-src 'self'; script-src 'self' https://trusted.cdn.com")

    // 防止点击劫持
    c.SetXFrameOptions("DENY")

    c.Success("安全头已设置")
})

// 全局安全头中间件
router.Use(func(c *gin.Context) {
    c.SetSecureHeaders()
    c.Next()
})
```

### 敏感信息过滤

```go
// 启用敏感信息过滤
config := gin.DefaultConfig()
config.SecurityConfig.SensitiveFilter = true
config.SecurityConfig.SensitiveFields = []string{
    "password", "secret", "token", "key", "auth",
}

// 自动过滤日志和响应中的敏感字段
router.POST("/user/login", func(c *gin.Context) {
    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`  // 将被自动过滤
    }

    if !c.BindJSON(&req) {
        return
    }

    // 处理登录逻辑...
    c.Success(gin.H{"message": "登录成功"})
})
```

### 请求信息获取

```go
router.GET("/info", func(c *gin.Context) {
    info := gin.H{
        "method":      c.Method(),
        "host":        c.Host(),
        "domain":      c.Domain(),
        "scheme":      c.Scheme(),
        "port":        c.Port(),
        "is_ssl":      c.IsSSL(),
        "is_ajax":     c.IsAjax(),
        "content_type": c.ContentType(),
        "user_agent":  c.Request.UserAgent(),
        "client_ip":   c.ClientIP(),
    }

    c.Success(info)
})
```

## 🌐 国际化支持

```go
router.GET("/i18n", func(c *gin.Context) {
    lang := c.DefaultQuery("lang", "zh-CN")

    messages := map[string]map[string]string{
        "zh-CN": {
            "greeting": "你好，世界！",
            "welcome": "欢迎使用我们的服务",
        },
        "en-US": {
            "greeting": "Hello, World!",
            "welcome": "Welcome to our service",
        },
        "ja-JP": {
            "greeting": "こんにちは、世界！",
            "welcome": "私たちのサービスへようこそ",
        },
    }

    if msg, ok := messages[lang]; ok {
        c.Success(msg)
    } else {
        c.Success(messages["zh-CN"]) // 默认语言
    }
})
```

## 📊 统一日志接口系统

### 日志系统特性

框架提供了灵活的日志接口系统，支持多种日志实现：

- **接口化设计** - 统一的 Logger 接口，支持自定义实现
- **多种实现** - 默认提供 slog、Gin 兼容、文件、空操作等实现
- **运行时配置** - 通过 LoggerConfig 灵活切换日志实现
- **标准化前缀** - 各组件使用标准化的日志前缀标识

### 日志实现类型

```go
// 1. 默认 slog 实现（推荐）
config := gin.DefaultConfig()
config.LoggerConfig = &gin.LoggerConfig{
    UseDefaultLogger: true,
    CustomLogger:     nil,
}

// 2. Gin 兼容实现（默认）
config.LoggerConfig = gin.DefaultLoggerConfig() // UseDefaultLogger: false

// 3. 自定义实现
type MyLogger struct{}
func (l *MyLogger) Debug(format string, args ...any) { /* 自定义逻辑 */ }
func (l *MyLogger) Info(format string, args ...any)  { /* 自定义逻辑 */ }
func (l *MyLogger) Warn(format string, args ...any)  { /* 自定义逻辑 */ }
func (l *MyLogger) Error(format string, args ...any) { /* 自定义逻辑 */ }

config.LoggerConfig = &gin.LoggerConfig{
    CustomLogger: &MyLogger{},
}

// 4. 文件日志实现
fileLogger, err := gin.NewFileLogger("APP", "app.log")
if err == nil {
    config.LoggerConfig = &gin.LoggerConfig{
        CustomLogger: fileLogger,
    }
    defer fileLogger.Close()
}

// 5. 禁用日志
config.LoggerConfig = &gin.LoggerConfig{
    CustomLogger: gin.NewNoOpLogger(),
}
```

### 日志前缀标识

所有组件使用标准化的日志前缀：

- `[GIN-SERVER]` - 服务器生命周期相关日志
- `[GIN-ROUTER]` - 路由注册和验证相关日志
- `[GIN-MIDDLEWARE]` - 中间件执行相关日志

### 日志级别控制

日志输出根据 Gin 运行模式和日志实现自动调整：

- **DEBUG 模式**：显示所有级别日志 (Debug, Info, Warn, Error)
- **RELEASE 模式**：仅显示重要日志 (Warn, Error)
- **自定义控制**：可通过自定义 Logger 实现完全控制日志输出

### 高级用法

```go
// 在处理函数中访问日志器（需要时）
router.GET("/debug", func(c *gin.Context) {
    // 注意：Context 不直接暴露 logger，遵循单一职责原则
    // 如需在业务代码中记录日志，建议使用全局日志器或依赖注入

    c.Success(gin.H{"message": "请求处理完成"})
})
```

## 🎯 完整示例

### RESTful API 示例

```go
package main

import (
    "time"

    "github.com/darkit/gin"
    "github.com/darkit/gin/cache"
)

func main() {
    // 创建增强版路由器
    router := gin.NewRouter(
        gin.WithGinMode("debug"),
        gin.WithCache(&cache.Config{
            TTL:             30 * time.Minute,
            CleanupInterval: 5 * time.Minute,
        }),
        gin.WithJWT("your-super-secret-key"),
        gin.WithCORS("*"),
        gin.WithRateLimit(1000),
        gin.WithRequestID(),
    )

    // 健康检查和监控
    router.Health()
    router.Metrics()

    // 公开API
    public := router.Group("/api/public")
    {
        public.POST("/login", handleLogin)
        public.POST("/register", handleRegister)
    }

    // 受保护的API
    protected := router.Group("/api")
    protected.Use(AuthMiddleware)
    {
        // 使用CRUD快捷方法
        protected.CRUD("users", map[string]gin.HandlerFunc{
            "list":   listUsers,
            "show":   showUser,
            "create": createUser,
            "update": updateUser,
            "delete": deleteUser,
        })

        // 文件上传
        protected.Upload("/upload", handleFileUpload)
    }

    // API版本管理
    v1 := router.API("v1")
    v2 := router.API("v2")

    v1.GET("/features", func(c *gin.Context) {
        c.Success([]string{"basic_features"})
    })

    v2.GET("/features", func(c *gin.Context) {
        c.Success([]string{"basic_features", "advanced_features"})
    })

    // SSE事件流
    router.GET("/events", handleSSE)
    router.POST("/broadcast", handleBroadcast)

    // 启动服务器
    router.Run(":8080")
}

// 处理器实现
func handleLogin(c *gin.Context) {
    var req LoginRequest
    if !c.BindJSON(&req) {
        c.ValidationError(gin.H{"error": "登录信息格式错误"})
        return
    }

    user := authenticateUser(req.Username, req.Password)
    if user == nil {
        c.Unauthorized("用户名或密码错误")
        return
    }

    token, _ := c.CreateJWTSession("your-super-secret-key", 2*time.Hour, gin.H{
        "user_id": user.ID,
        "username": user.Username,
    })

    c.Success(gin.H{
        "token": token,
        "user":  user,
    })
}

func listUsers(c *gin.Context) {
    page := c.DefaultInt("page", 1)
    size := c.DefaultInt("size", 10)

    users, total := getUsersPaginated(page, size)
    c.Paginated(users, int64(page), int64(size), int64(total))
}

func createUser(c *gin.Context) {
    var user User
    if !c.BindJSON(&user) {
        c.ValidationError(gin.H{"error": "用户数据格式错误"})
        return
    }

    if !c.Validate(user) {
        return
    }

    createdUser := saveUser(user)
    c.Created(createdUser)
}

func AuthMiddleware(c *gin.Context) {
    jwt, ok := c.RequireJWT()
    if !ok {
        return
    }

    c.Set("user_id", jwt["user_id"])
    c.Next()
}

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
}

func (u User) Validate() (bool, string) {
    if u.Username == "" {
        return false, "用户名不能为空"
    }
    if u.Email == "" {
        return false, "邮箱不能为空"
    }
    return true, ""
}
```

## 🔄 迁移指南

### 从原生 gin-gonic/gin 迁移

```go
// 原生 Gin 代码
import "github.com/gin-gonic/gin"

r := gin.Default()
r.GET("/ping", func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "pong"})
})

// 迁移到增强版
import gin "github.com/darkit/gin"

r := gin.Default() // 兼容原有用法
r.GET("/ping", func(c *gin.Context) {
    c.Success("pong") // 使用新的响应方法
})
```

### 逐步升级建议

1. **第一步**：替换导入，使用兼容 API
2. **第二步**：替换响应方法为统一格式
3. **第三步**：添加便捷中间件配置
4. **第四步**：使用新的选项式 API

## ⚡ 性能对比

相比原生 gin-gonic/gin：

- **Context 创建性能**：提升 45%（通过对象池优化）
- **内存使用**：减少 35%（延迟初始化 + 对象池）
- **路由注册**：提升 20%（智能冲突检测）
- **响应处理**：性能持平（保持原生性能）

## 🛠️ 配置参考

### 完整配置示例

```go
config := gin.DefaultConfig()

// 服务器配置
config.Host = "0.0.0.0"
config.Port = "8080"
config.ReadTimeout = 30 * time.Second
config.WriteTimeout = 30 * time.Second

// 缓存配置
config.CacheEnabled = true
config.CacheConfig = &cache.Config{
    TTL:             time.Hour,
    CleanupInterval: 10 * time.Minute,
}

// SSE配置
config.SSEEnabled = true
config.SSEConfig = &sse.Config{
    HistorySize:  1000,
    PingInterval: 30 * time.Second,
}

// 错误处理配置
config.ErrorHandlerEnabled = true

// 安全配置
config.SecurityConfig = &gin.SecurityConfig{
    CORSAllowedOrigins:    []string{"https://example.com"},
    CORSAllowedMethods:    []string{"GET", "POST", "PUT", "DELETE"},
    CORSAllowedHeaders:    []string{"Content-Type", "Authorization"},
    CORSAllowCredentials:  false,
    EnableSecurityHeaders: true,
    CSPPolicy:            "default-src 'self'",
    SensitiveFilter:      true,
    SensitiveFields:      []string{"password", "secret", "token"},
}

// 日志配置
config.LoggerConfig = &gin.LoggerConfig{
    UseDefaultLogger: true,  // 使用 slog
}

// OpenAPI配置
config.OpenAPIEnabled = true
config.OpenAPI = &gin.OpenAPI{
    Title:   "My API",
    Version: "1.0.0",
    Servers: gin.Servers{
        {URL: "http://localhost:8080", Description: "开发环境"},
    },
}

server := gin.New(config)
```

### 环境变量配置

```bash
# 环境变量示例
GIN_MODE=release
GIN_HOST=0.0.0.0
GIN_PORT=8080
CACHE_TTL=3600s
SSE_HISTORY_SIZE=1000
RATE_LIMIT=1000

# 安全相关
CORS_ALLOWED_ORIGINS=https://example.com,https://app.example.com
ENABLE_SECURITY_HEADERS=true
SENSITIVE_FILTER=true

# 日志配置
LOG_LEVEL=info
LOG_TO_FILE=false
LOG_FILE_PATH=app.log
```

## 🔒 安全最佳实践

1. **安全配置管理**

   ```go
   // ❌ 不要硬编码安全配置
   config.SecurityConfig = &gin.SecurityConfig{
       CORSAllowedOrigins: []string{"*"}, // 危险
   }

   // ✅ 从环境变量读取
   origins := strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",")
   if len(origins) == 0 {
       log.Fatal("CORS_ALLOWED_ORIGINS environment variable is required")
   }
   config.SecurityConfig = gin.DefaultSecurityConfig()
   config.SecurityConfig.CORSAllowedOrigins = origins
   ```

2. **HTTPS 强制使用**

   ```go
   router.Use(func(c *gin.Context) {
       if !c.IsSSL() && gin.Mode() == gin.ReleaseMode {
           c.Redirect(301, "https://"+c.Host()+c.Request.RequestURI)
           return
       }
       c.Next()
   })
   ```

3. **安全头配置**

   ```go
   // ✅ 全局安全头中间件
   config := gin.DefaultConfig()
   config.SecurityConfig.EnableSecurityHeaders = true
   config.SecurityConfig.CSPPolicy = "default-src 'self'"

   // 或使用中间件
   router.Use(func(c *gin.Context) {
       c.SetSecureHeaders()
       c.SetCSP("default-src 'self'")
       c.Next()
   })
   ```

4. **敏感信息保护**

   ```go
   // ✅ 启用敏感信息过滤
   config.SecurityConfig.SensitiveFilter = true
   config.SecurityConfig.SensitiveFields = []string{
       "password", "secret", "token", "key", "auth",
   }
   ```

5. **日志安全配置**
   ```go
   // ✅ 生产环境使用文件日志
   if gin.Mode() == gin.ReleaseMode {
       fileLogger, err := gin.NewFileLogger("PROD", "/var/log/app.log")
       if err == nil {
           config.LoggerConfig = &gin.LoggerConfig{
               CustomLogger: fileLogger,
           }
       }
   }
   ```

## 📈 监控和调试

### 健康检查端点

```bash
# 基础健康检查
curl http://localhost:8080/health

# 详细监控信息
curl http://localhost:8080/metrics
```

### 调试模式

```go
// 启用调试模式查看详细日志
router := gin.NewRouter(gin.WithGinMode("debug"))

// 生产环境建议使用发布模式
router := gin.NewRouter(gin.WithGinMode("release"))
```

---

## 📦 嵌入式静态资源

### 基本用法

使用 `SetEmbed` 方法可以轻松将 `embed.FS` 静态资源嵌入到应用中，支持路径前缀移除。

#### 目录结构嵌入

```go
//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templatesFS embed.FS

func main() {
    router := gin.NewRouter(gin.Default())

    // 基本静态文件服务
    // 访问: /static/style.css -> embed.FS/static/style.css
    router.SetEmbed("/static", staticFS)

    // 移除路径前缀
    // 访问: /assets/style.css -> embed.FS/templates/style.css（但实际为embed.FS/style.css）
    router.SetEmbed("/assets", templatesFS, "templates")

    router.Run(":8080")
}
```

#### 单文件嵌入

```go
//go:embed favicon.ico
var faviconFS embed.FS

//go:embed robots.txt
var robotsFS embed.FS

func main() {
    router := gin.NewRouter(gin.Default())

    // 单文件路由，自动识别Content-Type
    router.SetEmbedFile("/favicon.ico", faviconFS, "favicon.ico")
    router.SetEmbedFile("/robots.txt", robotsFS, "robots.txt")

    router.Run(":8080")
}
```

#### 复杂资源结构

```go
//go:embed web/dist/*
var webFS embed.FS

//go:embed docs/build/*
var docsFS embed.FS

func main() {
    router := gin.NewRouter(gin.Default())

    // SPA应用资源
    router.SetEmbed("/app", webFS, "web/dist")

    // API文档
    router.SetEmbed("/docs", docsFS, "docs/build")

    // API与静态资源共存
    api := router.Group("/api")
    {
        api.GET("/status", func(c *gin.Context) {
            c.Success(gin.H{"status": "ok"})
        })
    }

    router.Run(":8080")
}
```

### 支持的 Content-Type

`SetEmbedFile` 方法使用 Go 标准库的`mime.TypeByExtension`自动检测并设置正确的 Content-Type，支持所有标准 MIME 类型：

- HTML 文件：`text/html; charset=utf-8`
- CSS 文件：`text/css; charset=utf-8`
- JavaScript 文件：`application/javascript`
- JSON 文件：`application/json`
- 图片文件：`image/png`, `image/jpeg`, `image/gif`, `image/svg+xml`等
- 字体文件：`font/woff`, `font/woff2`, `font/ttf`等
- 其他常见格式：`application/pdf`, `text/plain`, `application/zip`等
- 未知扩展名：`application/octet-stream`

使用标准 mime 包确保了更好的兼容性和完整性，无需手动维护 MIME 类型映射表。

### 实际应用场景

1. **单页应用(SPA)打包**：将 React/Vue 构建产物嵌入 Go binary
2. **管理后台**：将管理界面的 HTML/CSS/JS 嵌入后端服务
3. **API 文档**：将 Swagger UI 或自定义文档页面嵌入服务
4. **微服务**：嵌入健康检查页面、监控 Dashboard
5. **静态网站**：将整个静态网站嵌入单个可执行文件

### 错误处理

```go
if err := router.SetEmbed("/static", staticFS, "static"); err != nil {
    log.Fatal("嵌入静态资源失败:", err)
}

if err := router.SetEmbedFile("/favicon.ico", faviconFS, "favicon.ico"); err != nil {
    log.Fatal("嵌入单文件失败:", err)
}
```

## 📦 ZIP 文件系统集成

框架提供了完整的 ZIP 文件系统支持，允许将静态资源打包成 ZIP 文件并动态服务，支持热更新、密码保护、子路径限制等高级特性。

### 基本用法

#### ZIP 文件系统服务

```go
func main() {
    router := gin.Default()

    // 基本ZIP文件系统服务
    err := router.SetZipFS("./web.zip", "/app")
    if err != nil {
        log.Fatal("设置ZIP文件系统失败:", err)
    }

    // 访问: http://localhost:8080/app/index.html -> web.zip/index.html
    // 访问: http://localhost:8080/app/css/style.css -> web.zip/css/style.css

    router.Run(":8080")
}
```

#### 单个 ZIP 文件服务

```go
func main() {
    router := gin.Default()

    // 服务ZIP中的特定文件
    err := router.SetZipFile("/api/spec", "./docs.zip", "api.json")
    if err != nil {
        log.Fatal("设置ZIP文件失败:", err)
    }

    // 访问: http://localhost:8080/api/spec -> docs.zip/api.json

    router.Run(":8080")
}
```

### 高级配置选项

#### 热更新支持

```go
// 启用热更新，每3秒检查ZIP文件变化
router.SetZipFS("./web.zip", "/app",
    gin.WithHotReload(3*time.Second),
)

// 单文件热更新
router.SetZipFile("/config", "./config.zip", "app.json",
    gin.WithFileHotReload(5*time.Second),
)
```

#### 首页文件配置

```go
// 设置默认首页文件
router.SetZipFS("./web.zip", "/app",
    gin.WithIndexFile("main.html"), // 默认为index.html
)

// 访问 /app/ 将自动服务 main.html
```

#### 子路径限制（安全功能）

```go
// 只允许访问ZIP中的特定路径
router.SetZipFS("./assets.zip", "/static",
    gin.WithSubPaths("/public", "/assets/css", "/assets/js"),
)

// 只能访问:
// /static/public/* -> assets.zip/public/*
// /static/assets/css/* -> assets.zip/assets/css/*
// /static/assets/js/* -> assets.zip/assets/js/*
//
// 访问其他路径将返回404
```

#### 密码保护的 ZIP 文件

```go
// 服务加密的ZIP文件
router.SetZipFS("./protected.zip", "/secure",
    gin.WithPassword("your-password"),
    gin.WithHotReload(10*time.Second),
)

// 单文件密码保护
router.SetZipFile("/secret-config", "./encrypted.zip", "config.json",
    gin.WithFilePassword("secret123"),
)
```

### 带中间件的 ZIP 服务

```go
// 为ZIP文件系统添加认证中间件
config := gin.NewZipFSConfig("./admin.zip", "/admin",
    gin.WithPassword("admin123"),
    gin.WithHotReload(5*time.Second),
)

err := router.SetZipFSWithMiddleware(config,
    authMiddleware(),    // 认证中间件
    corsMiddleware(),    // CORS中间件
    loggingMiddleware(), // 日志中间件
)
if err != nil {
    log.Fatal("设置带中间件的ZIP文件系统失败:", err)
}
```

### 路由组集成

```go
// 在路由组中使用ZIP文件系统
adminGroup := router.Group("/admin")
adminGroup.Use(authMiddleware()) // 组级认证

// 为整个路由组设置ZIP文件系统
err := adminGroup.SetZipFS("./admin-ui.zip",
    gin.WithHotReload(3*time.Second),
    gin.WithIndexFile("dashboard.html"),
)

// 路由组中的单文件服务
err = adminGroup.SetZipFile("/config", "./admin-config.zip", "settings.json",
    gin.WithFileHotReload(10*time.Second),
)
```

### 完整配置示例

```go
func main() {
    router := gin.NewRouter(gin.Default())

    // 1. 公开的静态资源（无密码）
    router.SetZipFS("./public.zip", "/public",
        gin.WithHotReload(5*time.Second),
        gin.WithIndexFile("index.html"),
        gin.WithSubPaths("/css", "/js", "/images"), // 安全限制
    )

    // 2. 管理后台（密码保护）
    router.SetZipFS("./admin.zip", "/admin",
        gin.WithPassword("admin-secret"),
        gin.WithHotReload(10*time.Second),
        gin.WithIndexFile("dashboard.html"),
    )

    // 3. API文档（单文件服务）
    router.SetZipFile("/api/docs", "./docs.zip", "swagger.json",
        gin.WithFileHotReload(30*time.Second),
        gin.WithContentType("application/json"),
    )

    // 4. 带中间件的安全区域
    secureConfig := gin.NewZipFSConfig("./secure.zip", "/secure",
        gin.WithPassword("secure123"),
        gin.WithSubPaths("/allowed"),
    )

    router.SetZipFSWithMiddleware(secureConfig,
        authMiddleware(),
        rateLimitMiddleware(),
    )

    // 5. 普通API路由
    router.GET("/api/status", func(c *gin.Context) {
        c.Success(gin.H{"status": "ok"})
    })

    router.Run(":8080")
}
```

### 监控和指标

```go
// 获取ZIP文件系统的监控指标
router.GET("/admin/zipfs/metrics", func(c *gin.Context) {
    // 注意：这需要你保存ZIP文件系统的引用
    zfs, _ := gin.NewZipFileSystem(config)
    metrics := zfs.GetMetrics()

    c.Success(gin.H{
        "reload_count":   metrics.ReloadCount,   // 重载次数
        "last_reload":    metrics.LastReload,    // 最后重载时间
        "error_count":    metrics.ErrorCount,    // 错误次数
        "request_count":  metrics.RequestCount,  // 请求次数
    })
})
```

### 内容类型检测

框架自动检测并设置正确的 Content-Type：

- **HTML 文件**: `text/html; charset=utf-8`
- **CSS 文件**: `text/css; charset=utf-8`
- **JavaScript 文件**: `application/javascript; charset=utf-8`
- **JSON 文件**: `application/json; charset=utf-8`
- **图片文件**: `image/png`, `image/jpeg`, `image/gif`等
- **字体文件**: `font/woff`, `font/woff2`, `font/ttf`等

### 性能特性

1. **内存缓存**: ZIP 文件内容在内存中缓存，避免重复解压
2. **热更新**: 文件修改时自动重载，开发环境友好
3. **并发安全**: 支持多 goroutine 同时访问
4. **路径优化**: 智能路径匹配和规范化
5. **错误恢复**: 自动处理 ZIP 文件损坏等异常情况

### 安全特性

1. **密码保护**: 支持 AES-256 加密的 ZIP 文件
2. **路径限制**: 通过 SubPaths 限制可访问的文件范围
3. **路径遍历防护**: 自动防止`../`等路径遍历攻击
4. **权限控制**: 可结合中间件实现细粒度权限控制

### 实际应用场景

1. **前端资源打包**: 将 React/Vue 构建产物打包成 ZIP 文件部署
2. **配置文件管理**: 将配置文件打包，支持热更新配置
3. **主题系统**: 不同主题的 CSS/JS 文件打包成 ZIP，动态切换
4. **插件系统**: 插件资源打包成 ZIP 文件，动态加载
5. **文档系统**: API 文档、用户手册等打包成 ZIP 文件服务
6. **多租户系统**: 不同租户的资源文件分别打包

### 与嵌入式资源对比

| 特性     | 嵌入式资源(embed.FS) | ZIP 文件系统       |
| -------- | -------------------- | ------------------ |
| 打包方式 | 编译时嵌入           | 运行时加载         |
| 文件更新 | 需要重新编译         | 支持热更新         |
| 内存占用 | 二进制文件大小       | 动态加载           |
| 密码保护 | 不支持               | 支持 AES-256       |
| 路径限制 | 不支持               | 支持子路径限制     |
| 适用场景 | 核心资源、不变资源   | 动态资源、配置文件 |

### 错误处理

```go
// ZIP文件不存在
err := router.SetZipFS("./nonexistent.zip", "/app")
if err != nil {
    log.Printf("ZIP文件系统设置失败: %v", err)
    // 可以设置回退处理
}

// 密码错误
err = router.SetZipFS("./encrypted.zip", "/secure",
    gin.WithPassword("wrong-password"),
)
if err != nil {
    log.Printf("密码可能错误: %v", err)
}

// 文件系统监控
router.GET("/admin/zipfs/status", func(c *gin.Context) {
    // 检查ZIP文件系统状态
    if _, err := os.Stat("./web.zip"); err != nil {
        c.ServerError("ZIP文件不可访问: " + err.Error())
        return
    }
    c.Success("ZIP文件系统正常")
})
```

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

感谢 [gin-gonic/gin](https://github.com/gin-gonic/gin) 团队提供的优秀基础框架。

---

**让 Web 开发更简单、更高效、更优雅！** 🚀
