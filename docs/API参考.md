# API 参考文档

**版本**: v0.1.5
**更新时间**: 2025-11-26
**API 总数**: ~100 个方法

本文档按功能分类列出所有 API，方便快速查找。完整的使用指南请参考 [开发者完整参考手册](./开发者完整参考手册.md)。

---

## 📑 目录

- [Context API](#context-api-60-个方法)
  - [响应方法](#-响应方法-20-个)
  - [请求处理](#-请求处理-15-个)
  - [数据绑定与验证](#-数据绑定与验证-10-个)
  - [会话管理](#-会话管理-8-个)
  - [缓存操作](#-缓存操作-7-个)
- [Router API](#router-api-39-个方法)
  - [路由注册](#-路由注册-15-个)
  - [中间件管理](#-中间件管理-8-个)
  - [配置方法](#-配置方法-10-个)
  - [辅助方法](#-辅助方法-6-个)
- [RouterGroup API](#routergroup-api-15-个方法)

---

## Context API (60 个方法)

### 🎨 响应方法 (20 个)

优雅的响应方法，统一 API 返回格式。

#### 成功响应

| 方法             | 状态码 | 说明       | 示例                       |
| ---------------- | ------ | ---------- | -------------------------- |
| `Success(data)`  | 200    | 成功响应   | `c.Success(user)`          |
| `Created(data)`  | 201    | 创建成功   | `c.Created(newUser)`       |
| `Accepted(data)` | 202    | 已接受处理 | `c.Accepted("任务已提交")` |
| `NoContent()`    | 204    | 无内容     | `c.NoContent()`            |

#### 错误响应

| 方法                      | 状态码 | 说明         | 示例                                                          |
| ------------------------- | ------ | ------------ | ------------------------------------------------------------- |
| `Fail(message)`           | 400    | 业务失败     | `c.Fail("余额不足")`                                          |
| `Error(message)`          | 500    | 业务错误     | `c.Error("操作失败")`                                         |
| `ErrorWithCode(err)`      | 动态   | 统一错误处理 | `c.ErrorWithCode(errors.New(1001).WithMessage("自定义错误"))` |
| `ValidationError(errors)` | 400    | 验证错误     | `c.ValidationError(gin.H{"name": "必填"})`                    |
| `Unauthorized(message)`   | 401    | 未授权       | `c.Unauthorized("请先登录")`                                  |
| `Forbidden(message)`      | 403    | 禁止访问     | `c.Forbidden("无权访问")`                                     |
| `NotFound(message)`       | 404    | 资源不存在   | `c.NotFound("用户不存在")`                                    |
| `ServerError(message)`    | 500    | 服务器错误   | `c.ServerError("系统异常")`                                   |

#### 特殊响应

| 方法                                 | 说明               | 示例                                                                   |
| ------------------------------------ | ------------------ | ---------------------------------------------------------------------- |
| `Paginated(data, page, size, total)` | 分页响应           | `c.Paginated(users, 1, 10, 100)`                                       |
| `PaginateResponse(fetch)`            | 自动分页查询       | `c.PaginateResponse(func(page,size int) (interface{}, int64) { ... })` |
| `StreamFile(path, filename)`         | 以附件形式下载文件 | `c.StreamFile("./data.pdf", "report.pdf")`                             |

**示例**：

```go
// 成功响应
router.GET("/users", func(c *gin.Context) {
    users := getAllUsers()
    c.Success(users)
})

// 创建响应
router.POST("/users", func(c *gin.Context) {
    var user User
    if !c.BindJSON(&user) {
        return
    }
    createdUser := createUser(user)
    c.Created(createdUser)  // 201 状态码
})

// 分页响应
router.GET("/posts", func(c *gin.Context) {
    page := c.ParamInt("page", 1)
    size := c.ParamInt("size", 10)
    posts, total := getPosts(page, size)
    c.Paginated(posts, page, size, total)
})

// 自动分页响应
router.GET("/orders", func(c *gin.Context) {
    c.PaginateResponse(func(page, size int) (interface{}, int64) {
        orders, total := findOrders(page, size)
        return orders, total
    })
})

// 错误响应
router.GET("/users/:id", func(c *gin.Context) {
    id := c.ParamInt("id")
    user := getUser(id)
    if user == nil {
        c.NotFound("用户不存在")  // 404
        return
    }
    c.Success(user)
})
```

---

### 📥 请求处理 (15 个)

处理请求参数、头部、信息提取等。

#### 参数提取

| 方法                       | 说明                                   | 示例                                              |
| -------------------------- | -------------------------------------- | ------------------------------------------------- |
| `Param(key, [default])`    | 智能参数提取（路径 → 查询 → 表单）     | `id := c.Param("id")`                             |
| `ParamInt(key, [default])` | 智能整数参数提取（路径 → 查询 → 表单） | `page := c.ParamInt("page", 1)`                   |
| `Query(key)`               | 查询参数                               | `name := c.Query("name")`                         |
| `DefaultQuery(key, def)`   | 查询参数（带默认值）                   | `page := c.DefaultQuery("page", "1")`             |
| `PostForm(key)`            | 表单参数                               | `title := c.PostForm("title")`                    |
| `RequireParams(keys...)`   | 必填参数验证                           | `if !c.RequireParams("name", "email") { return }` |

#### 请求信息

| 方法        | 说明               | 示例                     |
| ----------- | ------------------ | ------------------------ |
| `Method()`  | 请求方法           | `method := c.Method()`   |
| `Host()`    | 主机名             | `host := c.Host()`       |
| `Scheme()`  | 协议（http/https） | `scheme := c.Scheme()`   |
| `URL()`     | 完整 URL           | `url := c.URL()`         |
| `BaseURL()` | 基础 URL           | `baseURL := c.BaseURL()` |
| `IsSSL()`   | 是否 HTTPS         | `if c.IsSSL() { ... }`   |
| `IsAjax()`  | 是否 AJAX 请求     | `if c.IsAjax() { ... }`  |
| `IsJSON()`  | 是否 JSON 请求     | `if c.IsJSON() { ... }`  |

#### 客户端信息

| 方法             | 说明       | 示例                           |
| ---------------- | ---------- | ------------------------------ |
| `GetIP()`        | 客户端 IP  | `ip := c.GetIP()`              |
| `GetUserAgent()` | User-Agent | `ua := c.GetUserAgent()`       |
| `Domain()`       | 域名       | `domain := c.Domain()`         |
| `RootDomain()`   | 根域名     | `rootDomain := c.RootDomain()` |

**示例**：

```go
// 路径参数
router.GET("/users/:id", func(c *gin.Context) {
    id := c.ParamInt("id")
    user := getUser(id)
    c.Success(user)
})

// 查询参数
router.GET("/search", func(c *gin.Context) {
    keyword := c.Query("q")
    page := c.ParamInt("page", 1)    // 智能提取，支持默认值
    size := c.ParamInt("size", 10)

    results := search(keyword, page, size)
    c.Success(results)
})

// 必填参数验证
router.POST("/contact", func(c *gin.Context) {
    if !c.RequireParams("name", "email", "message") {
        return  // 自动返回 400 错误
    }

    name := c.Query("name")
    email := c.Query("email")
    message := c.Query("message")

    sendEmail(name, email, message)
    c.Success("消息已发送")
})

// 请求信息
router.GET("/info", func(c *gin.Context) {
    c.Success(gin.H{
        "method": c.Method(),
        "host": c.Host(),
        "scheme": c.Scheme(),
        "url": c.URL(),
        "is_ssl": c.IsSSL(),
        "is_ajax": c.IsAjax(),
        "client_ip": c.GetIP(),
        "user_agent": c.GetUserAgent(),
    })
})
```

---

### 📋 数据绑定与验证 (10 个)

JSON、表单数据绑定和验证。

#### 绑定方法

| 方法                   | 说明                    | 示例                                      |
| ---------------------- | ----------------------- | ----------------------------------------- |
| `BindJSON(obj)`        | 绑定 JSON（自动验证）   | `if !c.BindJSON(&user) { return }`        |
| `BindQuery(obj)`       | 绑定查询参数            | `if !c.BindQuery(&filter) { return }`     |
| `BindAndValidate(obj)` | 绑定并验证              | `if !c.BindAndValidate(&data) { return }` |
| `ShouldBindJSON(obj)`  | 绑定 JSON（不自动响应） | `err := c.ShouldBindJSON(&user)`          |

#### 验证方法

| 方法            | 说明     | 示例                              |
| --------------- | -------- | --------------------------------- |
| `Validate(obj)` | 验证对象 | `if !c.Validate(user) { return }` |

**示例**：

```go
// 定义结构体（带验证标签）
type CreateUserRequest struct {
    Name  string `json:"name" binding:"required,min=2,max=50"`
    Email string `json:"email" binding:"required,email"`
    Age   int    `json:"age" binding:"required,gte=18,lte=120"`
}

// JSON 绑定（自动验证和错误响应）
router.POST("/users", func(c *gin.Context) {
    var req CreateUserRequest

    // BindJSON 自动验证并返回 400 错误
    if !c.BindJSON(&req) {
        return  // 已自动响应验证错误
    }

    user := createUser(req)
    c.Created(user)
})

// 查询参数绑定
type SearchFilter struct {
    Keyword string `form:"q" binding:"required"`
    Page    int    `form:"page" binding:"gte=1"`
    Size    int    `form:"size" binding:"gte=1,lte=100"`
}

router.GET("/search", func(c *gin.Context) {
    var filter SearchFilter
    if !c.BindQuery(&filter) {
        return
    }

    results := search(filter)
    c.Success(results)
})

// 手动验证
router.PUT("/users/:id", func(c *gin.Context) {
    var user User
    c.ShouldBindJSON(&user)  // 不自动响应

    // 自定义验证
    if !c.Validate(user) {
        return  // 自动响应验证错误
    }

    updateUser(user)
    c.Success(user)
})
```

---

### 🔐 会话管理 (8 个)

JWT 认证、Session 管理等。

#### JWT 方法

| 方法                                     | 说明                | 示例                                                       |
| ---------------------------------------- | ------------------- | ---------------------------------------------------------- |
| `CreateJWTSession(secret, ttl, payload)` | 创建 JWT            | `token, _ := c.CreateJWTSession("key", 2*time.Hour, data)` |
| `RequireJWT()`                           | 验证并获取 JWT      | `jwt, ok := c.RequireJWT()`                                |
| `GetJWTPayload()`                        | 获取 JWT 载荷       | `payload := c.GetJWTPayload()`                             |
| `RefreshJWTSession(secret, ttl)`         | 刷新 JWT            | `newToken, _ := c.RefreshJWTSession("key", 2*time.Hour)`   |
| `ClearJWT()`                             | 清除 JWT Cookie     | `c.ClearJWT()`                                             |
| `JWTClaimString(key)`                    | 获取 JWT 字符串声明 | `userID := c.JWTClaimString("user_id")`                    |
| `JWTClaimStrings(key)`                   | 获取字符串数组声明  | `roles := c.JWTClaimStrings("roles")`                      |
| `AuthInfo()`                             | 解析当前用户信息    | `info, ok := c.AuthInfo()`                                 |
| `HasRole(role)`                          | 是否包含指定角色    | `if !c.HasRole("admin") { ... }`                           |
| `HasAnyRole(roles...)`                   | 是否包含任意角色    | `c.HasAnyRole("ops","fin")`                                |

#### OAuth 方法

| 方法                             | 说明            | 示例                                        |
| -------------------------------- | --------------- | ------------------------------------------- |
| `GenerateTokens(claims, config)` | 生成 OAuth 令牌 | `tokens, _ := c.GenerateTokens(userClaims)` |

**示例**：

```go
// 登录 - 创建 JWT
router.POST("/login", func(c *gin.Context) {
    var req LoginRequest
    if !c.BindJSON(&req) {
        return
    }

    user := authenticateUser(req.Username, req.Password)
    if user == nil {
        c.Unauthorized("用户名或密码错误")
        return
    }

    // 创建 JWT（2小时有效期）
    token, _ := c.CreateJWTSession("your-secret-key", 2*time.Hour, gin.H{
        "user_id": user.ID,
        "username": user.Username,
        "role": user.Role,
    })

    c.Success(gin.H{
        "token": token,
        "user": user,
    })
})

// 受保护路由 - 验证 JWT
func AuthMiddleware(c *gin.Context) {
    jwt, ok := c.RequireJWT()  // 自动验证并返回 401
    if !ok {
        return
    }

    // 设置用户信息
    c.Set("user_id", jwt["user_id"])
    c.Set("username", jwt["username"])
    c.Set("role", jwt["role"])

    c.Next()
}

router.GET("/profile", func(c *gin.Context) {
    payload := c.GetJWTPayload()
    userID := payload["user_id"]

    user := getUserByID(userID)
    c.Success(user)
}, AuthMiddleware)

// 刷新令牌
router.POST("/refresh", func(c *gin.Context) {
    newToken, err := c.RefreshJWTSession("your-secret-key", 2*time.Hour)
    if err != nil {
        c.Unauthorized("令牌已过期")
        return
    }

    c.Success(gin.H{"token": newToken})
})

// 登出
router.POST("/logout", func(c *gin.Context) {
    c.ClearJWT()
    c.Success("登出成功")
})

// OAuth 令牌生成
router.POST("/oauth/token", func(c *gin.Context) {
    // 验证用户...

    claims := gin.UserClaims{
        UserID:   "user123",
        Username: "john",
        Roles:    []string{"user", "admin"},
        Scope:    "read write",
    }

    tokens, _ := c.GenerateTokens(claims)
    c.Success(tokens)
})
```

---

### 💾 缓存操作 (7 个)

内存缓存操作。

#### 基础缓存

| 方法                                | 说明                   | 示例                                            |
| ----------------------------------- | ---------------------- | ----------------------------------------------- |
| `GetCache()`                        | 获取缓存实例           | `cache := c.GetCache()`                         |
| `cache.Get(key)`                    | 获取缓存               | `value, found := cache.Get("key")`              |
| `cache.Set(key, value)`             | 设置缓存（默认 TTL）   | `cache.Set("key", value)`                       |
| `cache.SetWithTTL(key, value, ttl)` | 设置缓存（自定义 TTL） | `cache.SetWithTTL("key", value, 5*time.Minute)` |
| `cache.Delete(key)`                 | 删除缓存               | `cache.Delete("key")`                           |
| `cache.Clear()`                     | 清空所有缓存           | `cache.Clear()`                                 |

#### 列表缓存

| 方法                             | 说明         | 示例                                     |
| -------------------------------- | ------------ | ---------------------------------------- |
| `cache.SetList(key, ttl)`        | 创建列表缓存 | `cache.SetList("queue", 10*time.Minute)` |
| `cache.LPush(key, values...)`    | 左侧插入     | `cache.LPush("queue", "task1", "task2")` |
| `cache.RPush(key, values...)`    | 右侧插入     | `cache.RPush("queue", "task3")`          |
| `cache.LPop(key)`                | 左侧弹出     | `value, _ := cache.LPop("queue")`        |
| `cache.RPop(key)`                | 右侧弹出     | `value, _ := cache.RPop("queue")`        |
| `cache.LRange(key, start, stop)` | 范围获取     | `list := cache.LRange("queue", 0, -1)`   |
| `cache.LLen(key)`                | 列表长度     | `length := cache.LLen("queue")`          |

**示例**：

```go
// 启用缓存
router := gin.NewRouter(
    gin.WithCache(&cache.Config{
        TTL: 30 * time.Minute,
        CleanupInterval: 5 * time.Minute,
    }),
)

// 基础缓存
router.GET("/users/:id", func(c *gin.Context) {
    id := c.Param("id")
    cacheKey := "user:" + id

    cache := c.GetCache()

    // 尝试从缓存获取
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

    // 设置缓存（5分钟）
    cache.SetWithTTL(cacheKey, user, 5*time.Minute)

    c.Success(user)
})

// 列表缓存 - 任务队列
router.POST("/tasks", func(c *gin.Context) {
    var task Task
    if !c.BindJSON(&task) {
        return
    }

    cache := c.GetCache()
    queueKey := "task_queue"

    // 创建列表缓存
    cache.SetList(queueKey, 1*time.Hour)

    // 添加任务到队列
    cache.RPush(queueKey, task)

    c.Success(gin.H{
        "queue_length": cache.LLen(queueKey),
    })
})

router.GET("/tasks/next", func(c *gin.Context) {
    cache := c.GetCache()
    queueKey := "task_queue"

    // 弹出第一个任务
    task, err := cache.LPop(queueKey)
    if err != nil {
        c.NotFound("队列为空")
        return
    }

    c.Success(task)
})

// 缓存管理
router.DELETE("/cache", func(c *gin.Context) {
    key := c.Query("key")
    cache := c.GetCache()

    if key == "" {
        cache.Clear()  // 清空所有缓存
        c.Success("所有缓存已清空")
    } else {
        cache.Delete(key)  // 删除特定缓存
        c.Success("缓存已删除")
    }
})
```

---

## Router API (39 个方法)

### 🛣️ 路由注册 (15 个)

注册各种路由和处理函数。

#### 标准 HTTP 方法

| 方法                         | 说明         | 示例                                      |
| ---------------------------- | ------------ | ----------------------------------------- |
| `GET(path, handlers...)`     | GET 路由     | `router.GET("/users", listUsers)`         |
| `POST(path, handlers...)`    | POST 路由    | `router.POST("/users", createUser)`       |
| `PUT(path, handlers...)`     | PUT 路由     | `router.PUT("/users/:id", updateUser)`    |
| `DELETE(path, handlers...)`  | DELETE 路由  | `router.DELETE("/users/:id", deleteUser)` |
| `PATCH(path, handlers...)`   | PATCH 路由   | `router.PATCH("/users/:id", patchUser)`   |
| `HEAD(path, handlers...)`    | HEAD 路由    | `router.HEAD("/users/:id", headUser)`     |
| `OPTIONS(path, handlers...)` | OPTIONS 路由 | `router.OPTIONS("/users", optionsUsers)`  |
| `Any(path, handlers...)`     | 所有方法     | `router.Any("/webhook", handleWebhook)`   |

#### 快捷路由

| 方法                                     | 说明                           | 示例                                                               |
| ---------------------------------------- | ------------------------------ | ------------------------------------------------------------------ |
| `CRUD(prefix, handler, opts...)`         | CRUD 路由组（ResourceHandler） | `router.CRUD("users", &UserResource{})`                            |
| `REST(resource, handler, opts...)`       | 可配置 REST 路由               | `router.REST("projects", ctrl, gin.RESTWithIDParam("project_id"))` |
| `API(version)`                           | API 版本路由组                 | `v1 := router.API("v1")`                                           |
| `Upload(path, handler)`                  | 文件上传路由                   | `router.Upload("/upload", uploadHandler)`                          |
| `StaticFiles(path, dir, middlewares...)` | 静态文件服务                   | `router.StaticFiles("/static", "./public")`                        |
| `Health(path...)`                        | 健康检查端点                   | `router.Health()`                                                  |
| `Metrics(path...)`                       | 监控端点                       | `router.Metrics()`                                                 |

#### 路由组

| 方法            | 说明       | 示例                          |
| --------------- | ---------- | ----------------------------- |
| `Group(prefix)` | 创建路由组 | `api := router.Group("/api")` |

**示例**：

```go
// 标准路由
router.GET("/users", listUsers)
router.POST("/users", createUser)
router.PUT("/users/:id", updateUser)
router.DELETE("/users/:id", deleteUser)

// CRUD 快捷路由（编译期校验）
type PostResource struct{}
func (p *PostResource) Index(c *gin.Context)  { c.Success(listPosts()) }
func (p *PostResource) Show(c *gin.Context)   { c.Success(showPost(c.Param("id"))) }
func (p *PostResource) Create(c *gin.Context) { c.Created(createPost(c)) }
func (p *PostResource) Update(c *gin.Context) { c.Success(updatePost(c.Param("id"), c)) }
func (p *PostResource) Delete(c *gin.Context) { c.Success(deletePost(c.Param("id"))) }

router.CRUD("posts", &PostResource{})
// 自动生成 GET/POST/PUT/PATCH/DELETE 路由

// API 版本管理
v1 := router.API("v1")  // /api/v1
v2 := router.API("v2")  // /api/v2

v1.GET("/users", listUsersV1)
v2.GET("/users", listUsersV2)

// 文件上传
router.Upload("/upload", func(c *gin.Context, file *multipart.FileHeader) error {
    return saveFile(file)
})

// 静态文件
router.StaticFiles("/static", "./public")
router.StaticFiles("/assets", "./assets", authMiddleware)

// REST 资源（支持自定义 ID、文档、附加中间件）
router.REST("projects", projectController{},
    gin.RESTWithIDParam("project_id"),
    gin.RESTWithDoc("list", gin.Summary("项目列表")),
)

// 健康检查和监控
router.Health()        // GET /health
router.Metrics()       // GET /metrics
router.Health("/status")    // 自定义路径
router.Metrics("/stats")

// 路由组
api := router.Group("/api")
{
    api.GET("/users", listUsers)
    api.POST("/users", createUser)
}

admin := router.Group("/admin")
admin.Use(AdminAuthMiddleware)
{
    admin.GET("/stats", getStats)
    admin.GET("/users", listAllUsers)
}
```

---

### ⚙️ 中间件管理 (8 个)

中间件注册和管理。

| 方法                             | 说明             | 示例                                                              |
| -------------------------------- | ---------------- | ----------------------------------------------------------------- |
| `Use(middlewares...)`            | 添加中间件       | `router.Use(logger, recovery)`                                    |
| `WithMiddleware(middlewares...)` | 选项式添加中间件 | 初始化时使用                                                      |
| `RequireAuth(scopes...)`         | OAuth 认证中间件 | `router.GET("/api/data", handler, router.RequireAuth("admin"))`   |
| `RequireRoles(roles...)`         | 要求具备全部角色 | `router.GET("/admin", handler, router.RequireRoles("admin"))`     |
| `RequireAnyRole(roles...)`       | 任一角色即可     | `router.GET("/ops", handler, router.RequireAnyRole("ops","sre"))` |

**示例**：

```go
// 全局中间件
router.Use(gin.Logger(), gin.Recovery())

// 路由组中间件
api := router.Group("/api")
api.Use(AuthMiddleware, RateLimitMiddleware)
{
    api.GET("/users", listUsers)
}

// 单个路由中间件
router.GET("/admin", adminHandler, AdminAuthMiddleware)

// OAuth 认证
router.GET("/api/profile", getProfile, router.RequireAuth())
router.GET("/api/admin", adminOnly, router.RequireAuth("admin"))
```

---

### 🔧 配置方法 (10 个)

路由器配置和初始化。

#### 初始化选项

| 方法                    | 说明         | 示例                                          |
| ----------------------- | ------------ | --------------------------------------------- |
| `Default()`             | 默认路由器   | `router := gin.Default()`                     |
| `NewRouter(options...)` | 选项式路由器 | `router := gin.NewRouter(gin.WithJWT("key"))` |

#### 配置选项

| 方法                       | 说明             | 示例                                                                                             |
| -------------------------- | ---------------- | ------------------------------------------------------------------------------------------------ |
| `WithGinMode(mode)`        | 设置模式         | `gin.WithGinMode("release")`                                                                     |
| `WithJWT(secret)`          | 启用 JWT         | `gin.WithJWT("secret-key")`                                                                      |
| `WithCache(config)`        | 启用缓存         | `gin.WithCache(&cache.Config{TTL: 1*time.Hour})`                                                 |
| `WithSSE(config)`          | 启用 SSE         | `gin.WithSSE(&sse.Config{HistorySize: 1000})`                                                    |
| `WithOpenAPI(spec)`        | 启用 OpenAPI     | `gin.WithOpenAPI(&gin.OpenAPI{Title: "API"})`                                                    |
| `WithCORS(origins...)`     | 启用 CORS        | `gin.WithCORS("http://localhost:3000")`                                                          |
| `WithSecurityConfig(func)` | 自定义安全配置   | `gin.WithSecurityConfig(func(sec *gin.SecurityConfig) { sec.RateLimitRequestsPerMinute = 200 })` |
| `WithConfig(func)`         | 直接调整框架配置 | `gin.WithConfig(func(cfg *gin.Config) { cfg.ErrorHandlerEnabled = true })`                       |
| `WithRateLimit(rpm)`       | 启用限流         | `gin.WithRateLimit(100)`                                                                         |
| `WithRequestID()`          | 启用请求 ID      | `gin.WithRequestID()`                                                                            |
| `WithTimeout(duration)`    | 设置超时         | `gin.WithTimeout(30*time.Second)`                                                                |

#### 其他配置

| 方法                  | 说明            | 示例                               |
| --------------------- | --------------- | ---------------------------------- |
| `EnableSwagger(path)` | 启用 Swagger UI | `router.EnableSwagger("/swagger")` |

**示例**：

```go
// 简单配置
router := gin.Default()

// 完整配置
router := gin.NewRouter(
    gin.WithGinMode("release"),
    gin.WithJWT("your-secret-key"),
    gin.WithCache(&cache.Config{
        TTL: 30 * time.Minute,
        CleanupInterval: 5 * time.Minute,
    }),
    gin.WithSSE(&sse.Config{
        HistorySize: 1000,
        PingInterval: 30 * time.Second,
    }),
    gin.WithOpenAPI(&gin.OpenAPI{
        Title: "My API",
        Version: "1.0.0",
    }),
    gin.WithCORS("http://localhost:3000", "https://example.com"),
    gin.WithSecurityConfig(func(sec *gin.SecurityConfig) {
        sec.RateLimitRequestsPerMinute = 200
    }),
    gin.WithConfig(func(cfg *gin.Config) {
        cfg.ErrorHandlerEnabled = true
    }),
    gin.WithRateLimit(1000),  // 1000次/分钟
    gin.WithRequestID(),
    gin.WithTimeout(30*time.Second),
)

// 详细 CORS 配置（自定义中间件）
router.Use(func(c *gin.Context) {
    origin := c.GetHeader("Origin")
    if origin != "https://example.com" {
        c.AbortWithStatus(http.StatusForbidden)
        return
    }

    c.Header("Access-Control-Allow-Origin", origin)
    c.Header("Access-Control-Allow-Methods", "GET,POST,PUT")
    c.Header("Access-Control-Allow-Headers", "Content-Type,Authorization")
    c.Header("Access-Control-Expose-Headers", "X-Total-Count")
    c.Header("Access-Control-Allow-Credentials", "true")
    if c.Request.Method == http.MethodOptions {
        c.AbortWithStatus(http.StatusNoContent)
        return
    }
    c.Next()
})

// 启用 Swagger
router.EnableSwagger("/swagger")
// 访问: http://localhost:8080/swagger/index.html
```

---

### 🛠️ 辅助方法 (6 个)

辅助功能和工具方法。

| 方法                                     | 说明                   | 示例                                                            |
| ---------------------------------------- | ---------------------- | --------------------------------------------------------------- |
| `Run(addr)`                              | 启动服务器             | `router.Run(":8080")`                                           |
| `OAuth()`                                | 添加 OAuth 端点        | `router.OAuth()`                                                |
| `JWTAuthRoutes(config)`                  | 注册登录/刷新/注销 API | `router.JWTAuthRoutes(gin.JWTAuthRoutesConfig{...})`            |
| `GetSSEHub()`                            | 获取 SSE Hub           | `hub := router.GetSSEHub()`                                     |
| `SetEmbed(path, fs, stripPrefix...)`     | 嵌入静态资源           | `router.SetEmbed("/static", staticFS)`                          |
| `SetEmbedFile(path, fs, filename)`       | 嵌入单文件             | `router.SetEmbedFile("/favicon.ico", faviconFS, "favicon.ico")` |
| `SetZipFS(zipPath, urlPath, options...)` | ZIP 文件系统           | `router.SetZipFS("./web.zip", "/app")`                          |

**示例**：

```go
// 启动服务器
router.Run(":8080")
router.Run("localhost:3000")

// OAuth 端点
router.OAuth()
// 自动创建：
// POST /oauth/token
// POST /oauth/refresh
// GET /oauth/userinfo
// POST /oauth/revoke

// JWT 登录/刷新/注销快速路由
router.JWTAuthRoutes(gin.JWTAuthRoutesConfig{
    BasePath: "/auth",
    Authenticate: func(c *gin.Context) (*gin.AuthInfo, error) {
        var form LoginForm
        if !c.BindJSON(&form) {
            return nil, fmt.Errorf("invalid payload")
        }
        user, err := authService.Login(form.Username, form.Password)
        if err != nil {
            return nil, err
        }
        return &gin.AuthInfo{UserID: user.ID, Username: user.Username, Roles: user.Roles}, nil
    },
})

// SSE Hub
hub := router.GetSSEHub()
hub.Broadcast(&sse.Event{
    Event: "notification",
    Data: gin.H{"message": "系统通知"},
})

// 嵌入静态资源
//go:embed static/*
var staticFS embed.FS

router.SetEmbed("/static", staticFS, "static")
router.SetEmbedFile("/favicon.ico", faviconFS, "favicon.ico")

// ZIP 文件系统
router.SetZipFS("./web.zip", "/app",
    gin.WithHotReload(5*time.Second),
    gin.WithPassword("secret"),
)
```

---

## RouterGroup API (15 个方法)

`RouterGroup` 继承自 `gin.RouterGroup`，提供分组路由功能。

### 路由注册

所有 HTTP 方法（GET、POST、PUT、DELETE、PATCH、HEAD、OPTIONS、Any）。

### 中间件管理

| 方法                  | 说明       | 示例                        |
| --------------------- | ---------- | --------------------------- |
| `Use(middlewares...)` | 添加中间件 | `group.Use(authMiddleware)` |

### 路由组管理

| 方法            | 说明         | 示例                                |
| --------------- | ------------ | ----------------------------------- |
| `Group(prefix)` | 创建子路由组 | `subGroup := group.Group("/admin")` |

### OpenAPI 支持

| 方法                     | 说明     | 示例                                |
| ------------------------ | -------- | ----------------------------------- |
| `WithTags(tags...)`      | 设置标签 | `group.WithTags("User Management")` |
| `WithSecurity(names...)` | 设置安全 | `group.WithSecurity("bearerAuth")`  |

### ZIP 文件系统

| 方法                                              | 说明         | 示例                                                      |
| ------------------------------------------------- | ------------ | --------------------------------------------------------- |
| `SetZipFS(zipPath, options...)`                   | ZIP 文件系统 | `group.SetZipFS("./admin.zip")`                           |
| `SetZipFile(path, zipPath, filename, options...)` | ZIP 单文件   | `group.SetZipFile("/config", "./config.zip", "app.json")` |

**示例**：

```go
// 基本路由组
api := router.Group("/api")
{
    api.GET("/users", listUsers)
    api.POST("/users", createUser)
}

// 带中间件的路由组
admin := router.Group("/admin")
admin.Use(AdminAuthMiddleware, AuditLogMiddleware)
{
    admin.GET("/users", listAllUsers)
    admin.DELETE("/users/:id", deleteUser)
}

// 嵌套路由组
api := router.Group("/api")
{
    v1 := api.Group("/v1")
    {
        v1.GET("/users", listUsersV1)
    }

    v2 := api.Group("/v2")
    {
        v2.GET("/users", listUsersV2)
    }
}

// OpenAPI 标签
users := router.Group("/api/users").
    WithTags("User Management").
    WithSecurity("bearerAuth")
{
    users.GET("/", listUsers)
    users.POST("/", createUser)
}

// ZIP 文件系统
adminGroup := router.Group("/admin")
adminGroup.Use(AdminAuthMiddleware)
adminGroup.SetZipFS("./admin-ui.zip",
    gin.WithHotReload(5*time.Second),
)
```

---

## 🔍 快速查找

### 按使用场景查找

#### 响应相关

- 成功: `Success`, `Created`, `Accepted`, `NoContent`
- 失败: `Fail`, `Error`, `ErrorWithCode`
- 错误: `ValidationError`, `Unauthorized`, `Forbidden`, `NotFound`, `ServerError`
- 特殊: `Paginated`, `PaginateResponse`, `StreamFile`

#### 请求相关

- 参数: `Param`, `ParamInt`, `Query`, `DefaultQuery`, `PostForm`, `RequireParams`
- 验证: `RequireParams`
- 信息: `Method`, `Host`, `URL`, `GetIP`, `GetUserAgent`

#### 数据处理

- 绑定: `BindJSON`, `BindQuery`, `BindAndValidate`
- 验证: `Validate`

#### 认证授权

- JWT: `CreateJWTSession`, `RequireJWT`, `GetJWTPayload`, `JWTClaimString`, `AuthInfo`, `HasRole`
- OAuth: `GenerateTokens`, `RequireAuth`

#### 缓存

- 基础: `Get`, `Set`, `Delete`, `Clear`
- 列表: `LPush`, `RPush`, `LPop`, `RPop`, `LRange`, `LLen`

#### 路由

- HTTP: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`
- 快捷: `CRUD`, `API`, `Upload`, `Health`, `Metrics`
- 组织: `Group`, `Use`

---

## 📚 相关文档

- **[快速入门](./快速入门.md)** - 30 分钟上手教程
- **[README.md](../README.md)** - 完整功能说明
- **[技术架构手册.md](./技术架构手册.md)** - 深入理解
- **[评估报告勘误说明.md](./评估报告勘误说明.md)** - 常见误解澄清

---

**更新时间**: 2025-10-25
**维护者**: Darkit Team
