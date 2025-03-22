# Gin Framework - Context扩展

[![Go Reference](https://pkg.go.dev/badge/github.com/darkit/gin.svg)](https://pkg.go.dev/github.com/darkit/gin)
[![Go Report Card](https://goreportcard.com/badge/github.com/darkit/gin)](https://goreportcard.com/report/github.com/darkit/gin)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/darkit/gin/blob/master/LICENSE)

Gin是一个高性能的Web框架，本项目在保持 Gin 高性能特性的同时，通过扩展 Context 和增加实用工具，简化了常见的 Web 开发任务，旨在提供简单易用的API和高效的路由处理。

## 特性

- 统一的响应格式
- 简化的参数获取
- 文件上传处理
- URL 构建工具
- 增强的请求信息获取
- 跨域(CORS)支持
- 分页响应支持
- 中间件机制
- 服务器发送事件(SSE)支持
- JWT认证系统（零依赖，基于标准库）
- 数据验证辅助
- 缓存控制方法
- 安全性增强
- 国际化支持
- 会话管理工具
- 缓存系统（内存缓存、列表缓存、持久化）

## 安装

```bash
go get github.com/darkit/gin
```

## 快速开始

### 基础路由

```go
func main() {
    r := gin.Default()
    
    // 简单的 GET 请求处理
    r.GET("/ping", func(c *gin.Context) {
        c.Success("pong")
    })
    
    r.Run(":8080")
}
```

### 路由组和中间件

```go
// 认证中间件
func AuthMiddleware(c *gin.Context) {
    token := c.GetToken()
    if token == "" {
        c.Forbidden("未授权访问")
        c.Abort()
        return
    }
    c.Next()
}

// 路由组使用
api := r.Group("/api", AuthMiddleware)
{
    api.GET("/users", ListUsers)
    api.POST("/users", CreateUser)
}
```

### 参数获取和验证

```go
r.POST("/users", func(c *gin.Context) {
    // 必需参数验证
    if !c.RequireParams("username", "email") {
        return
    }

    // 获取参数
    username := c.Param("username")
    email := c.Param("email")
    age := c.ParamInt("age", 0) // 带默认值的整数参数

    // 处理逻辑...
    c.SuccessWithMsg("用户创建成功", gin.H{
        "username": username,
        "email": email,
        "age": age,
    })
})
```

### 文件上传

```go
r.POST("/upload", func(c *gin.Context) {
    file, err := c.FormFile("file")
    if err != nil {
        c.Fail("文件上传失败")
        return
    }

    config := gin.UploadConfig{
        AllowedExts: []string{".jpg", ".png", ".pdf"},
        MaxSize:     10 * 1024 * 1024, // 10MB
        SavePath:    "./uploads",
    }

    filename, err := c.SaveUploadedFile(file, config)
    if err != nil {
        c.Fail("文件保存失败: " + err.Error())
        return
    }

    c.Success(gin.H{"filename": filename})
})
```

### JWT认证

```go
// 定义密钥（实际应用中应该从环境变量或配置中读取）
const secretKey = "your-secure-secret-key"

// 用户登录
r.POST("/login", func(c *gin.Context) {
    // 验证用户凭据...
    userID := "12345" // 验证成功后获取的用户ID
    
    // 创建JWT会话，有效期24小时
    token, err := c.CreateJWTSession(secretKey, userID, 24*time.Hour, gin.H{
        "username": "张三",
        "role": "admin",
    })
    
    if err != nil {
        c.Error("生成令牌失败: " + err.Error())
        return
    }
    
    c.Success(gin.H{"token": token})
})

// 需要认证的接口
r.GET("/protected", func(c *gin.Context) {
    // 验证JWT令牌并获取载荷
    payload, ok := c.RequireJWT(secretKey)
    if !ok {
        // RequireJWT已经设置了错误响应
        return
    }
    
    // 从载荷中获取用户信息
    userID := payload[gin.JWTClaimSub].(string)
    username, _ := payload["username"].(string)
    
    c.Success(gin.H{
        "message": "授权访问成功",
        "user_id": userID,
        "username": username,
    })
})

// 刷新令牌
r.GET("/refresh", func(c *gin.Context) {
    token, err := c.RefreshJWTSession(secretKey, 24*time.Hour)
    if err != nil {
        c.Fail("刷新令牌失败: " + err.Error())
        return
    }
    
    c.Success(gin.H{"token": token})
})

// 注销
r.GET("/logout", func(c *gin.Context) {
    c.ClearJWT()
    c.Success("已注销")
})
```

### 数据验证

```go
// 定义带验证功能的结构体
type UserForm struct {
    Username string `json:"username" binding:"required"`
    Email    string `json:"email" binding:"required,email"`
    Age      int    `json:"age" binding:"min=0,max=120"`
}

// 实现Validator接口
func (u UserForm) Validate() (bool, string) {
    if len(u.Username) < 3 {
        return false, "用户名长度不能少于3个字符"
    }
    if !strings.Contains(u.Email, "@") {
        return false, "邮箱格式不正确"
    }
    if u.Age < 18 {
        return false, "年龄必须大于等于18岁"
    }
    return true, ""
}

// 在控制器中使用
r.POST("/users", func(c *gin.Context) {
    var form UserForm
    
    // 绑定JSON数据
    if !c.BindJSON(&form) {
        return
    }
    
    // 验证数据
    if !c.Validate(form) {
        return  // Validate会自动处理错误响应
    }
    
    // 数据验证通过，继续处理...
    c.Success(gin.H{"message": "用户创建成功"})
})
```

### 缓存控制

```go
r.GET("/no-cache", func(c *gin.Context) {
    // 设置禁止缓存响应头
    c.NoCache()
    c.Success("这个响应不会被缓存")
})

r.GET("/cache", func(c *gin.Context) {
    // 设置缓存300秒
    c.Cache(300)
    c.Success("这个响应会被缓存5分钟")
})
```

### 安全增强

```go
r.GET("/secure", func(c *gin.Context) {
    // 设置常用安全头
    c.SetSecureHeaders()
    
    // 设置内容安全策略
    c.SetCSP("default-src 'self'; script-src 'self' https://trusted.cdn.com;")
    
    // 设置X-Frame-Options以防止点击劫持
    c.SetXFrameOptions("DENY")
    
    c.Success("安全增强的响应")
})
```

### 获取切片参数

```go
r.GET("/items", func(c *gin.Context) {
    // 获取整型ID列表，例如 ?ids=1,2,3
    ids := c.GetIntSlice("ids")
    
    // 获取字符串标签列表，例如 ?tags=go,web,api
    tags := c.GetStringSlice("tags")
    
    // 可以指定分隔符，例如 ?ids=1|2|3
    customIds := c.GetIntSlice("ids", "|")
    
    c.Success(gin.H{
        "ids": ids,
        "tags": tags,
        "custom_ids": customIds,
    })
})
```

### 分页处理

```go
r.GET("/users", func(c *gin.Context) {
    // 从查询参数获取分页信息，默认页码1，每页10条
    page, pageSize := c.Paginate(20) // 可以指定默认每页大小
    
    // 使用分页参数查询数据库
    offset := (page - 1) * pageSize
    
    // 假设这里是从数据库查询的逻辑
    users := []gin.H{} // 数据库查询结果
    totalCount := int64(100) // 总记录数
    
    // 返回分页响应
    c.PageResponse(users, totalCount, page, pageSize)
})
```

### 会话管理

```go
r.GET("/session", func(c *gin.Context) {
    // 设置会话数据
    c.SessionSet("user_id", "12345")
    c.SessionSet("logged_in", true)
    c.SessionSet("login_time", time.Now())
    
    c.Success("会话数据已设置")
})

r.GET("/profile", func(c *gin.Context) {
    // 获取会话数据
    userID := c.SessionGetString("user_id")
    isLoggedIn := c.SessionGetBool("logged_in")
    
    if !isLoggedIn {
        c.Forbidden("请先登录")
        return
    }
    
    c.Success(gin.H{
        "user_id": userID,
        "logged_in": isLoggedIn,
    })
})
```

### 国际化支持

```go
r.GET("/welcome", func(c *gin.Context) {
    // 获取客户端语言
    lang := c.Language()
    
    // 根据语言返回不同的欢迎信息
    message := "欢迎使用"
    if strings.HasPrefix(lang, "en") {
        message = "Welcome"
    } else if strings.HasPrefix(lang, "ja") {
        message = "ようこそ"
    }
    
    c.Success(gin.H{"message": message, "language": lang})
})
```

### 服务器发送事件 (SSE)

```go
// 创建 SSE Hub，配置历史记录大小
hub := r.NewSSEHub(20)
go hub.Run()

// 处理客户端连接，支持事件过滤
r.GET("/events", func(c *gin.Context) {
    // 创建客户端连接，并订阅特定事件
    client := c.NewSSEClient(hub, "user.created", "user.updated", "ping")
    
    // 可以设置自定义客户端ID
    customID := c.Query("client_id")
    if customID != "" {
        client.ID = customID
    }
    
    // 发送初始连接事件
    hub.SendToClient(client.ID, &gin.SSEEvent{
        Event: "user.created",
        Data:  gin.H{"message": "连接成功", "client_id": client.ID},
    })
    
    // 等待客户端断开连接
    <-client.Disconnected
})

// 广播消息到所有客户端
r.POST("/broadcast", func(c *gin.Context) {
    hub.BroadCast(&gin.SSEEvent{
        Event: "user.created",
        Data:  gin.H{"message": "这是广播消息"},
        ID:    fmt.Sprintf("%d", time.Now().UnixNano()),
    })
})

// 发送消息到指定客户端
r.POST("/send/:clientID", func(c *gin.Context) {
    clientID := c.Param("clientID")
    success := hub.SendToClient(clientID, &gin.SSEEvent{
        Event: "user.created",
        Data:  gin.H{"message": "这是定向消息"},
    })
    if success {
        c.Success("消息发送成功")
    } else {
        c.Fail("客户端不存在或已断开")
    }
})

// 获取所有在线客户端
r.GET("/clients", func(c *gin.Context) {
    clients := hub.GetClients()
    c.Success(gin.H{
        "clients": clients,
        "count":   len(clients),
    })
})

// Hub 管理接口
r.GET("/close", func(c *gin.Context) {
    hub.Close()
    c.Success("关闭成功")
})

r.GET("/restart", func(c *gin.Context) {
    if !hub.IsRunning() {
        hub.Restart()
        c.Success("重启成功")
    }
})

r.GET("/status", func(c *gin.Context) {
    c.Success(gin.H{"running": hub.IsRunning()})
})
```

#### SSE Hub 特性

- 支持客户端事件过滤
- 自动心跳检测
- 断线自动清理
- 消息历史记录
- 支持自定义客户端ID
- 支持广播和定向消息
- Hub 状态管理
- 优雅关闭和重启

#### 客户端示例

```javascript
// 建立 SSE 连接
const clientId = 'client_' + Date.now();
const evtSource = new EventSource('/events?client_id=' + clientId);

// 连接建立事件
evtSource.onopen = function() {
    console.log('SSE 连接已建立');
};

// 监听特定事件
evtSource.addEventListener('user.created', function(e) {
    const data = JSON.parse(e.data);
    console.log('收到用户创建事件:', data);
});

evtSource.addEventListener('user.updated', function(e) {
    const data = JSON.parse(e.data);
    console.log('收到用户更新事件:', data);
});

// 心跳事件
evtSource.addEventListener('ping', function(e) {
    console.log('收到心跳:', e.data);
});

// 错误处理
evtSource.onerror = function(e) {
    console.log('连接错误或关闭');
    evtSource.close();
};
```

#### 注意事项

1. SSE Hub 支持自动的心跳检测和断线清理
2. 客户端可以通过事件过滤器只接收感兴趣的事件
3. 支持消息历史记录，断线重连时可以补发消息
4. Hub 提供了完整的状态管理和控制接口
5. 建议在生产环境中适当配置心跳间隔和超时时间

### URL 构建

```go
// 创建URL构建器并链式调用相关方法
url := c.BuildUrl("/api/users").
       Set("page", 1).
       Set("size", 10).
       Domain("api.example.com").
       Scheme("https").
       Builder()

// 注意: 从2.0版本开始，URL构建器的方法已更改为私有方法
// 但仍然保持链式调用的便捷特性
```

### 请求信息获取

```go
r.GET("/info", func(c *gin.Context) {
    info := gin.H{
        "method":      c.Method(),
        "host":        c.Host(),
        "domain":      c.Domain(),
        "subdomain":   c.SubDomain(),
        "scheme":      c.Scheme(),
        "path":        c.BaseURL(),
        "url":         c.URL(),
        "contentType": c.ContentType(),
        "isAjax":     c.IsAjax(),
        "isJson":     c.IsJson(),
        "isSsl":      c.IsSsl(),
        "clientIP":    c.GetIP(),
        "userAgent":   c.GetUserAgent(),
    }
    c.Success(info)
})
```

### RESTful 资源路由

```go
// 定义资源处理器
type UserResource struct {
    *gin.RestfulHandler
}

func (r *UserResource) Index(c *gin.Context)  { ... } // GET /users
func (r *UserResource) Show(c *gin.Context)   { ... } // GET /users/:id
func (r *UserResource) Create(c *gin.Context) { ... } // POST /users
func (r *UserResource) Update(c *gin.Context) { ... } // PUT /users/:id
func (r *UserResource) Delete(c *gin.Context) { ... } // DELETE /users/:id

// 注册资源路由
r.Resource("/users", &UserResource{})

// 带中间件的资源路由
api := r.Group("/api", AuthMiddleware)
api.Resource("/users", &UserResource{})
```

### 缓存系统

```go
func main() {
    r := gin.Default()
    
    // 初始化全局缓存
    // 参数: 默认过期时间, 清理间隔
    cache := gin.SetGlobalCache(10*time.Minute, 30*time.Second)
    
    // 带持久化的缓存
    // gin.SetGlobalCacheWithPersistence(10*time.Minute, 30*time.Second, "./cache.dat", 5*time.Minute)
    
    r.GET("/cache/set", func(c *gin.Context) {
        // 设置缓存，可选过期时间（不传则使用默认过期时间）
        c.CacheSet("user:123", gin.H{"name": "张三", "age": 30}, 5*time.Minute)
        
        // 设置不同类型的缓存数据
        c.CacheSet("counter", 1)
        c.CacheSet("enabled", true)
        c.CacheSet("score", 95.5)
        
        c.Success("缓存已设置")
    })
    
    r.GET("/cache/get", func(c *gin.Context) {
        // 获取基本缓存
        value, exists := c.CacheGet("user:123")
        if !exists {
            c.Fail("缓存不存在")
            return
        }
        
        // 获取特定类型的缓存
        count, _ := c.CacheGetInt("counter")
        enabled, _ := c.CacheGetBool("enabled")
        score, _ := c.CacheGetFloat64("score")
        name, _ := c.CacheGetString("user:name")
        
        c.Success(gin.H{
            "user": value,
            "count": count,
            "enabled": enabled,
            "score": score,
            "name": name,
        })
    })
    
    r.GET("/cache/delete", func(c *gin.Context) {
        c.CacheDelete("user:123")
        c.Success("缓存已删除")
    })
    
    r.GET("/cache/clear", func(c *gin.Context) {
        c.CacheClear()
        c.Success("所有缓存已清除")
    })
    
    r.GET("/cache/keys", func(c *gin.Context) {
        keys := c.CacheKeys()
        c.Success(gin.H{"keys": keys, "count": len(keys)})
    })
    
    // 列表缓存操作
    r.GET("/cache/list", func(c *gin.Context) {
        // 设置列表缓存的过期时间
        c.CacheSetList("queue", 5*time.Minute)
        
        // 添加元素到列表头部
        c.CacheLPush("queue", "任务1", "任务2", "任务3")
        
        // 添加元素到列表尾部
        c.CacheRPush("queue", "任务4", "任务5")
        
        // 获取列表范围
        tasks := c.CacheLRange("queue", 0, -1)
        
        // 从列表头部弹出元素
        firstTask, _ := c.CacheLPop("queue")
        
        // 从列表尾部弹出元素
        lastTask, _ := c.CacheRPop("queue")
        
        // 获取指定位置的元素
        middleTask, _ := c.CacheLIndex("queue", 1)
        
        c.Success(gin.H{
            "all_tasks": tasks,
            "first_task": firstTask,
            "last_task": lastTask,
            "middle_task": middleTask,
        })
    })
    
    // 直接使用缓存实例进行高级操作
    r.GET("/cache/advanced", func(c *gin.Context) {
        cache := c.GetCache()
        
        // 检查TTL（过期时间）
        ttl, _ := cache.GetTTL("user:123")
        
        // 增加计数器
        cache.Increment("counter", 5)
        
        // 获取统计信息
        stats := cache.GetStats()
        
        // 交易操作
        tx := cache.BeginTransaction()
        tx.Set("tx_key", "事务值", 5*time.Minute)
        tx.LPush("tx_list", "事务列表值")
        tx.Commit()
        
        c.Success(gin.H{
            "ttl": ttl.Seconds(),
            "stats": stats,
        })
    })
    
    // 持久化操作
    r.GET("/cache/persist", func(c *gin.Context) {
        cache := c.GetCache()
        
        // 手动保存
        err := cache.Save()
        if err != nil {
            c.Fail("保存失败: " + err.Error())
            return
        }
        
        // 手动加载
        err = cache.Load()
        if err != nil {
            c.Fail("加载失败: " + err.Error())
            return
        }
        
        c.Success("持久化操作完成")
    })
    
    r.Run(":8080")
}
```

#### 缓存系统特性

- **内存缓存**：高性能的键值对缓存
- **列表缓存**：支持列表操作，可用于实现队列、栈等数据结构
- **类型安全**：提供类型特定的获取方法，避免类型转换错误
- **自动过期**：支持TTL（生存时间）和自动清理过期项
- **持久化**：可将缓存保存到文件并从文件恢复
- **自动持久化**：支持定时自动保存到文件
- **事务支持**：提供事务接口进行原子操作
- **统计信息**：提供缓存使用统计和性能监控
- **并发安全**：所有操作都是线程安全的
- **零依赖**：纯Go实现，无外部依赖

#### 缓存配置选项

```go
// 创建缓存时的配置选项
cache := gin.SetGlobalCache(
    5*time.Minute,  // 默认过期时间
    30*time.Second, // 清理间隔
)

// 启用持久化
cache := gin.SetGlobalCacheWithPersistence(
    5*time.Minute,   // 默认过期时间
    30*time.Second,  // 清理间隔
    "./cache.dat",   // 持久化文件路径
    5*time.Minute,   // 自动保存间隔
)
```

## 统一响应格式

框架提供了统一的响应方法：

```go
// 成功响应
c.Success(data)
c.SuccessWithMsg("操作成功", data)

// 失败响应
c.Fail("操作失败")
c.Error("服务器错误")
c.Forbidden("没有权限")
c.NotFound("资源不存在")
c.Unauthorized("未授权访问")
c.MethodNotAllowed()
c.ServiceUnavailable("服务暂时不可用")

// 分页响应
c.PageResponse(list, total, page, pageSize)
```

## 完整示例

请参考 [examples/main.go](examples/main.go) 获取更详细的使用示例。

## 配置选项

```go
// 设置运行模式
gin.SetMode(gin.DebugMode)   // 开发模式
gin.SetMode(gin.ReleaseMode) // 生产模式
gin.SetMode(gin.TestMode)    // 测试模式

// JSON 解码器配置
gin.EnableJsonDecoderUseNumber()
gin.EnableJsonDecoderDisallowUnknownFields()

// 禁用验证器
gin.DisableBindValidation()
```

## 安全最佳实践

使用框架提供的安全功能可以显著提高应用的安全性：

1. 始终使用HTTPS（通过`IsSsl()`检测）
2. 利用`SetSecureHeaders()`设置常用安全头
3. JWT令牌存储在安全的HttpOnly Cookie中
4. 正确设置内容安全策略（CSP）
5. 实施适当的缓存控制策略
6. 密钥和敏感配置应从环境变量加载，而不是硬编码

## 性能优化

1. 框架保持了原生Gin的高性能特性
2. 内部组件进行了私有化处理，减少了暴露的API表面积
3. 针对高频操作提供了优化的方法
4. SSE Hub实现了高效的客户端管理和消息派发
5. 请求数据转换使用高效的内部缓存

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。
