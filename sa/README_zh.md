# Sa-Token-Go Gin 集成包 (sa)

**中文文档** | **[English](README.md)**

[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.21-blue)](https://img.shields.io)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

Sa-Token-Go 的 Gin 框架集成包，提供开箱即用的注解装饰器风格 API。基于 [github.com/darkit/gin/pkg/token](../pkg/token) 核心包实现。

## 📦 包说明

`sa` 包是 Sa-Token-Go 认证授权框架的 Gin 集成层，提供：

- ✅ **开箱即用** - 默认配置 + 内存存储，无需手动初始化
- 🎨 **注解装饰器** - 类似 Java Sa-Token 的装饰器风格（`@SaCheckLogin`、`@SaCheckRole`）
- 🔌 **传统中间件** - 兼容 Gin 标准中间件模式
- 🔄 **类型重导出** - 统一导出 core 包的所有类型和函数
- 🎯 **StpUtil 风格** - 提供全局辅助函数（`Login()`, `Logout()`, `HasPermission()`）

## 📂 包结构

```
sa/
├── annotation.go      # 注解系统：装饰器函数、标签解析
├── context.go        # Gin 上下文适配器：实现 RequestContext 接口
├── export.go         # 统一导出层：重导出 core 类型和全局函数
└── plugin.go         # Gin 插件：传统中间件、处理器示例
```

## 🏗️ 核心组件

### 1. 注解装饰器系统 (annotation.go)

提供类似 Java Sa-Token 的注解装饰器风格：

```go
// 注解结构体
type Annotation struct {
    CheckLogin      bool     // 检查登录
    CheckRole       []string // 检查角色
    CheckPermission []string // 检查权限
    CheckDisable    bool     // 检查封禁
    Ignore          bool     // 忽略认证
}

// 装饰器函数
func CheckLogin() gin.HandlerFunc
func CheckRole(roles ...string) gin.HandlerFunc
func CheckPermission(perms ...string) gin.HandlerFunc
func CheckDisable() gin.HandlerFunc
func Ignore() gin.HandlerFunc
```

### 2. Gin 上下文适配器 (context.go)

实现 `adapter.RequestContext` 接口，桥接 Gin 和 Sa-Token-Go 核心：

```go
type GinContext struct {
    c       *gin.Context
    aborted bool
}

// 实现所有 RequestContext 接口方法：
// GetHeader, GetQuery, GetCookie, SetHeader, SetCookie
// GetClientIP, GetMethod, GetPath, Set, Get
// GetHeaders, GetQueryAll, GetPostForm, GetBody, GetURL, GetUserAgent
// SetCookieWithOptions, GetString, MustGet, Abort, IsAborted
```

### 3. 统一导出层 (export.go)

重新导出 `pkg/token` 核心包的所有类型和函数，提供：

**默认配置与存储：**
```go
// 默认使用内存存储，自动初始化
var storageProvider StorageProvider = StorageProviderFunc(func() Storage {
    return storage.NewStorage()
})

// 切换自定义存储
func UseStorage(storage Storage, cfg *Config)
func UseStorageProvider(provider StorageProvider, cfg *Config)
```

**全局 StpUtil 风格函数：**
```go
// 认证相关
func Login(loginID interface{}, device ...string) (string, error)
func Logout(loginID interface{}, device ...string) error
func IsLogin(tokenValue string) bool
func GetLoginID(tokenValue string) (string, error)

// 权限验证
func HasPermission(loginID interface{}, permission string) bool
func HasRole(loginID interface{}, role string) bool

// 账号封禁
func Disable(loginID interface{}, duration time.Duration) error
func IsDisable(loginID interface{}) bool
func Untie(loginID interface{}) error

// Session 管理
func GetSession(loginID interface{}) (*Session, error)
func GetSessionByToken(tokenValue string) (*Session, error)

// 安全特性
func GenerateNonce() (string, error)
func VerifyNonce(nonce string) bool
func LoginWithRefreshToken(loginID interface{}, device ...string) (*RefreshTokenInfo, error)
func RefreshAccessToken(refreshToken string) (*RefreshTokenInfo, error)
```

### 4. Gin 插件 (plugin.go)

提供传统中间件模式和完整的处理器示例：

```go
type Plugin struct {
    manager             *Manager
    ValidateCredentials func(username, password string) error
}

// 中间件
func (p *Plugin) AuthMiddleware() gin.HandlerFunc
func (p *Plugin) PermissionRequired(permission string) gin.HandlerFunc
func (p *Plugin) RoleRequired(role string) gin.HandlerFunc

// 处理器示例
func (p *Plugin) LoginHandler(c *gin.Context)
func (p *Plugin) LogoutHandler(c *gin.Context)
func (p *Plugin) UserInfoHandler(c *gin.Context)
```

## ✨ 核心特性

基于 [github.com/darkit/gin/pkg/token](../pkg/token) 核心包，完整支持：

- 🔐 **登录认证** - 支持多设备登录、Token 管理
- 🛡️ **权限验证** - 细粒度权限控制、通配符支持（`*`, `user:*`, `user:*:view`）
- 👥 **角色管理** - 灵活的角色授权机制
- 🚫 **账号封禁** - 临时/永久封禁功能
- 👢 **踢人下线** - 强制用户下线、多端互斥登录
- 💾 **Session 会话** - 完整的 Session 管理
- ⏰ **活跃检测** - 自动检测 Token 活跃度
- 🔄 **自动续期** - Token 异步自动续期（性能提升 400%）
- 🎨 **注解支持** - `@SaCheckLogin`、`@SaCheckRole`、`@SaCheckPermission`
- 🎧 **事件监听** - 强大的事件系统、支持优先级、异步执行
- 📦 **模块化设计** - 按需导入、最小依赖
- 🔒 **Nonce 防重放** - 防止请求重放攻击、一次性令牌
- 🔄 **Refresh Token** - 刷新令牌机制、无感刷新
- 🔐 **OAuth2** - 完整的 OAuth2 授权码模式实现

## 🚀 快速开始

### 📥 安装

```bash
# 安装 sa 包（包含 Gin 集成 + core 核心功能）
go get github.com/darkit/gin/sa

# 如需 Redis 存储（生产环境推荐）
go get github.com/darkit/gin/pkg/token/storage/redis
```

### ⚡ 最简使用

**sa 包默认已初始化（内存存储），可直接使用！**

```go
package main

import (
    "github.com/darkit/gin/sa"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    // 登录接口
    r.POST("/login", func(c *gin.Context) {
        userID := c.PostForm("user_id")
        token, _ := sa.Login(userID) // 直接使用，无需初始化！
        c.JSON(200, gin.H{"token": token})
    })

    // 使用注解装饰器
    r.GET("/user", sa.CheckLogin(), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "需要登录才能访问"})
    })

    r.GET("/admin", sa.CheckPermission("admin:*"), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "需要管理员权限"})
    })

    r.Run(":8080")
}
```

### 🔧 自定义配置

如需自定义存储或配置：

```go
import (
    "github.com/darkit/gin/sa"
    "github.com/darkit/gin/pkg/token/storage/redis"
)

func init() {
    // 切换到 Redis 存储
    redisStorage := redis.NewStorage(&redis.Options{
        Addr:     "localhost:6379",
        Password: "",
        DB:       0,
    })

    // 自定义配置
    cfg := sa.DefaultConfig()
    cfg.TokenName = "Authorization"
    cfg.Timeout = 86400 // 24 小时
    cfg.TokenStyle = sa.TokenStyleRandom64

    // 应用配置
    sa.UseStorage(redisStorage, cfg)
}
```

## 🔧 核心 API

### 🔑 登录认证

```go
// 登录（支持 int, int64, uint, string）
token, _ := sa.Login(1000)
token, _ := sa.Login("user123")
token, _ := sa.Login(1000, "mobile")  // 指定设备

// 检查登录（自动异步续签）
isLogin := sa.IsLogin(token)

// 获取登录 ID
loginID, _ := sa.GetLoginID(token)

// 登出
sa.Logout(1000)
sa.LogoutByToken(token)

// 踢人下线
sa.Kickout(1000)
sa.Kickout(1000, "mobile")
```

### 🛡️ 权限验证

```go
// 设置权限
mgr := sa.GetManager()
mgr.SetPermissions("1000", []string{
    "user:read",
    "user:write",
    "admin:*",      // 通配符：匹配所有 admin 权限
})

// 检查权限
hasPermission := sa.HasPermission("1000", "user:read")
hasPermission := sa.HasPermission("1000", "admin:delete")  // 通配符匹配
```

### 👥 角色管理

```go
// 设置角色
mgr := sa.GetManager()
mgr.SetRoles("1000", []string{"admin", "manager"})

// 检查角色
hasRole := sa.HasRole("1000", "admin")
```

### 🎨 注解装饰器

这是 `sa` 包的核心特性！

```go
import (
    "github.com/darkit/gin/sa"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    // 忽略认证
    r.GET("/public", sa.Ignore(), publicHandler)

    // 需要登录
    r.GET("/user/info", sa.CheckLogin(), userInfoHandler)

    // 需要管理员权限
    r.GET("/admin", sa.CheckPermission("admin:*"), adminHandler)

    // 需要多个权限之一（OR 逻辑）
    r.GET("/user-or-admin",
        sa.CheckPermission("user:read", "admin:*"),
        userOrAdminHandler)

    // 需要管理员角色
    r.GET("/manager", sa.CheckRole("admin"), managerHandler)

    // 检查账号是否被封禁
    r.GET("/sensitive", sa.CheckDisable(), sensitiveHandler)

    r.Run(":8080")
}
```

### 🔌 传统中间件模式

如果你更喜欢传统中间件风格，可以使用 `Plugin`：

```go
import (
    "github.com/darkit/gin/sa"
    "github.com/gin-gonic/gin"
)

func main() {
    mgr := sa.GetManager()
    plugin := sa.NewPlugin(mgr)

    // 设置凭证验证函数（必须）
    plugin.ValidateCredentials = func(username, password string) error {
        // 实现你的凭证验证逻辑
        if username == "admin" && password == "123456" {
            return nil
        }
        return errors.New("invalid credentials")
    }

    r := gin.Default()

    // 使用插件提供的登录/登出处理器
    r.POST("/login", plugin.LoginHandler)
    r.POST("/logout", plugin.LogoutHandler)

    // 使用传统中间件
    r.GET("/user", plugin.AuthMiddleware(), userHandler)
    r.GET("/admin", plugin.PermissionRequired("admin:*"), adminHandler)
    r.GET("/manager", plugin.RoleRequired("manager"), managerHandler)

    r.Run(":8080")
}
```

### 💾 Session 管理

```go
// 获取 Session
sess, _ := sa.GetSession(1000)

// 设置数据
sess.Set("nickname", "张三")
sess.Set("age", 25)

// 读取数据
nickname := sess.GetString("nickname")
age := sess.GetInt("age")

// 删除 Session
mgr := sa.GetManager()
mgr.DeleteSession("1000")
```

### 🚫 账号封禁

```go
// 封禁 1 小时
sa.Disable(1000, 1*time.Hour)

// 永久封禁
sa.Disable(1000, 0)

// 解封
sa.Untie(1000)

// 检查是否被封禁
isDisabled := sa.IsDisable(1000)

// 获取剩余封禁时间
remainingTime, _ := sa.GetDisableTime(1000)
```

## 🎯 注解支持表

| 注解                 | 说明     | 示例                             |
| -------------------- | -------- | -------------------------------- |
| `@SaIgnore`          | 忽略认证 | `sa.Ignore()`                    |
| `@SaCheckLogin`      | 检查登录 | `sa.CheckLogin()`                |
| `@SaCheckRole`       | 检查角色 | `sa.CheckRole("admin")`          |
| `@SaCheckPermission` | 检查权限 | `sa.CheckPermission("admin:*")`  |
| `@SaCheckDisable`    | 检查封禁 | `sa.CheckDisable()`              |

## 🔗 与 core 包的关系

`sa` 包的架构层次：

```
┌─────────────────────────────────────────┐
│         用户应用代码 (Your App)          │
│  使用 sa.Login(), sa.CheckLogin() 等    │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│      sa 包 (github.com/darkit/gin/sa)   │
│  - annotation.go  # 注解装饰器         │
│  - context.go     # Gin 上下文适配器    │
│  - export.go      # 重导出 + 全局函数   │
│  - plugin.go      # 传统中间件         │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│  core 包 (github.com/darkit/gin/pkg/token) │
│  - manager/       # 核心认证管理器      │
│  - adapter/       # 适配器接口         │
│  - security/      # 安全特性           │
│  - oauth2/        # OAuth2 实现        │
│  - listener/      # 事件监听           │
│  - 等...                                │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│     存储层 (Storage Interface)          │
│  - memory         # 内存存储（默认）    │
│  - redis          # Redis 存储         │
└─────────────────────────────────────────┘
```

### 重要说明

1. **开箱即用**：`sa` 包在 `init()` 中自动初始化，默认使用内存存储
2. **类型重导出**：所有 core 包的类型和常量都通过 `export.go` 重新导出
3. **全局函数**：提供 StpUtil 风格的全局函数，内部调用 `helper` 包
4. **适配器模式**：`GinContext` 实现 `adapter.RequestContext`，桥接 Gin 和 core
5. **灵活切换**：通过 `UseStorage()` 可随时切换存储实现

## 📚 更多功能

`sa` 包完整支持 core 包的所有高级特性：

- 🎨 **Token 风格**：9 种 Token 生成风格（UUID、Simple、Random32/64/128、JWT、Hash、Timestamp、Tik）
- 🎧 **事件监听**：监听登录、登出、踢人、封禁等事件
- 🔒 **Nonce 防重放**：防止请求重放攻击
- 🔄 **Refresh Token**：刷新令牌机制、无感刷新
- 🔐 **OAuth2**：完整的 OAuth2 授权码模式实现

详细使用方式请参考 [core 包文档](../pkg/token/README_zh.md)。

## 📄 许可证

Apache License 2.0

## 🙏 致谢

参考 [sa-token](https://github.com/dromara/sa-token) 设计

---

**相关链接：**
- [core 包文档](../pkg/token/README_zh.md) - Sa-Token-Go 核心包
- [GitHub Issues](https://github.com/darkit/gin/issues) - 问题反馈
