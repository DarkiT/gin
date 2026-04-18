# auth - 认证子系统

`auth` 模块为 `darkit/gin` 提供认证、授权、会话管理和令牌安全功能。它通过项目友好的 API 包装底层认证核心，支持多个层级的工作模式。

## 目录

- [模块概述](#模块概述)
- [核心概念](#核心概念)
- [集成模式](#集成模式)
- [配置说明](#配置说明)
- [存储选项](#存储选项)
- [安全特性](#安全特性)
- [API 参考](#api-参考)
- [快速开始](#快速开始)

## 模块概述

### 设计目标

- 为所有调用路径提供一个一致的认证运行时
- 通过 `c.Auth()` 保持请求级认证的可用性
- 支持嵌入式引擎和独立使用
- 支持可插拔的存储后端
- 为令牌刷新、随机数和 OAuth2 提供内置安全原语

### 非目标

- 用户数据库管理
- 密码哈希和账户注册工作流
- 业务特定的角色或权限建模
- 跨服务 SSO 编排
- 自动 HTTP 端点生成

### 核心能力

- 颁发和验证访问令牌
- 将令牌映射到登录身份和设备
- 维护用户会话
- 管理权限和角色
- 支持强制登出和账户禁用
- 提供刷新令牌、随机数和 OAuth2 辅助功能
- 支持可插拔的存储后端

## 核心概念

### AuthContext

`AuthContext` 是请求作用域的门面。它从传入请求中提取令牌，委托给 `Manager`，并为以下操作提供紧凑的 API：

```go
// 登录/登出
token, err := c.Auth().Login(loginID, device)
err := c.Auth().Logout()

// 登录状态检查
err := c.Auth().CheckLogin()
isLogin, _ := c.Auth().IsLogin()

// 获取登录ID
loginID, err := c.Auth().LoginID()

// 权限检查
err := c.Auth().CheckPermission(permission)
err := c.Auth().CheckAnyPermission(permissions...)
err := c.Auth().CheckAllPermissions(permissions...)

// 角色检查
err := c.Auth().CheckRole(role)
err := c.Auth().CheckAnyRole(roles...)
err := c.Auth().CheckAllRoles(roles...)

// 禁用状态检查
err := c.Auth().CheckDisable()

// 会话访问
session, err := c.Auth().GetSession()

// 刷新令牌交换
pair, err := c.Auth().Refresh(newRefreshToken)
```

### Manager

`Manager` 是模块的核心运行时对象。所有认证状态最终都通过它流动，无论调用来自 `AuthContext`、全局助手、中间件还是 `StpLogic`。

```go
// 创建管理器
mgr := auth.NewManager(storage, &cfg)

// 登录
token, err := mgr.Login(loginID, device, permissoins...)
pair, err := mgr.LoginWithRefreshToken(loginID, device)

// 登出
err := mgr.Logout(token)
err := mgr.LogoutByLoginID(loginID)

// 状态检查
isLogin := mgr.IsLogin(token)
loginID, _ := mgr.GetLoginID(token)

// 权限/角色
mgr.SetPermissions(loginID, permissions)
mgr.SetRoles(loginID, roles)
hasPerm := mgr.HasPermission(loginID, permission)
hasRole := mgr.HasRole(loginID, role)

// 会话
session, _ := mgr.GetSession(loginID)

// 禁用/启用
err := mgr.Disable(loginID)
err := mgr.Enable(loginID)

// 踢出
err := mgr.Kickout(loginID)
err := mgr.KickoutByToken(token)

// 刷新令牌
newToken, _ := mgr.RefreshAccessToken(refreshToken)
```

### Session

`Session` 是按登录身份存储在配置后端的状态：

```go
type Session struct {
    LoginID     string
    Device      string
    LoginTime   time.Time
    Permissions []string
    Roles       []string
}
```

### TokenInfo

```go
type TokenInfo struct {
    LoginID   string
    Device   string
    CreateTime time.Time
    ActiveTime time.Time
    Tag       string
}
```

## 集成模式

### 1. 引擎层级集成（推荐）

当认证是应用程序运行时的一部分时，使用 `gin.WithAuth(...)`：

```go
package main

import (
	"time"

	ginx "github.com/darkit/gin"
	"github.com/darkit/gin/auth"
)

func main() {
	e := ginx.New(
		ginx.WithAuth(auth.AuthConfig{
			Secret:     "replace-me",
			Expiry:     24 * time.Hour,
			TokenStyle: auth.TokenStyleJWT,
		}),
	)

	e.POST("/login", func(c *ginx.Context) {
		token, err := c.Auth().Login("user-1001", "web")
		if err != nil {
			c.InternalError(err.Error())
			return
		}
		c.Success(ginx.H{"token": token})
	})

	_ = e.Run(":8080")
}
```

### 2. 请求层级集成

在处理器内部，`c.Auth()` 返回一个由引擎管理器支持的 `*auth.AuthContext`：

```go
func handleProfile(c *gin.Context) {
	// 检查登录状态
	if err := c.Auth().CheckLogin(); err != nil {
		c.Unauthorized(err.Error())
		return
	}

	// 获取登录ID
	loginID, err := c.Auth().LoginID()
	if err != nil {
		c.Unauthorized(err.Error())
		return
	}

	// 检查权限
	if err := c.Auth().CheckAnyPermission("user:read", "profile:read"); err != nil {
		c.Forbidden(err.Error())
		return
	}

	c.Success(gin.H{"login_id": loginID})
}
```

### 3. 全局 API

当您想要无需持有管理器引用的进程级认证访问时，使用全局 API：

```go
package main

import (
	"fmt"

	"github.com/darkit/gin/auth"
)

func main() {
	// 初始化全局管理器
	cfg := auth.DefaultAuthConfig()
	mgr := auth.NewManager(auth.NewMemoryStorage(), &cfg)
	auth.SetGlobalManager(mgr)
	defer auth.CloseGlobalManager()

	// 登录
	token, err := auth.Login("user-1001", "web")
	if err != nil {
		panic(err)
	}

	// 检查登录状态
	isLogin := auth.IsLogin(token)
	fmt.Println("Is logged in:", isLogin)

	// 获取登录ID
	loginID, _ := auth.GetLoginID(token)
	fmt.Println("Login ID:", loginID)

	// 登出
	auth.Logout(token)
}
```

### 4. 本地管理器集成

如果您想在不使用全局状态的情况下使用中间件或认证逻辑：

```go
cfg := auth.DefaultAuthConfig()
storage := auth.NewMemoryStorage()
mgr := auth.NewManager(storage, &cfg)

builder := auth.NewMiddlewareBuilder(mgr)

router.Use(builder.AuthRequired())
router.GET("/admin", builder.RoleRequired("admin"), adminHandler)
```

### 5. StpLogic 多域名集成

当一个进程承载多个不能共享管理器状态的认证域名时：

```go
adminMgr := auth.NewManager(auth.NewMemoryStorage(), &cfg)
userMgr := auth.NewManager(auth.NewMemoryStorage(), &cfg)

adminLogic := auth.NewStpLogic(adminMgr)
userLogic := auth.NewStpLogic(userMgr)

adminToken, _ := adminLogic.Login("admin-1", "web")
userToken, _ := userLogic.Login("user-1", "app")
```

## 配置说明

### AuthConfig

```go
type AuthConfig struct {
	// 密钥，用于 JWT 签名等
	Secret string

	// 令牌过期时间
	Expiry time.Duration

	// 令牌样式
	TokenStyle TokenStyle

	// 令牌名称，默认 "Authorization"
	TokenName string

	// 是否从 Cookie 读取令牌
	AllowCookie bool

	// 是否从查询参数读取令牌
	AllowQuery bool

	// 是否从表单读取令牌
	AllowForm bool

	// 是否允许并发登录
	AllowConcurrent bool

	// 是否共享令牌（同一设备复用）
	ShareToken bool

	// 最大登录数
	MaxLoginCount int

	// 是否自动续期
	AutoRenew bool

	// 续期间隔
	RenewInterval time.Duration

	// 最大续期 TTL
	MaxRefresh time.Duration

	// 存储后端
	Storage Storage

	// 权限加载器
	PermissionLoader PermissionLoader

	// 角色加载器
	RoleLoader RoleLoader
}
```

### 令牌样式

```go
const (
	TokenStyleUUID      TokenStyle = "uuid"
	TokenStyleSimple    TokenStyle = "simple"
	TokenStyleRandom32  TokenStyle = "random32"
	TokenStyleRandom64  TokenStyle = "random64"
	TokenStyleRandom128 TokenStyle = "random128"
	TokenStyleJWT       TokenStyle = "jwt"
	TokenStyleHash      TokenStyle = "hash"
	TokenStyleTimestamp TokenStyle = "timestamp"
	TokenStyleTik       TokenStyle = "tik"
)
```

### 创建默认配置

```go
cfg := auth.DefaultAuthConfig()
```

## 存储选项

### 内存存储

```go
storage := auth.NewMemoryStorage()
```

适用于：

- 本地开发
- 测试
- 单进程服务

特性：

- 进程内映射存储
- TTL 支持
- 定期清理协程
- 进程重启时状态丢失

### Redis 存储

```go
storage, err := auth.NewRedisStorage("redis://localhost:6379/0")
if err != nil {
	panic(err)
}

cfg := auth.DefaultAuthConfig()
cfg.Storage = storage
mgr := auth.NewManager(storage, &cfg)
```

适用于：

- 生产部署
- 水平扩展服务
- 跨实例共享认证状态

特性：

- 持久外部状态
- TTL 委托给 Redis
- 基于扫描的键匹配

## 安全特性

### 刷新令牌支持

```go
// 登录时获取令牌对
pair, err := mgr.LoginWithRefreshToken("user-1001", "web")
if err != nil {
	panic(err)
}

// 使用刷新令牌获取新的访问令牌
newToken, err := mgr.RefreshAccessToken(pair.RefreshToken)
if err != nil {
	panic(err)
}
```

### 随机数支持

```go
// 生成随机数
nonce, _ := mgr.GenerateNonce(token)

// 验证随机数（一次性使用）
ok, _ := mgr.VerifyNonce(token, nonce)
```

### OAuth2 支持

```go
server := mgr.GetOAuth2Server()

// 客户端注册
clientID, _ := server.RegisterClient("my-app", "secret")

// 授权码
code, _ := server.GenerateCode(token, clientID, "redirect-uri")

// 令牌交换
tokenPair, _ := server.Exchange(code, clientID, "secret")

// 刷新
newPair, _ := server.Refresh(pair.RefreshToken)

// 撤销
server.Revoke(token)
```

### 权限系统

```go
// 设置权限
mgr.SetPermissions("user-1001", []string{"user:read", "user:write", "article:*"})

// 权限检查
hasRead := mgr.HasPermission("user-1001", "user:read")
hasWrite := mgr.HasPermission("user-1001", "user:write")
hasAll := mgr.HasPermission("user-1001", "user:*")  // 支持通配符
```

权限匹配支持：

- 精确匹配：`user:read`
- 全局通配符：`*`
- 前缀通配符：`user:*`
- 分段通配符：`article:*:edit`

### 角色系统

```go
// 设置角色
mgr.SetRoles("user-1001", []string{"admin", "editor"})

// 角色检查
isAdmin := mgr.HasRole("user-1001", "admin")
hasRole := mgr.HasRolesOr("user-1001", "admin", "editor")
allRoles := mgr.HasRolesAnd("user-1001", "admin", "editor")
```

## API 参考

### AuthContext 方法

| 方法 | 说明 |
|------|------|
| `Login(loginID, device string) (string, error)` | 用户登录 |
| `Logout() error` | 用户登出 |
| `CheckLogin() error` | 检查登录状态 |
| `IsLogin() (bool, error)` | 是否已登录 |
| `LoginID() (string, error)` | 获取登录ID |
| `CheckPermission(permission string) error` | 检查单个权限 |
| `CheckAnyPermission(permissions ...string) error` | 检查任意权限（OR） |
| `CheckAllPermissions(permissions ...string) error` | 检查所有权限（AND） |
| `CheckRole(role string) error` | 检查单个角色 |
| `CheckAnyRole(roles ...string) error` | 检查任意角色（OR） |
| `CheckAllRoles(roles ...string) error` | 检查所有角色（AND） |
| `CheckDisable() error` | 检查禁用状态 |
| `GetSession() (*Session, error)` | 获取会话信息 |
| `Refresh(refreshToken string) (*TokenPair, error)` | 刷新令牌 |

### Manager 方法

| 方法 | 说明 |
|------|------|
| `NewManager(storage Storage, cfg *AuthConfig) *Manager` | 创建管理器 |
| `Login(loginID, device string, permissions ...string) (string, error)` | 登录 |
| `LoginWithRefreshToken(loginID, device string) (*TokenPair, error)` | 带刷新的登录 |
| `Logout(token string) error` | 登出 |
| `LogoutByLoginID(loginID string) error` | 按登录ID登出 |
| `IsLogin(token string) bool` | 检查登录状态 |
| `GetLoginID(token string) (string, error)` | 获取登录ID |
| `GetTokenInfo(token string) (*TokenInfo, error)` | 获取令牌信息 |
| `Disable(loginID string) error` | 禁用账户 |
| `Enable(loginID string) error` | 启用账户 |
| `Kickout(loginID string) error` | 踢出用户 |
| `KickoutByToken(token string) error` | 按令牌踢出 |
| `SetPermissions(loginID string, permissions []string)` | 设置权限 |
| `SetRoles(loginID string, roles []string)` | 设置角色 |
| `HasPermission(loginID, permission string) bool` | 检查权限 |
| `HasRole(loginID, role string) bool` | 检查角色 |
| `GetSession(loginID string) (*Session, error)` | 获取会话 |
| `RefreshAccessToken(refreshToken string) (string, error)` | 刷新令牌 |
| `GenerateNonce(token string) (string, error)` | 生成随机数 |
| `VerifyNonce(token, nonce string) (bool, error)` | 验证随机数 |

### MiddlewareBuilder 方法

| 方法 | 说明 |
|------|------|
| `AuthRequired() gin.HandlerFunc` | 需要登录 |
| `RoleRequired(roles ...string) gin.HandlerFunc` | 需要角色 |
| `PermRequired(permission string) gin.HandlerFunc` | 需要权限 |
| `DisableCheck() gin.HandlerFunc` | 检查禁用 |

## 快速开始

### 最小化登录和访问检查

```go
package main

import (
	"fmt"

	"github.com/darkit/gin/auth"
)

func main() {
	cfg := auth.DefaultAuthConfig()
	mgr := auth.NewManager(auth.NewMemoryStorage(), &cfg)

	token, err := mgr.Login("user-1001", "web")
	if err != nil {
		panic(err)
	}

	if !mgr.IsLogin(token) {
		panic("expected token to be valid")
	}

	loginID, err := mgr.GetLoginID(token)
	if err != nil {
		panic(err)
	}

	fmt.Println("Login ID:", loginID)
	fmt.Println("Token:", token)
}
```

### 完整中间件保护示例

```go
package main

import (
	"log"
	"time"

	ginx "github.com/darkit/gin"
	"github.com/darkit/gin/auth"
	"github.com/darkit/gin/middleware"
)

func main() {
	cfg := auth.DefaultAuthConfig()
	mgr := auth.NewManager(auth.NewMemoryStorage(), &cfg)

	builder := auth.NewMiddlewareBuilder(mgr)

	e := ginx.New()

	r := e.Router()
	r.Use(middleware.Recovery())
	r.Use(middleware.Logger())
	r.Use(middleware.RequestID())

	// 公开接口
	r.POST("/login", func(c *ginx.Context) {
		token, err := c.Auth().Login("admin", "web")
		if err != nil {
			c.Unauthorized(err.Error())
			return
		}
		c.Success(ginx.H{"token": token})
	})

	// 需要登录
	authGroup := r.Group("")
	authGroup.Use(builder.AuthRequired())

	authGroup.GET("/profile", func(c *ginx.Context) {
		loginID, _ := c.Auth().LoginID()
		c.Success(ginx.H{"login_id": loginID})
	})

	// 需要特定角色
	adminGroup := r.Group("/admin")
	adminGroup.Use(builder.RoleRequired("admin"))

	adminGroup.GET("/users", func(c *ginx.Context) {
		c.Success(ginx.H{"users": []string{"alice", "bob"}})
	})

	_ = e.Run(":8080")
}
```

### 权限和角色

```go
// 设置权限
mgr.SetPermissions("user-1001", []string{"user:read", "user:*"})
mgr.SetRoles("user-1001", []string{"admin"})

canRead := mgr.HasPermission("user-1001", "user:read")
canWrite := mgr.HasPermission("user-1001", "user:write")
isAdmin := mgr.HasRole("user-1001", "admin")
```

### 会话访问

```go
session, err := mgr.GetSession("user-1001")
if err != nil {
	panic(err)
}

_ = session.LoginID
_ = session.Device
_ = session.LoginTime
_ = session.Permissions
_ = session.Roles
```

### 刷新令牌流程

```go
pair, err := mgr.LoginWithRefreshToken("user-1001", "web")
if err != nil {
	panic(err)
}

next, err := mgr.RefreshAccessToken(pair.RefreshToken)
if err != nil {
	panic(err)
}

_ = next // 新的访问令牌
```

## 相关文档

- [DESIGN.md](DESIGN.md) - 详细设计文档
- [API.md](API.md) - API 参考文档
