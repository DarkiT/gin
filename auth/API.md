# auth API 参考

本文档描述了 `auth` 模块暴露的公共 API 表面以及应用程序交互的最重要的导出运行时类型。

## 包级构造函数和导出

### 类型别名

包重新导出几个核心类型：

- `type Manager = manager.Manager`
- `type Session = session.Session`
- `type TokenInfo = manager.TokenInfo`
- `type Storage = adapter.Storage`
- `type RequestContext = adapter.RequestContext`
- `type TokenStyle = config.TokenStyle`
- `type SameSiteMode = config.SameSiteMode`
- `type CookieOptions = adapter.CookieOptions`
- `type Event = listener.Event`
- `type EventData = listener.EventData`
- `type EventListener = listener.Listener`
- `type EventManager = listener.Manager`
- `type OAuth2Server = oauth2.OAuth2Server`
- `type NonceManager = security.NonceManager`
- `type RefreshTokenManager = security.RefreshTokenManager`
- `type RefreshTokenInfo = security.RefreshTokenInfo`

### 令牌样式常量

可用的导出令牌样式：

- `TokenStyleUUID`
- `TokenStyleSimple`
- `TokenStyleRandom32`
- `TokenStyleRandom64`
- `TokenStyleRandom128`
- `TokenStyleJWT`
- `TokenStyleHash`
- `TokenStyleTimestamp`
- `TokenStyleTik`

### SameSite 常量

- `SameSiteStrict`
- `SameSiteLax`
- `SameSiteNone`

### 事件常量

- `EventLogin`
- `EventLogout`
- `EventKickout`
- `EventDisable`
- `EventUntie`
- `EventRenew`
- `EventCreateSession`
- `EventDestroySession`

### 构造函数和工厂

#### `DefaultAuthConfig() AuthConfig`

返回默认的公开认证配置。

#### `NewManager(storage Storage, cfg *AuthConfig) *Manager`

从公开配置创建新的管理器。

行为说明：

- 调用 `cfg.Validate()` 并在配置无效时 panic
- 将公开配置转换为内部核心配置
- 如果配置了，注册权限/角色加载器

#### `NewMemoryStorage() Storage`

返回默认的内存存储后端。

#### `NewRedisStorage(redisURL string) (Storage, error)`

从如下 URL 创建 Redis 存储后端：

```text
redis://localhost:6379/0
redis://:password@localhost:6379/1
```

#### `NewGinRequestContext(c *gin.Context) adapter.RequestContext`

将 `*gin.Context` 适配到 `AuthContext` 使用的内部请求抽象。

#### `NewAuthContext(ctx adapter.RequestContext, mgr *manager.Manager) *AuthContext`

创建请求作用域的认证门面。

#### `NewMiddlewareBuilder(mgr *manager.Manager) *MiddlewareBuilder`

创建绑定到特定管理器的可重用中间件构建器。

#### `NewStpLogic(mgr *Manager) *StpLogic`

创建隔离的多实例认证逻辑包装器。

## 配置

## `AuthConfig`

用于引擎设置和独立管理器的公共配置模型。

```go
type AuthConfig struct {
    Secret          string
    Expiry          time.Duration
    TokenName       string
    TokenStyle      TokenStyle
    KeyPrefix       string

    ReadFromHeader  bool
    ReadFromCookie  bool
    ReadFromQuery   bool
    ReadFromBody    bool

    AllowConcurrent bool
    ShareToken      bool
    MaxLoginCount   int

    AutoRenew       bool
    RenewInterval   time.Duration
    MaxRefresh      time.Duration
    ActiveTimeout   time.Duration

    CookieConfig    *CookieConfig
    Storage         adapter.Storage

    PermissionLoader func(loginID string) ([]string, error)
    RoleLoader       func(loginID string) ([]string, error)
}
```

### 字段

#### 核心令牌字段

- `Secret`：使用 `TokenStyleJWT` 时必需
- `Expiry`：令牌生存期；必须大于零
- `TokenName`：用于头部/饼干/查询查找的逻辑令牌名称
- `TokenStyle`：令牌生成策略
- `KeyPrefix`：存储键前缀

#### 令牌读取源字段

- `ReadFromHeader`：启用从名为 `TokenName` 的请求头部查找令牌
- `ReadFromCookie`：启用从名为 `TokenName` 的饼干查找
- `ReadFromQuery`：查询源意图的公共配置标志
- `ReadFromBody`：启用从请求表单体查找

> 注意：`AuthContext.extractToken()` 总是使用 `TokenName` 检查查询参数，而头部/饼干/体由配置标志控制。

#### 登录并发字段

- `AllowConcurrent`：如果为假，新登录踢出同一设备上的先前登录
- `ShareToken`：如果为真，重用现有的有效账户/设备令牌
- `MaxLoginCount`：当启用并发且禁用共享时，一个账户的最大并发令牌数

#### 续期字段

- `AutoRenew`：启用验证时令牌续期
- `RenewInterval`：一个令牌续期写入之间的最小间距
- `MaxRefresh`：触发续期的剩余 TTL 阈值
- `ActiveTimeout`：公开暴露，为正时转换为核心配置

#### 饼干字段

- `CookieConfig`：启用饼干支持时使用的饼干设置

#### 存储和加载器

- `Storage`：自定义后端，可选
- `PermissionLoader`：惰性权限加载器
- `RoleLoader`：惰性角色加载器

### 方法

#### `func (c *AuthConfig) Validate() error`

验证配置。

检查：

- 令牌样式必须有效
- JWT 模式需要 `Secret`
- `Expiry` 必须为正数

## `CookieConfig`

```go
type CookieConfig struct {
    Path     string
    Domain   string
    Secure   bool
    HttpOnly bool
    SameSite SameSiteMode
}
```

当启用饼干支持时使用。

## 请求级 API

## `AuthContext`

`AuthContext` 是主 gin 包中 `c.Auth()` 返回的请求作用域 API。

### 登录和登出

#### `Login(loginID any, device ...string) (string, error)`

登录用户并返回访问令牌。

#### `Logout() error`

通过解析当前 `LoginID()` 并调用管理器登出来登出当前请求用户。

#### `LogoutByID(loginID any, device ...string) error`

登出指定的登录身份。

#### `Kickout(loginID any, device ...string) error`

强制用户下线。

### 令牌访问和登录状态

#### `Token() string`

返回当前请求令牌。
首次访问时缓存提取的令牌。

提取顺序：

1. 配置的头部 `TokenName`
2. `Authorization: Bearer <token>`
3. 启用时的饼干
4. 查询参数
5. 启用时的表单体

#### `IsLogin() bool`

返回当前请求令牌是否有效。

#### `CheckLogin() error`

当当前请求未认证时返回未登录错误。

#### `LoginID() (string, error)`

从当前令牌返回当前登录身份。

#### `MustLoginID() string`

如果当前请求未登录则 panic。

#### `TokenInfo() (*TokenInfo, error)`

返回当前令牌的解析令牌元数据。

### 权限检查

#### `HasPermission(permission string) bool`

检查一个权限。

#### `HasPermissions(permissions ...string) bool`

跨所有权限的 AND 检查。

#### `HasAnyPermission(permissions ...string) bool`

跨权限的 OR 检查。

#### `CheckPermission(permission string) error`

返回错误的单权限检查。

#### `CheckPermissions(permissions ...string) error`

返回错误的 AND 权限检查。

#### `CheckAnyPermission(permissions ...string) error`

返回错误的 OR 权限检查。

### 角色检查

#### `HasRole(role string) bool`

检查一个角色。

#### `HasRoles(roles ...string) bool`

AND 角色检查。

#### `HasAnyRole(roles ...string) bool`

OR 角色检查。

#### `CheckRole(role string) error`

返回错误的单角色检查。

#### `CheckRoles(roles ...string) error`

返回错误的 AND 角色检查。

#### `CheckAnyRole(roles ...string) error`

返回错误的 OR 角色检查。

### 禁用状态

#### `Disable(loginID any, duration time.Duration) error`

禁用特定账户。

#### `Untie(loginID any) error`

移除禁用状态。

#### `IsDisabled(loginID any) bool`

检查指定账户是否被禁用。

#### `CheckDisabled() error`

检查当前请求用户是否被禁用。

### 会话和授权数据

#### `Session() *session.Session`

返回当前用户会话，未登录时为 `nil`。

#### `GetSessionByID(loginID any) (*session.Session, error)`

通过登录 ID 获取会话。

#### `SetPermissions(loginID any, permissions []string) error`

为用户设置所有权限。

#### `SetRoles(loginID any, roles []string) error`

为用户设置所有角色。

#### `GetPermissions(loginID any) ([]string, error)`

返回用户权限。

#### `GetRoles(loginID any) ([]string, error)`

返回用户角色。

### 刷新令牌流程

#### `RefreshToken(refreshToken string) (string, error)`

用刷新令牌交换新的访问令牌。
只返回新的访问令牌字符串。

## 核心运行时 API

## `Manager`

`Manager` 是中央运行时对象。

## `TokenInfo`

```go
type TokenInfo struct {
    LoginID    string `json:"loginId"`
    Device     string `json:"device"`
    CreateTime int64  `json:"createTime"`
    ActiveTime int64  `json:"activeTime"`
    Tag        string `json:"tag,omitempty"`
}
```

### 生命周期

#### `CloseManager()`

停止并释放管理器管理的资源，如续期池状态。

### 登录、登出和令牌状态

#### `Login(loginID string, device ...string) (string, error)`

根据并发和共享策略创建或重用令牌。

#### `LoginByToken(loginID string, tokenValue string, device ...string) error`

使用现有令牌重新绑定或刷新登录状态。
也刷新活跃时间和 TTL。

#### `Logout(loginID string, device ...string) error`

按账户和设备登出。

#### `LogoutByToken(tokenValue string) error`

按令牌登出。

#### `Kickout(loginID string, device ...string) error`

将目标令牌标记为踢出并移除账户映射。

#### `KickoutByToken(tokenValue string) error`

按令牌踢出。

#### `IsLogin(tokenValue string) bool`

验证登录状态并可能触发异步续期。

#### `CheckLogin(tokenValue string) error`

返回错误的登录状态检查。

#### `CheckLoginWithState(tokenValue string) (bool, error)`

返回布尔状态加上详细错误。

#### `GetLoginID(tokenValue string) (string, error)`

从有效令牌返回登录 ID。

#### `GetLoginIDNotCheck(tokenValue string) (string, error)`

不进行完整令牌状态强制执行地返回登录 ID。

#### `GetTokenValue(loginID string, device ...string) (string, error)`

返回账户/设备映射的当前令牌。

#### `GetTokenInfo(tokenValue string) (*TokenInfo, error)`

返回解析的令牌元数据。

### 禁用管理

#### `Disable(loginID string, duration time.Duration) error`

在持续时间内禁用账户。
非正持续时间按更广泛的设计意图被视为无限期。

#### `Untie(loginID string) error`

移除禁用状态。

#### `IsDisable(loginID string) bool`

返回账户是否被禁用。

#### `GetDisableTime(loginID string) (int64, error)`

返回剩余禁用时间。

### 会话管理

#### `GetSession(loginID string) (*session.Session, error)`

加载或为登录 ID 创建会话包装器。

#### `GetSessionByToken(tokenValue string) (*session.Session, error)`

将令牌解析为登录 ID，然后返回会话。

#### `DeleteSession(loginID string) error`

销毁用户的会话状态。

#### `GetTokenValueListByLoginID(loginID string) ([]string, error)`

返回为登录 ID 在所有设备上找到的所有令牌。

#### `GetSessionCountByLoginID(loginID string) (int, error)`

返回为登录 ID 找到的活跃令牌数量。

### 权限管理

#### `SetPermissions(loginID string, permissions []string) error`

将会话存储中的权限持久化。

#### `SetLoaders(permissionLoader func(string) ([]string, error), roleLoader func(string) ([]string, error))`

注册惰性权限和角色加载器。

#### `GetPermissions(loginID string) ([]string, error)`

从会话返回权限，必要时惰性加载。

#### `HasPermission(loginID string, permission string) bool`

使用通配符支持检查一个权限。

#### `HasPermissionsAnd(loginID string, permissions []string) bool`

AND 权限检查。

#### `HasPermissionsOr(loginID string, permissions []string) bool`

OR 权限检查。

权限模式支持包括：

- `*`
- `user:*`
- 分段模式如 `user:*:view`

### 角色管理

#### `SetRoles(loginID string, roles []string) error`

将会话存储中的角色持久化。

#### `GetRoles(loginID string) ([]string, error)`

从会话返回角色，必要时惰性加载。

#### `HasRole(loginID string, role string) bool`

检查一个角色。

#### `HasRolesAnd(loginID string, roles []string) bool`

AND 角色检查。

#### `HasRolesOr(loginID string, roles []string) bool`

OR 角色检查。

### 令牌标签

#### `SetTokenTag(tokenValue, tag string) error`
#### `GetTokenTag(tokenValue string) (string, error)`

这些方法被导出但故意返回"不支持"。
对自定义元数据使用 `Session`。

### 事件 API

#### `RegisterFunc(event listener.Event, fn func(*listener.EventData))`

注册函数监听器。

#### `Register(event listener.Event, listener listener.Listener) string`

注册监听器实例。

#### `RegisterWithConfig(event listener.Event, listener listener.Listener, config listener.ListenerConfig) string`

用监听器配置注册监听器。

#### `Unregister(id string) bool`

取消注册监听器。

#### `TriggerEvent(data *listener.EventData)`

手动触发事件。

#### `WaitEvents()`

等待异步事件监听器完成。

#### `GetEventManager() *listener.Manager`

返回事件管理器。

### 内省

#### `GetConfig() *config.Config`

返回内部核心配置。

#### `GetStorage() adapter.Storage`

返回绑定的存储后端。

### 安全助手

#### `GenerateNonce() (string, error)`

生成一次性随机数。

#### `VerifyNonce(nonce string) bool`

验证并消费随机数。

#### `LoginWithRefreshToken(loginID, device string) (*security.RefreshTokenInfo, error)`

执行登录并返回刷新/访问令牌对元数据。

#### `RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error)`

使用刷新令牌获取新的访问令牌。

#### `RevokeRefreshToken(refreshToken string) error`

撤销刷新令牌。

#### `GetOAuth2Server() *oauth2.OAuth2Server`

返回 OAuth2 助手服务器。

## 全局包 API

包暴露全局助手，镜像管理器 API，需要通过 `SetGlobalManager(...)` 初始化。

### 全局管理器生命周期

- `SetGlobalManager(mgr *Manager)`
- `GetGlobalManager() *Manager`
- `CloseGlobalManager()`

### 全局 StpLogic 绑定

- `SetStpLogic(logic *StpLogic)`
- `GetStpLogic() *StpLogic`

### 全局认证操作

代表性导出函数包括：

- `Login(loginID any, device ...string) (string, error)`
- `LoginByToken(loginID any, tokenValue string, device ...string) error`
- `Logout(loginID any, device ...string) error`
- `LogoutByToken(tokenValue string) error`
- `IsLogin(tokenValue string) bool`
- `CheckLogin(tokenValue string) error`
- `GetLoginID(tokenValue string) (string, error)`
- `GetLoginIDNotCheck(tokenValue string) (string, error)`
- `GetTokenValue(loginID any, device ...string) (string, error)`
- `GetTokenInfo(tokenValue string) (*TokenInfo, error)`
- `Kickout(loginID any, device ...string) error`
- `Disable(loginID any, duration time.Duration) error`
- `Untie(loginID any) error`
- `IsDisable(loginID any) bool`
- `GetDisableTime(loginID any) (int64, error)`
- `GetSession(loginID any) (*session.Session, error)`
- `GetSessionByToken(tokenValue string) (*session.Session, error)`
- `DeleteSession(loginID any) error`
- `SetPermissions(loginID any, permissions []string) error`
- `GetPermissions(loginID any) ([]string, error)`
- `HasPermission(loginID any, permission string) bool`
- `HasPermissionsAnd(loginID any, permissions []string) bool`
- `HasPermissionsOr(loginID any, permissions []string) bool`
- `SetRoles(loginID any, roles []string) error`
- `GetRoles(loginID any) ([]string, error)`
- `HasRole(loginID any, role string) bool`
- `HasRolesAnd(loginID any, roles []string) bool`
- `HasRolesOr(loginID any, roles []string) bool`
- `SetTokenTag(tokenValue, tag string) error`
- `GetTokenTag(tokenValue string) (string, error)`
- `GetTokenValueList(loginID any) ([]string, error)`
- `GetSessionCount(loginID any) (int, error)`
- `GenerateNonce() (string, error)`
- `VerifyNonce(nonce string) bool`
- `LoginWithRefreshToken(loginID any, device ...string) (*security.RefreshTokenInfo, error)`
- `RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error)`
- `RevokeRefreshToken(refreshToken string) error`
- `GetOAuth2Server() *oauth2.OAuth2Server`

### 面向令牌的全局检查

包还暴露面向令牌的便利检查：

- `CheckDisable(tokenValue string) error`
- `CheckPermission(tokenValue string, permission string) error`
- `CheckPermissionAnd(tokenValue string, permissions []string) error`
- `CheckPermissionOr(tokenValue string, permissions []string) error`
- `GetPermissionList(tokenValue string) ([]string, error)`
- `CheckRole(tokenValue string, role string) error`
- `CheckRoleAnd(tokenValue string, roles []string) error`
- `CheckRoleOr(tokenValue string, roles []string) error`
- `GetRoleList(tokenValue string) ([]string, error)`
- `GetTokenSession(tokenValue string) (*session.Session, error)`

## 多实例 API

## `StpLogic`

`StpLogic` 提供绑定管理器的 API，镜像全局助手而不使用全局状态。

### 管理器绑定

- `GetManager() *Manager`
- `SetManager(mgr *Manager)`
- `CloseManager()`

### 镜像认证操作

`StpLogic` 为以下内容暴露管理者等价方法：

- 登录/登出/登录检查
- 令牌查找
- 禁用/解除绑定/禁用时间
- 会话访问
- 权限和角色管理
- 随机数生成/验证
- 刷新令牌流程
- OAuth2 访问
- 面向令牌的权限和角色检查

代表性方法：

- `Login(loginID any, device ...string) (string, error)`
- `Logout(loginID any, device ...string) error`
- `IsLogin(tokenValue string) bool`
- `GetLoginID(tokenValue string) (string, error)`
- `SetPermissions(loginID any, permissions []string) error`
- `SetRoles(loginID any, roles []string) error`
- `GenerateNonce() (string, error)`
- `LoginWithRefreshToken(loginID any, device ...string) (*security.RefreshTokenInfo, error)`
- `RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error)`
- `GetOAuth2Server() *oauth2.OAuth2Server`

## 中间件 API

## 顶级中间件函数

每个中间件接收管理器并返回 `gin.HandlerFunc`。

### `AuthRequired(mgr *manager.Manager) gin.HandlerFunc`

用 `401` JSON 拒绝未认证请求。

### `RoleRequired(mgr *manager.Manager, roles ...string) gin.HandlerFunc`

OR 角色检查。需要至少一个提供的角色。
未登录时返回 `401`，角色检查失败时返回 `403`。

### `RoleRequiredAll(mgr *manager.Manager, roles ...string) gin.HandlerFunc`

AND 角色检查。需要所有提供的角色。

### `PermRequired(mgr *manager.Manager, permissions ...string) gin.HandlerFunc`

OR 权限检查。

### `PermRequiredAll(mgr *manager.Manager, permissions ...string) gin.HandlerFunc`

AND 权限检查。

### `DisableCheck(mgr *manager.Manager) gin.HandlerFunc`

拒绝来自禁用账户的请求。
如果账户在登录后被禁用且旧令牌已被失效，请求将在到达禁用账户分支之前在登录检查处因 `401` 失败。

## `MiddlewareBuilder`

构建器方法返回相应的中间件，同时重用绑定的管理器：

- `AuthRequired() gin.HandlerFunc`
- `RoleRequired(roles ...string) gin.HandlerFunc`
- `RoleRequiredAll(roles ...string) gin.HandlerFunc`
- `PermRequired(permissions ...string) gin.HandlerFunc`
- `PermRequiredAll(permissions ...string) gin.HandlerFunc`
- `DisableCheck() gin.HandlerFunc`

## 存储接口

## `adapter.Storage`

```go
type Storage interface {
    Set(key string, value any, expiration time.Duration) error
    SetKeepTTL(key string, value any) error
    Get(key string) (any, error)
    Delete(keys ...string) error
    Exists(key string) bool
    Keys(pattern string) ([]string, error)
    Expire(key string, expiration time.Duration) error
    TTL(key string) (time.Duration, error)
    Clear() error
    Ping() error
}
```

### 方法语义

#### `Set`

存储带有可选过期的键。`0` 表示无过期。

#### `SetKeepTTL`

更新值同时保持先前的 TTL 不变。
认证运行时用于令牌状态和活跃时间更新。

#### `Get`

返回原始存储值。

#### `Delete`

删除一个或多个键。

#### `Exists`

检查键是否存在。

#### `Keys`

返回匹配模式的键，如 `user:*`。

#### `Expire`

设置或更新键的过期。

#### `TTL`

返回剩余生存时间。

#### `Clear`

清除存储的数据。谨慎使用。

#### `Ping`

检查后端是否可达。

## 存储实现

## 内存存储

通过 `NewMemoryStorage()` 创建。

来自实现的键特征：

- 带互斥锁保护的基于映射的存储
- 每项过期时间戳
- 清理协程
- 键缺失或过期时 `SetKeepTTL` 错误
- `TTL` 对无过期使用 `-1s`，对缺失/过期语义使用 `-2s`

## Redis 存储

通过 `NewRedisStorage(redisURL)` 创建。

Redis 包本身中的额外导出构造函数包括：

- `NewStorageFromConfig(cfg *Config) (adapter.Storage, error)`
- `NewStorageFromClient(client *redis.Client) adapter.Storage`
- `NewBuilder() *Builder`

键特征：

- 每操作上下文超时
- 基于 `SCAN` 的键列表
- `SET ... KeepTTL` 支持
- 通过具体 redis 存储类型上的 `GetClient()` 访问底层 Redis 客户端

## OAuth2 API

## `OAuth2Server`

由 `Manager.GetOAuth2Server()` 或全局/`StpLogic` 等价物返回。

### 核心方法

- `RegisterClient(client *Client) error`
- `UnregisterClient(clientID string)`
- `GetClient(clientID string) (*Client, error)`
- `GenerateAuthorizationCode(clientID, redirectURI, userID string, scopes []string) (*AuthorizationCode, error)`
- `ExchangeCodeForToken(code, clientID, clientSecret, redirectURI string) (*AccessToken, error)`
- `ValidateAccessToken(tokenString string) (*AccessToken, error)`
- `RefreshAccessToken(refreshToken, clientID, clientSecret string) (*AccessToken, error)`
- `RevokeToken(tokenString string) error`

客户端元数据、授权码、访问令牌和刷新令牌都存储在配置的存储后端中。授权码是一次性的，刷新令牌交换在成功时轮换刷新令牌。

### 支持类型

#### `Client`

```go
type Client struct {
    ClientID     string
    ClientSecret string
    RedirectURIs []string
    GrantTypes   []GrantType
    Scopes       []string
}
```

#### `AuthorizationCode`

包含授权码负载、重定向 URI、用户 ID、范围、创建时间、过期和一次性使用状态。

#### `AccessToken`

包含 OAuth2 访问令牌字符串、令牌类型、过期时间、刷新令牌、范围、用户 ID 和客户端 ID。

## 刷新令牌 API

## `RefreshTokenInfo`

```go
type RefreshTokenInfo struct {
    RefreshToken string `json:"refreshToken"`
    AccessToken  string `json:"accessToken"`
    LoginID      string `json:"loginID"`
    Device       string `json:"device"`
    CreateTime   int64  `json:"createTime"`
    ExpireTime   int64  `json:"expireTime"`
}
```

该类型实现二进制编组/解组以支持存储序列化。

## 随机数 API

随机数操作通常通过 `Manager`、全局助手或 `StpLogic` 访问，但底层能力由 `NonceManager` 实现。

行为：

- 生成的随机数是随机的 64 字符十六进制字符串
- 默认 TTL 是 5 分钟
- 验证是一次性的并消费随机数

## 请求上下文适配器 API

## `GinRequestContext`

从 `*gin.Context` 到认证请求抽象的具体适配器。

代表性方法：

- `GetHeader(key string) string`
- `GetHeaders() map[string][]string`
- `GetQuery(key string) string`
- `GetQueryAll() map[string][]string`
- `GetPostForm(key string) string`
- `GetCookie(key string) string`
- `GetBody() ([]byte, error)`
- `GetClientIP() string`
- `GetMethod() string`
- `GetPath() string`
- `GetURL() string`
- `GetUserAgent() string`
- `SetHeader(key, value string)`
- `SetCookie(...)`
- `SetCookieWithOptions(options *adapter.CookieOptions)`
- `Set(key string, value any)`
- `Get(key string) (any, bool)`
- `GetString(key string) string`
- `MustGet(key string) any`
- `Abort()`
- `IsAborted() bool`

## 与主 gin 包的集成

### `gin.WithAuth(cfg auth.AuthConfig)`

引擎选项，它：

- 验证配置
- 当 `cfg.Storage` 为 nil 时默认选择内存存储
- 创建并在引擎上存储认证管理器

### `func (c *Context) Auth() *auth.AuthContext`

主 gin 包中的请求助手。
当配置了认证时，返回由引擎认证管理器支持的 `AuthContext`，或在未启用认证时返回未配置的认证上下文。

## 实用说明

- `TokenStyleJWT` 需要 `Secret`。
- 内存存储是默认回退。
- 令牌标签已导出但不支持。
- `AuthContext.Token()` 总是尝试使用 `TokenName` 提取查询令牌。
- 通过 `c.Auth()` 的请求级使用是使用 `gin.WithAuth(...)` 时的预期主要集成路径。