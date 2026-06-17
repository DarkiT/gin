# auth 设计

## 概述

`auth` 模块是为 `darkit/gin` 构建的分层认证和授权子系统。
它围绕单一运行时核心 `Manager` 构建，并通过请求作用域、全局和多实例集成样式暴露该核心。

设计目标是保持认证行为集中化，同时允许不同的应用程序集成模式。

## 设计目标

- 为所有调用路径提供一个一致的认证运行时
- 通过 `c.Auth()` 保持请求级认证的可用性
- 支持嵌入式引擎和独立使用
- 支持可插拔的存储后端
- 在保持与导入核心模型兼容性的同时，保持项目本地 API 的简洁性
- 为令牌刷新、随机数和 OAuth2 提供内置安全原语

## 非目标

- 用户数据库管理
- 密码哈希和账户注册工作流
- 业务特定的角色或权限建模
- 跨服务 SSO 编排
- 自动 HTTP 端点生成

## 分层架构

运行时可以理解为五层：

```text
请求/应用层
├── gin.WithAuth(...)
├── c.Auth()
├── global.go 中的全局助手
└── StpLogic 实例

门面层
├── AuthContext
├── 全局 API
├── StpLogic
└── MiddlewareBuilder / 中间件函数

核心运行时层
└── Manager

安全与能力层
├── token.Generator
├── security.NonceManager
├── security.RefreshTokenManager
├── oauth2.OAuth2Server
├── security.ApiKeyManager
├── security.SignTemplate
├── security.TempTokenManager
├── security.SameTokenTemplate
└── listener.Manager

持久化层
└── adapter.Storage
    ├── memory.Storage
    └── redis.Storage
```

### 层职责

#### 1. 请求/应用层

这是应用程序代码进入认证系统的方式：

- `gin.WithAuth(...)` 在引擎设置期间保存并校验配置，管理器在运行阶段创建
- `c.Auth()` 创建请求作用域的 `AuthContext`
- 全局函数包装进程级管理器
- `StpLogic` 为每个认证域包装专用管理器

#### 2. 门面层

这一层使核心运行时便于使用而无需复制逻辑。

- `AuthContext` 将传入请求状态映射到管理器调用
- 中间件对登录/角色/权限/禁用检查执行标准 JSON 拒绝
- 全局助手将 `Manager` 语义作为包函数暴露
- `StpLogic` 复制该全局样式 API，但在特定实例上

#### 3. 核心运行时层

`Manager` 是真正的真相来源。
所有有状态的认证行为都在这里实现：

- 登录和登出
- 令牌验证
- 并发登录策略
- 禁用/解除绑定/踢出
- 会话访问
- 权限和角色解析
- 事件分发
- 刷新令牌和随机数布线
- OAuth2 服务器访问

#### 4. 安全与能力层

这一层包含 `Manager` 组合的可重用子系统：

- `token.Generator` 用于访问令牌生成
- `NonceManager` 用于防重放一次性值
- `RefreshTokenManager` 用于访问令牌轮换
- `OAuth2Server` 用于授权码和令牌流
- `ApiKeyManager` 用于开放接口密钥管理
- `SignTemplate` 用于带时间戳 / nonce 的签名校验
- `TempTokenManager` 用于一次性短期令牌
- `SameTokenTemplate` 用于服务间调用令牌
- `listener.Manager` 用于事件钩子

#### 5. 持久化层

所有状态都通过 `adapter.Storage` 接口存储。
这使得运行时独立于具体后端，同时保留 TTL 感知行为。

## 为什么以 `Manager` 为中心

一个主要的设计选择是每个公共集成模式最终都委托给 `Manager`。
这避免了分散的认证行为。

没有这个选择，不同 API 可能在以下方面出现分歧：

- 登录状态解释
- 令牌失效
- 会话更新
- 权限加载
- 并发登录处理

通过集中这些规则，模块保证：

- 请求认证的行为类似于独立认证
- 中间件检查的行为类似于手动管理器检查
- `StpLogic` 的行为类似于全局 API，除了限定在其自身管理器范围内

## 令牌生成策略

公共配置通过 `AuthConfig.TokenStyle` 暴露多种令牌样式。
导出的令牌样式包括：

- `TokenStyleUUID`
- `TokenStyleSimple`
- `TokenStyleRandom32`
- `TokenStyleRandom64`
- `TokenStyleRandom128`
- `TokenStyleJWT`
- `TokenStyleHash`
- `TokenStyleTimestamp`
- `TokenStyleTik`

## RememberMe 与 Token-Session

上游同步后，运行时把“登录态本身”和“Token-Session 容器”拆成两个层次：

- 普通 `Login(...)` 走标准 `Timeout`
- `LoginRememberMe(...)` 走 `RememberMeTimeout`
- `GetTokenSession(token, isCreate)` 为访问令牌绑定独立 Session 容器
- `TokenSessionCheckLogin` 控制创建 Token-Session 时是否强制校验登录态

这样可以把“长期登录”、“匿名会话”和“令牌附加上下文”拆开建模，而不把所有状态都挤进用户 Session。

## OAuth2 存储兼容策略

本项目在同步 upstream `0.2.2` 核心能力的同时，保留了本地已验证的 OAuth2 存储增强：

- `Client`、`AuthorizationCode`、`AccessToken` 都支持二进制编解码
- 客户端元数据与授权码 / token 一样走统一存储后端，不依赖进程内 map
- 授权码消费是一次性的
- refresh 成功后会轮换旧 refresh token，避免重复消费
- 若底层后端提供原子 `SetNX`，OAuth2 并发关键路径优先使用后端锁

这套设计保证 memory、redis 与通用 KV 适配器在 OAuth2 语义上尽量一致，避免“单机可用、换后端就失真”的漂移。

### 策略选择

生成器在 `Manager` 内部使用内部核心配置一次性创建。
这意味着令牌生成策略在管理器生命周期内是稳定的。

### 设计含义

- **UUID/随机样式**优先考虑简单性和熵
- **JWT** 需要 `AuthConfig.Secret`；否则验证失败
- **时间戳/短 ID 样式**优先考虑兼容性或紧凑性而不是不透明性
- **哈希样式**提供确定性的不透明输出，但仍依赖于生成器逻辑

### 令牌元数据模型

每次登录存储一个 `TokenInfo` 记录：

- `LoginID`
- `Device`
- `CreateTime`
- `ActiveTime`
- `Tag`

`Tag` 字段存在于存储模型中，但公共标签 API 有意返回"不支持"。
这是一个故意的设计边界：调用者应该使用 `Session` 进行自定义元数据，而不是重载令牌状态。

## 登录和令牌生命周期设计

### 登录流程

`Manager.Login(loginID, device...)` 执行以下步骤：

1. 拒绝被禁用的账户
2. 规范化设备名称
3. 解析账户键（`account:<loginID>:<device>`）
4. 当 `IsShare` 启用时，选择性重用现有令牌
5. 强制执行并发登录策略和最大登录限制
6. 需要时生成新令牌
7. 序列化和存储 `TokenInfo`
8. 存储账户到令牌的映射
9. 创建或更新会话
10. 发出登录事件

### 并发登录模型

配置支持三个关键控制：

- `AllowConcurrent`
- `ShareToken`
- `MaxLoginCount`

组合行为：

- 如果 `ShareToken=true`，重用相同账户+设备的现有有效令牌
- 如果 `AllowConcurrent=false`，新登录踢出同一设备上的先前登录
- 如果允许并发登录且不共享令牌，`MaxLoginCount` 限制账户的总活跃令牌数

这种设计提供了灵活性，而无需将登录路径拆分为单独的实现。

### 登出与踢出

模块有意区分**登出**和**踢出**。

#### 登出

`Logout` / `LogoutByToken` 直接移除令牌链：

- 令牌映射被删除
- 账户映射被删除
- 续期标记被删除
- 会话可能根据内部调用路径被移除

#### 踢出

`Kickout` 通过将令牌负载替换为 `KICK_OUT` 同时移除账户链接来保留强制失效的语义证据。

这让后续验证能够明确检测令牌状态，而不仅仅是将其视为缺失。

### 替换状态

代码还定义了 `BE_REPLACED` 作为替换语义的令牌状态。
即使并非所有公共流程当前都强调它，该状态也是令牌状态模型的一部分。

## 自动续期设计

模块通过 `AutoRenew`、`RenewInterval` 和 `MaxRefresh` 支持基于活动的续期。

### 验证时行为

`Manager.IsLogin(token)`：

- 验证令牌存在并解码 `TokenInfo`
- 检查存储的 TTL
- 如果续期条件匹配，安排异步续期

### 续期条件

只有在满足所有必需条件时才发生续期：

- 启用了自动续期
- 令牌超时为正数
- 当前 TTL 仍为正数
- 剩余 TTL 在配置时达到或低于 `MaxRefresh`
- 当配置 `RenewInterval` 时，令牌未被最近的续期标记阻塞

### 续期效果

`renewToken()`：

- 更新 `ActiveTime`
- 使用 `SetKeepTTL` 写入新的令牌信息，同时保持当前 TTL
- 为令牌键扩展 TTL
- 为账户键扩展 TTL
- 续期会话 TTL
- 存储续期标记以限制续期频率

这种设计减少了写放大，同时仍然保持活跃会话存活。

## 刷新令牌设计

刷新令牌支持与主流访问令牌管理器分开实现，但组合到 `Manager` 中。

### 为什么使用单独的管理器

刷新令牌具有不同于正常访问令牌的语义：

- 更长的 TTL
- 不同的存储键命名空间
- 单独的验证流程
- 访问令牌轮换行为

将其保存在 `RefreshTokenManager` 中避免了在 `Manager` 中膨胀登录状态逻辑。

### 生成的令牌对

`GenerateTokenPair` 返回：

- `RefreshToken`
- `AccessToken`
- `LoginID`
- `Device`
- `CreateTime`
- `ExpireTime`

### 重要设计决策：序列化存储

刷新令牌数据通过 `MarshalBinary()` / `UnmarshalBinary()` 显式序列化。
这很重要，因为存储后端不共享单一对象编码模型。
实现选择 JSON 字节作为通用分母。

### 重要设计决策：刷新期间保持访问令牌语义

刷新访问令牌时，实现在更新刷新令牌元数据之前将原始令牌存储值复制到新令牌键中。

为什么存在这个机制：

- 登录检查期望存储的令牌负载保持与 `TokenInfo` 兼容
- 刷新不应破坏 `IsLogin()` / `CheckLogin()`
- 存储后端可能在其他地方以不一致的令牌记录格式结束

这是设计中的一个关键兼容性保障措施。

## 会话管理设计

会话按键入身份而不是令牌键入。
这意味着会话代表用户级状态而不是单个令牌记录。

### 会话内容

在登录期间，管理器至少存储：

- `loginId`
- `device`
- `loginTime`

稍后，权限和角色数据也可能存储在相同会话下的：

- `permissions`
- `roles`

### 会话加载行为

`GetSession(loginID)` 尝试加载会话，如果未找到，则创建一个新的会话对象包装器。
这意味着调用者即使在没有先前持久会话负载存在的情况下也可以与会话 API 一起工作。

### 续期行为

会话 TTL 在以下期间与令牌和账户映射一起续期：

- `LoginByToken`
- 自动续期流程

这使会话过期与活跃认证状态保持一致。

## 权限系统设计

权限模型是会话支持的，带有可选的延迟加载。

### 权限数据来源

权限可能来自：

1. 先前存储的会话数据
2. 配置的 `PermissionLoader`

如果会话中没有权限数据，`GetPermissions()` 调用 `loadPermissions()`。
如果没有注册加载器，回退是空权限列表。

### 为什么使用会话支持缓存

这种设计避免了对每个权限检查的数据库或远程源命中。
一旦加载，权限就与会话一起存储，使用标准认证过期。

### 权限匹配模型

权限检查支持：

- 精确匹配
- 全局通配符：`*`
- 前缀通配符：`user:*`
- 分段通配符模式如 `user:*:view`

分段通配符实现要求相等的段计数，并将 `*` 视为单段通配符。

这种设计对于大多数路由/操作权限方案足够表达力，而无需实现更重的策略引擎。

## 角色系统设计

角色系统镜像权限设计，但仅使用精确相等匹配。

### 角色数据来源

角色从以下来源加载：

1. 会话缓存
2. `RoleLoader` 回退（如果配置）

### 检查语义

模块有意暴露两者：

- 单角色检查
- AND 检查（`HasRolesAnd`）
- OR 检查（`HasRolesOr`）

中间件通过专用函数镜像相同语义。

## 中间件设计

中间件层故意很薄。
它不引入第二个授权系统；它只是调用 `AuthContext` 并发出 JSON HTTP 错误。

可用的公共中间件构造函数：

- `AuthRequired`
- `RoleRequired`
- `RoleRequiredAll`
- `PermRequired`
- `PermRequiredAll`
- `DisableCheck`

### 错误模型

中间件返回：

- `401 Unauthorized` 用于未登录情况，包括先前有效但被 `Disable` 失效的令牌
- `403 Forbidden` 用于不足的权限/角色检查，以及当请求仍携带有效登录状态时的禁用账户检查

这使 HTTP 语义与管理器级状态检查保持一致。

## 存储设计

`Storage` 接口是 TTL 感知的，并且故意很小：

- `Set`
- `SetKeepTTL`
- `Get`
- `Delete`
- `Exists`
- `Keys`
- `Expire`
- `TTL`
- `Clear`
- `Ping`

### 为什么 `SetKeepTTL` 很重要

这个方法专门存在，因为某些认证操作需要在保留生命周期的同时更新负载。
例子：

- 更新 `ActiveTime`
- 标记踢出令牌状态而不重置清理计时

没有这个方法，认证状态更新会意外地扩展或重置 TTL 行为。

### 内存后端

内存后端为正确性和本地简单性而设计：

- 基于映射的存储
- 互斥锁保护
- 每项存储过期时间戳
- 定期清理协程
- 访问路径上的异步删除过期键

### Redis 后端

Redis 后端为分布式状态而设计：

- 将 TTL 和存在检查委托给 Redis
- 使用 `SCAN` 进行键模式枚举
- 支持 `SET ... KeepTTL`
- 使用每操作超时

### 通用 KV 适配层

`auth/storage/kv` 负责把 `pkg/storage.Store` 适配为 `adapter.Storage`。

设计边界：

- `NewStrict` 在构造期要求 `storage.TTLStore` 与 `storage.KeyScanner`
- `NewRelaxed` 只用于测试或明确不使用完整认证能力的场景
- `Get` 统一返回 `string`，保持 Manager 对 TokenInfo、Session、OAuth2 payload 的解析语义
- 空 key 在 auth 边界直接拒绝，避免 Fiber storage 的静默忽略语义进入认证主链
- 普通适配器不暴露非原子 `SetNX`；只有 `NewAtomic` 包装真正实现 `AtomicStore` 的后端

### 存储契约考虑

一些后端之间的差异仅部分标准化。
例如，缺失键错误是后端特定的，但认证逻辑通常将查找时的"错误或零"视为不存在。
这使管理器逻辑可移植，即使确切的错误类型不同。

## 安全考虑

### 1. 禁用账户保护

每个登录路径首先检查账户禁用状态。
这防止了账户被禁用时的重新登录。

### 2. 重放抵抗

内置随机数生成和一次性验证。
这对于必须拒绝重复请求的签名或敏感操作特别有用。

### 3. 显式强制无效令牌状态

使用 `KICK_OUT` / `BE_REPLACED` 状态比静默删除每个失效令牌更安全，因为调用者可以区分验证失败的原因。

### 4. 续期节流

`RenewInterval` 防止过度的写放大，并减少高频续期风暴的风险。

### 5. 刷新令牌轮换边界

刷新令牌单独存储并独立验证。
它们的访问令牌更新路径保持登录元数据兼容性。

### 6. JWT 密钥强制执行

`AuthConfig.Validate()` 拒绝没有密钥的 JWT 模式。
这防止了意外的不安全 JWT 颁发。

### 7. Redis `Clear()` 警告

Redis 存储实现可以清除广泛可达的键；它旨在用于测试或受控管理用途，而不是常规生产流程。

## 事件模型

`Manager` 通过 `listener.Manager` 包含事件子系统。
事件包括：

- 登录
- 登出
- 踢出
- 禁用
- 解除绑定
- 续期
- 会话创建/销毁

### 为什么事件是设计的一部分

它们允许横切关注点而不将它们耦合到认证逻辑：

- 审计
- 指标
- 异步通知
- 安全监控

管理器暴露注册和等待 API，以便调用者可以在监听器管理器级别选择同步或异步监听器模式。

## 公共 API 形状原理

模块出于目的暴露几个重叠的入口点：

- `AuthContext` 用于处理器可用性
- `Manager` 用于显式运行时所有权
- 全局助手用于轻量级集成
- `StpLogic` 用于隔离的多域名认证

这不是实现的重复；它是围绕一个共享运行时模型的**入口点**的重复。
这种权衡有利于采用，同时保持一致性。

## 已知边界和限制

- `AuthContext` 依赖于请求上下文，不应在请求作用域之外持有
- 令牌标签 API 故意不支持，即使 `TokenInfo` 包含 `Tag` 字段
- 默认内存存储不是重启安全和多实例安全的
- 权限和角色加载器是基于回调的；模块不定义如何获取业务数据
- 管理器仍然是大型中心文件，这对行为一致性是可维护的，但带有重构债务

## 演进指南

未来的更改应该保留这些不变性：

- `Manager` 仍然是单一行为真相来源
- 存储保持 TTL 感知
- 刷新令牌流必须与正常令牌验证保持兼容
- 中间件必须保持薄包装器，而不是替代策略引擎
- 请求/全局/实例集成必须保持等效语义
