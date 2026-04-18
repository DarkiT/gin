# Auth Integration

本文件只覆盖接入层视角，不展开 auth 子系统全部内部细节。

当前代码层面，auth 能力不只包含登录态检查，还覆盖：

- token / session
- 角色 / 权限
- refresh token 相关能力
- OAuth2 primitives

## 认证接入的三层模型

### 1. Engine 级接入

启动时用：
- `gin.WithAuth(auth.AuthConfig{...})`

这是最常见、最推荐的集成方式。

效果：
- 初始化 `auth.Manager`
- 让请求内 `c.Auth()` 可用

## 2. Request 级使用

在 handler 内：
- `c.Auth().CheckLogin()`
- `c.Auth().LoginID()`
- `c.Auth().Login(loginID, device)`
- `c.Auth().Logout()`
- `c.Auth().CheckAnyPermission(...)`
- `c.Auth().CheckRole(...)`

这层最适合业务接口。

## 3. 独立 manager / global 模式

适合：
- 不依赖 `Engine`
- 需要复用 auth runtime
- 中间件或独立服务场景

常见入口：
- `auth.NewManager(...)`
- `auth.SetGlobalManager(...)`
- `auth.NewStpLogic(...)`

## 最小接入步骤

1. 构造 `auth.AuthConfig`
2. 在 `gin.New(...)` 中传入 `gin.WithAuth(cfg)`
3. 在登录接口中调用 `c.Auth().Login(...)`
4. 在受保护接口中先 `CheckLogin()` 再取 `LoginID()`

模板：
- `../assets/examples/auth_flow.go.tmpl`

## 常见配置关注点

- `Secret`
- `Expiry`
- `TokenStyle`
- `Storage`

如果自定义存储为空，通常会退回内存存储。

## 常见坑

### `c.Auth()` 返回未配置错误

优先检查：
- 是否启用了 `WithAuth`
- 当前 handler 是否由该 `Engine` 处理

### 登录成功但权限检查失败

优先检查：
- 权限/角色是如何装入 session 的
- 是否依赖外部 loader 但未注册

### 多端/多域行为不符合预期

优先检查：
- device 维度
- 并发登录策略
- 是否该改用 `StpLogic`

## 需要深入 auth 细节时

先确认当前 workspace 是 gin 仓库，再读：
- `./repo-doc-map.md`
