# Auth Integration

本文件只覆盖接入层视角，不展开 auth 子系统全部内部细节。

当前代码层面，auth 能力不只包含登录态检查，还覆盖：

- token / session
- 角色 / 权限
- refresh token 相关能力
- OAuth2 primitives
- 基于 `pkg/storage` 的 strict / relaxed / atomic KV 适配

## 认证接入的三层模型

### 1. Engine 级接入

启动时用：
- `gin.WithAuth(auth.AuthConfig{...})`

这是最常见、最推荐的集成方式。

效果：
- 在运行阶段初始化 `auth.Manager`
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

通用 KV 后端接入 auth/session 时不要直接传基础 `storage.Store`：

- 推荐 `auth.NewKVStorage(store)` 或 `auth/storage/kv.NewStrict(store)`
- 底层必须支持 `storage.TTLStore` 与 `storage.KeyScanner`
- 需要 OAuth2 操作锁走后端原子能力时，使用 `auth.NewAtomicKVStorage(...)`
- 只实现基础 `storage.Store` 的后端优先用于 `pkg/cache`

说明：

- `WithAuth(...)` 在构造阶段只保存配置并完成校验
- `auth.Manager` 会在 `Run()` 或首个请求进入前由 `Engine` 自动初始化
- `Login(...)` 的 token/account/session 多步写入失败会做 best-effort rollback，避免残留半登录状态

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

调用方项目先读：
- `./cache-storage-integration.md`

只有当前 workspace 是 `github.com/darkit/gin` 本仓，才继续读：
- `./repo-doc-map.md`
