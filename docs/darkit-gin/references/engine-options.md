# Engine Options

本文件聚焦 `Engine` 的创建方式、`Option` 矩阵与常见初始化陷阱。

## 目录

- 创建入口
- 常用 Option 矩阵
- 防漂移提示
- 最常见初始化模式
- 常见坑
- 下一跳

## 创建入口

### `gin.New(opts...)`

适合：
- 需要显式控制初始化项
- 不想自动加载默认 middleware

### `gin.Default(opts...)`

适合：
- 大多数 Web 服务
- 需要开箱即用的请求链路能力

默认中间件：
- `middleware.RequestID()`
- `middleware.Recovery()`
- `middleware.Logger()`

## 常用 Option 矩阵

| Option | 用途 | 常见场景 | 注意点 |
|---|---|---|---|
| `WithAddr(addr)` | 设置监听地址 | 本地启动 / 容器服务 | 可被 `Run(":8081")` 覆盖 |
| `WithReadTimeout(d)` | 读超时 | API 服务 | 与慢上传场景配套评估 |
| `WithWriteTimeout(d)` | 写超时 | API / 导出接口 | 大文件导出不要设太短 |
| `WithTrustedProxies(proxies)` | 受信代理 | 反向代理/Nginx/LB | 非法配置会 fail-fast |
| `WithGracefulShutdown(timeout)` | 优雅停机超时 | 生产停机 | 与 deployment termination 配合 |
| `WithLogger(l)` | 自定义 logger | 接入业务日志体系 | 需实现 logger 接口 |
| `WithCache(c)` | 自定义 cache | 接入 Redis/自定义缓存 | 影响 `c.Cache()` |
| `WithUploadDir(dir)` | 上传目录 | 文件服务 | 与磁盘权限配套 |
| `WithMaxFileSize(size)` | 单文件上限 | 上传保护 | 与前端限制保持一致 |
| `WithMaxMultipartMemory(size)` | multipart 内存阈值 | 文件上传 | 同时会写入 Gin 设置 |
| `WithAllowedExts(exts...)` | 扩展名白名单 | 上传保护 | 仅扩展名不足以防全部绕过 |
| `WithUploadConfig(cfg)` | 完整上传配置 | 复杂上传策略 | `nil` 会被忽略 |
| `WithMail(cfg)` | 初始化 mail provider | 发信能力 | 配置错误通常 fail-fast |
| `WithSMS(cfg)` | 初始化短信 provider | 验证码 / 通知 | 某些 provider 需 side-effect import |
| `EnableSwagger(cfg)` | 启用 Swagger/OpenAPI | 文档生成 | 依赖项目内 swagger 实现 |
| `WithAuth(cfg)` | 初始化 auth manager | 登录/权限服务 | 配置校验失败会 panic |
| `Development()` | 开发预设 | 本地调试 | 偏宽松 |
| `Production()` | 生产预设 | 线上服务 | 带更保守超时 |

## 防漂移提示

- `WithCache(c)` 既可作为初始化 Option，也可在运行时通过 `e.WithCache(c)` 替换
- `EnableSwagger(cfg)` 只负责启用框架侧 Swagger/OpenAPI 集成；注解细节与输出结构要再看 `examples/swagger-demo/main.go` 与 `pkg/swagger/`
- 若示例文档、README 与真实行为冲突，以 `options.go`、`engine.go` 与测试为准

## 最常见初始化模式

### 基础 API 服务

```go
e := gin.Default(
    gin.WithAddr(":8080"),
    gin.WithReadTimeout(30*time.Second),
    gin.WithWriteTimeout(30*time.Second),
)
```

### 带认证服务

```go
e := gin.New(
    gin.WithAuth(auth.AuthConfig{
        Secret:     "replace-me",
        Expiry:     24 * time.Hour,
        TokenStyle: auth.TokenStyleJWT,
    }),
)
```

### 带 provider 服务

```go
e := gin.New(
    gin.WithCache(customCache),
    gin.WithMail(mailCfg),
    gin.WithSMS(smsCfg),
)
```

## 常见坑

### 1. 启动时直接 panic

优先检查：
- `WithAuth` 配置是否通过校验
- `WithTrustedProxies` 格式是否合法
- `WithMail` / `WithSMS` 的 provider 配置是否完整

### 2. 上传配置不生效

优先检查：
- 是否用了 `WithUploadConfig`
- `MaxMultipartMemory` 是否同步写入 Gin
- 路由是否运行在同一个 `Engine` 上

### 3. `c.Auth()` 不可用

优先检查：
- 引擎是否通过 `WithAuth` 初始化
- 当前 handler 是否来自该引擎

## 下一跳

- 认证：`./auth-integration.md`
- 路由：`./router-patterns.md`
- 排障：`./troubleshooting.md`
- repo 实际文档：`./repo-doc-map.md`
