# Architecture Overview

这份文件只保留从使用者视角最有价值的结构信息，帮助快速判断问题落在哪一层。

## 目录

- 项目定位
- 你应该如何分层理解
- 现在最重要的使用边界
- 下一跳

## 项目定位

`github.com/darkit/gin` 不是重写版 Gin，而是构建在 `gin-gonic/gin` 之上的增强层。

它对上游公开面做了较高程度的兼容，同时在这些地方明显增强：

- 增强 `Context`
- 更强的 `Router`
- `auth` 子系统
- 中间件生态
- regex 路由与自动注册
- 静态站点 / SPA / ZIP 交付能力
- Problem Details、SSE、cursor pagination、webhook helper、探针、OpenAPI 机器友好能力
- lifecycle-managed cache 与 `pkg/storage` / Fiber storage 生态适配
- repo-local `gincompat` 公开面兼容矩阵（仅框架维护时使用）

## 你应该如何分层理解

### 1. Upstream 兼容层

最底层仍是上游 Gin 的：

- `gin.Engine`
- `gin.Context`
- `gin.RouterGroup`

当前项目通过包装和扩展保持这套心智模型，而不是完全替换它。

### 2. Engine 层

负责：

- 聚合配置与共享组件
- 管理 provider：logger、cache、mail、sms、auth
- 托管 cache/auth/mail/sms 等受管资源生命周期
- 生命周期与优雅停机
- `NoRoute` 调度链
- 受控静态挂载与 regex 路由兜底

如果问题是“服务怎么起来”“全局能力怎么接”“静态站点为什么没命中”，优先看这里。

### 3. Router 层

负责：

- `func(*Context)` 处理器签名
- 分组、版本路由、资源路由
- 自动注册
- chi 风格 regex 路由
- 探针路由
- Swagger/OpenAPI 路由文档
- 受控静态挂载入口

如果问题是“路由怎么组织”“用哪个注册入口”“为什么 regex/static 优先级不对”，优先看这里。

### 4. Context 层

这是业务 handler 的主工作面。

负责：

- 参数解析
- 绑定与校验
- 标准 JSON 响应
- Problem Details
- 分页与 cursor pagination
- SSE / NDJSON
- webhook helper
- 文件上传 / 下载
- 导出
- 认证透出
- OTel trace/span 读取

如果问题是“handler 里怎么写最省心”，优先看这里。

### 5. Capability 层

由几个子系统构成：

- `auth/`
- `middleware/`
- `pkg/static`
- `pkg/swagger`
- `pkg/routes`
- `pkg/cache` / `pkg/storage` / `pkg/logger` / `pkg/mail` / `pkg/sms` 等
- `internal/tools/gincompat`（仅 `github.com/darkit/gin` 本仓维护场景）

如果问题已经缩到专项能力面，调用方项目优先进入对应 reference；只有维护框架本仓时才继续读 live code。

## 现在最重要的使用边界

### 路由优先级

当前请求落点顺序应理解为：

1. 普通 Gin 路由
2. regex 路由
3. `Assets*` / `Site*` / `FallbackSite*`
4. 用户 `NoRoute`

### 参数语义

- `Param`：路径参数
- `Input`：聚合取值

### 中间件语义

- `Use`：增强 `HandlerFunc`
- `UseAny`：增强 `HandlerFunc` + `gin.HandlerFunc` + 标准 `http` middleware

### 错误语义

- `Error(...)`：上游 Gin 错误收集
- `ErrorResponse(...)` / `Problem(...)`：项目的对外错误响应

### 生命周期语义

- `WithCache(...)` 表示 Engine 接管 cache 生命周期，关闭时调用 `Close()`
- `WithAuth(...)` / `WithMail(...)` / `WithSMS(...)` 构造期声明配置，运行阶段由 Engine 初始化受管资源
- 增强 `Context` 是请求期轻量 wrapper；当前不做池化回收，避免逃逸后复用引发数据竞争

## 下一跳

- 快速起步：`./quickstart.md`
- cache/storage：`./cache-storage-integration.md`
- `Context` 速查：`./context-cheatsheet.md`
- 路由设计：`./router-patterns.md`
- 现代能力配方：`./feature-recipes.md`
- 静态站点与交付：`./static-site-recipes.md`
