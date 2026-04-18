# 高级示例

演示 Darkit Gin 的高级功能，包括中间件组合、RESTful 资源路由、API 版本管理、缓存、日志与健康检查等。

## 运行示例

```bash
cd examples/advanced
go run main.go
```

服务将在 `http://localhost:8080` 启动。

## 功能演示

### 1. RESTful 资源路由

使用 `routes.Resource()` 自动注册 RESTful 端点：

```go
routes.Resource(v1, "products", &ProductController{})
```

自动创建以下路由：

- `GET /v1/products` → Index (列表)
- `GET /v1/products/:id` → Show (详情)
- `POST /v1/products` → Create (创建)
- `PUT /v1/products/:id` → Update (全量更新)
- `PATCH /v1/products/:id` → Patch (部分更新)
- `DELETE /v1/products/:id` → Destroy (删除)

**测试：**

```bash
# 获取产品列表
curl http://localhost:8080/v1/products

# 获取单个产品
curl http://localhost:8080/v1/products/1

# 创建产品
curl -X POST http://localhost:8080/v1/products \
  -H "Content-Type: application/json" \
  -d '{"name":"新产品","price":299.99}'

# 更新产品
curl -X PUT http://localhost:8080/v1/products/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"更新产品","price":399.99}'

# 部分更新
curl -X PATCH http://localhost:8080/v1/products/1 \
  -H "Content-Type: application/json" \
  -d '{"price":199.99}'

# 删除产品
curl -X DELETE http://localhost:8080/v1/products/1
```

### 2. API 版本管理

使用 `routes.Version()` 创建版本化路由：

**V1 API:**

```bash
curl http://localhost:8080/v1/stats
```

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "version": "v1",
    "total": 100,
    "active": 85
  }
}
```

**V2 API (增强版):**

```bash
curl http://localhost:8080/v2/stats
```

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "version": "v2",
    "total": 100,
    "active": 85,
    "inactive": 15,
    "new_today": 5,
    "updated_at": 1703001234
  }
}
```

### 3. 中间件组合

API 分组应用多个中间件：

```go
api := r.Group("/api")
api.Use(
    middleware.CORS(...),
    middleware.RateLimit(...),
    middleware.Timeout(30*time.Second),
)
```

**测试限流：**

```bash
# 快速发送多个请求（超过限流阈值）
for i in {1..25}; do
  curl http://localhost:8080/api/orders &
done
wait
```

超过限制后将返回 429 Too Many Requests。

说明：当前示例中的 `/api/orders` 已受 `Timeout(30*time.Second)` 保护，但并未额外暴露专门的慢接口来演示超时返回。

### 4. CORS 配置

跨域请求支持：

```bash
# 预检请求
curl -X OPTIONS http://localhost:8080/api/orders \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST"

# 实际请求
curl http://localhost:8080/api/orders \
  -H "Origin: http://localhost:3000"
```

响应头将包含：

- `Access-Control-Allow-Origin: http://localhost:3000`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Credentials: true`

### 5. 缓存使用

**首次请求（缓存未命中）：**

```bash
curl http://localhost:8080/cached
```

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "source": "generated",
    "data": "Generated at 2024-12-19T10:30:00Z"
  }
}
```

**后续请求（缓存命中）：**

```bash
curl http://localhost:8080/cached
```

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "source": "cache",
    "data": "Generated at 2024-12-19T10:30:00Z"
  }
}
```

缓存 TTL 为 1 分钟，过期后自动重新生成。

### 6. 日志记录

```bash
curl -X POST http://localhost:8080/log-demo \
  -H "Content-Type: application/json" \
  -d '{"action":"create","resource":"user"}'
```

服务端控制台将输出：

```
INFO  收到请求 payload=map[action:create resource:user]
DEBUG 调试信息 keys=2
```

### 7. 健康检查

**默认健康检查：**

```bash
curl http://localhost:8080/health
```

```json
{
  "status": "healthy"
}
```

**详细健康检查：**

```bash
curl http://localhost:8080/health/detailed
```

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "status": "healthy",
    "checks": {
      "database": "ok",
      "cache": "ok",
      "queue": "ok"
    },
    "uptime": "1h30m25s",
    "timestamp": 1703001234
  }
}
```

### 8. 认证保护

**未授权访问：**

```bash
curl http://localhost:8080/protected/profile
```

```json
{
  "code": 401,
  "message": "缺少 Authorization 头"
}
```

**授权访问：**

```bash
curl http://localhost:8080/protected/profile \
  -H "Authorization: Bearer valid-token"
```

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "user_id": 1,
    "name": "张三",
    "email": "zhangsan@example.com"
  }
}
```

## 核心特性

### 1. RESTful 资源路由

`routes.Resource()` 自动注册 6 个标准 RESTful 端点：

| HTTP 方法 | 路径               | 控制器方法 | 说明         |
| --------- | ------------------ | ---------- | ------------ |
| GET       | `/v1/products`     | Index      | 获取资源列表 |
| GET       | `/v1/products/:id` | Show       | 获取单个资源 |
| POST      | `/v1/products`     | Create     | 创建资源     |
| PUT       | `/v1/products/:id` | Update     | 全量更新     |
| PATCH     | `/v1/products/:id` | Patch      | 部分更新     |
| DELETE    | `/v1/products/:id` | Destroy    | 删除资源     |

### 2. API 版本管理

```go
v1 := routes.Version(r, "1")  // 创建 /v1 路由组
v2 := routes.Version(r, "2")  // 创建 /v2 路由组
```

支持多版本 API 并行维护，平滑升级。

### 3. 中间件

**内置中间件：**

- `Recovery()` - Panic 恢复
- `RequestID()` - 请求追踪 ID
- `Logger()` - 请求日志
- `CORS()` - 跨域配置
- `RateLimit()` - 流量限制
- `Timeout()` - 超时控制
- `Secure()` - 安全头

**中间件组合：**

```go
// 全局中间件
e.Use(middleware.Recovery(), middleware.RequestID())

// 路由组中间件
api := r.Group("/api")
api.Use(middleware.RateLimit(...), middleware.Timeout(...))
```

### 4. 缓存系统

**内置内存缓存：**

```go
cache := c.Cache()
cache.Set(ctx, key, value, ttl)
data, err := cache.Get(ctx, key)
```

支持：

- TTL 过期
- 最大容量限制
- 自动清理
- 并发安全

**自定义缓存：**
实现 `cache.Cache` 接口，可集成 Redis、Memcached 等。

### 5. 日志系统

**Context 快捷访问：**

```go
c.Logger().Info("message", "key", value)
c.Logger().Error("error", "err", err)
```

**支持级别：**

- Debug - 调试信息
- Info - 一般信息
- Warn - 警告
- Error - 错误

**自定义日志：**
实现 `logger.Logger` 接口，可集成 Zap、Logrus 等。

### 6. 优雅停机

监听系统信号：

- `SIGINT` (Ctrl+C)
- `SIGTERM` (kill)
- `SIGQUIT` (kill -3)

停机流程：

1. 停止接受新请求
2. 等待当前请求完成（最长 10 秒）
3. 关闭资源（数据库、缓存等）
4. 退出进程

## 性能测试

使用 Apache Bench 测试：

```bash
# 基准测试
ab -n 10000 -c 100 http://localhost:8080/v1/products

# 限流测试
ab -n 1000 -c 50 http://localhost:8080/api/orders

# 缓存测试
ab -n 10000 -c 100 http://localhost:8080/cached
```

## 最佳实践

### 1. 中间件顺序

推荐顺序：

1. `Recovery()` - 最外层，捕获所有 panic
2. `RequestID()` - 生成追踪 ID
3. `Logger()` - 记录请求日志
4. `CORS()` - 处理跨域
5. `Secure()` - 添加安全头
6. `RateLimit()` - 流量控制
7. `Timeout()` - 超时保护
8. 认证/授权中间件
9. 业务逻辑

### 2. 资源路由

对于标准 CRUD 操作，优先使用 `routes.Resource()`：

```go
// ✅ 推荐
routes.Resource(r, "users", &UserController{})

// ❌ 不推荐（手动定义重复路由）
r.GET("/users", ctrl.Index)
r.GET("/users/:id", ctrl.Show)
r.POST("/users", ctrl.Create)
// ...
```

### 3. API 版本

新功能应创建新版本，保持旧版本稳定：

```go
// V1 - 稳定版本
v1 := routes.Version(r, "1")
v1.GET("/users", oldHandler)

// V2 - 新功能
v2 := routes.Version(r, "2")
v2.GET("/users", newHandler)  // 增强的实现
```

### 4. 错误处理

统一错误响应格式：

```go
if err != nil {
    c.Logger().Error("操作失败", "error", err)
    c.InternalError("服务暂时不可用")
    return
}
```

### 5. 缓存策略

- 频繁访问的数据：使用缓存
- 缓存键命名：`{resource}:{id}:{version}`
- 合理设置 TTL：避免过长或过短
- 缓存失效：更新/删除数据时主动清除缓存
