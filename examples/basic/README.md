# 基础示例

演示 Darkit Gin 的基础功能，包括路由定义、参数获取和响应方法。

## 运行示例

```bash
cd examples/basic
go run main.go
```

服务将在 `http://localhost:8080` 启动。

## 功能演示

### 1. 获取单个用户

**请求：**

```bash
curl http://localhost:8080/users/1
```

**响应：**

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 1,
    "name": "张三",
    "email": "zhangsan@example.com"
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1703001234
}
```

### 2. 获取用户列表（分页）

**请求：**

```bash
curl "http://localhost:8080/users?page=1&per_page=10"
```

**响应：**

```json
{
  "code": 200,
  "message": "success",
  "data": [
    {
      "id": 1,
      "name": "张三",
      "email": "zhangsan@example.com"
    },
    {
      "id": 2,
      "name": "李四",
      "email": "lisi@example.com"
    },
    {
      "id": 3,
      "name": "王五",
      "email": "wangwu@example.com"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 3,
    "total_pages": 1
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1703001234
}
```

### 3. 创建用户

**请求：**

```bash
curl -X POST http://localhost:8080/users \
  -H "Content-Type: application/json" \
  -d '{
    "name": "赵六",
    "email": "zhaoliu@example.com"
  }'
```

**响应：**

```json
{
  "code": 201,
  "message": "created",
  "data": {
    "id": 100,
    "name": "赵六",
    "email": "zhaoliu@example.com"
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1703001234
}
```

### 4. 更新用户

**请求：**

```bash
curl -X PUT http://localhost:8080/users/1 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "张三（已更新）",
    "email": "zhangsan_new@example.com"
  }'
```

### 5. 删除用户

**请求：**

```bash
curl -X DELETE http://localhost:8080/users/1
```

**响应：**

```
HTTP/1.1 204 No Content
```

### 6. 错误响应示例

**400 Bad Request:**

```bash
curl "http://localhost:8080/errors/demo?type=400"
```

```json
{
  "code": 400,
  "message": "错误的请求参数",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1703001234
}
```

**422 Validation Error:**

```bash
curl "http://localhost:8080/errors/demo?type=422"
```

```json
{
  "code": 422,
  "message": "validation failed",
  "errors": [
    {
      "field": "name",
      "message": "名称不能为空"
    },
    {
      "field": "email",
      "message": "邮箱格式不正确"
    }
  ],
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1703001234
}
```

### 7. 请求信息

**请求：**

```bash
curl http://localhost:8080/info \
  -H "User-Agent: Mozilla/5.0" \
  -H "X-Requested-With: XMLHttpRequest"
```

**响应：**

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "ip": "127.0.0.1",
    "user_agent": "Mozilla/5.0",
    "is_ajax": true,
    "is_json": false
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1703001234
}
```

## 核心特性

### 1. 统一响应格式

所有响应自动包装为统一格式：

- `code`: HTTP 状态码
- `message`: 响应消息
- `data`: 业务数据
- `request_id`: 请求追踪 ID
- `timestamp`: Unix 时间戳

### 2. 丰富的响应方法

- `c.Success(data)` - 200 OK
- `c.Created(data)` - 201 Created
- `c.Accepted(data)` - 202 Accepted
- `c.NoContent()` - 204 No Content
- `c.Paginated(data, page, perPage, total)` - 分页响应
- `c.BadRequest(message)` - 400 Bad Request
- `c.Unauthorized(message)` - 401 Unauthorized
- `c.Forbidden(message)` - 403 Forbidden
- `c.NotFound(message)` - 404 Not Found
- `c.Conflict(message)` - 409 Conflict
- `c.ValidationError(errors)` - 422 Unprocessable Entity
- `c.InternalError(message)` - 500 Internal Server Error
- `c.ErrorResponse(code, message)` - 自定义状态码

### 3. 参数获取辅助方法

- `c.Input(key, default...)` - 聚合读取参数（路径/查询/表单）
- `c.ParamInt(key, default...)` - 获取整数参数
- `c.ParamInt64(key, default...)` - 获取 int64 参数
- `c.ParamFloat(key, default...)` - 获取 float64 参数
- `c.ParamBool(key, default...)` - 获取 bool 参数
- `c.GetIP()` - 获取客户端 IP
- `c.GetUserAgent()` - 获取 User-Agent
- `c.IsAjax()` - 判断是否 AJAX 请求
- `c.IsJSON()` - 判断是否 JSON 请求

### 4. 内置中间件

`engine.Default()` 自动启用：

- **RequestID**: 自动生成请求 ID
- **Recovery**: Panic 恢复
- **Logger**: 请求日志

### 5. 优雅停机

监听 `SIGINT`/`SIGTERM`/`SIGQUIT` 信号，自动执行优雅停机：

- 停止接受新请求
- 等待当前请求完成
- 超时后强制退出
