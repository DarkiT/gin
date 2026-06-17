# Context Cheatsheet

这份速查表只保留上层 handler 最常用、最容易漂移的能力。

## 目录

- 先记住 5 条
- 请求信息
- 参数读取
- 绑定与校验
- 标准响应
- 内容协商
- 流式响应
- webhook 辅助
- Cookie 与请求状态
- 文件、导出、认证、WebSocket
- 图片与脱敏
- 最常见误用

## 先记住 5 条

- `Param` 只读路径参数；聚合读取请用 `Input`
- `Error(...)` 是上游 Gin 错误收集，不是统一错误响应
- `Negotiate(code, config)` 与上游兼容；自动协商请用 `AutoNegotiate(data)`
- 写流式响应、文件下载、导出后，不要再补第二次响应
- 如果你要的是“标准错误模型”，优先用 `Problem(...)` / `ValidationProblem(...)`

## 请求信息

- `GetIP()`
- `GetUserAgent()`
- `RequestID()`
- `GetBearerToken()`
- `GetBasicAuth()`
- `IsSecure()`
- `GetReferer()`
- `GetOrigin()`
- `TraceID()`
- `SpanID()`

## 参数读取

### 与上游一致的单一来源取值

- `Param(key)`
- `Query(key)`
- `DefaultQuery(key, def)`
- `PostForm(key)`
- `DefaultPostForm(key, def)`

### 项目增强的聚合取值

- `Input(key, def...)`
- `ParamInt`
- `ParamInt64`
- `ParamFloat`
- `ParamBool`
- `ParamIntE`
- `ParamInt64E`
- `ParamFloatE`
- `ParamBoolE`
- `ParamSlice`
- `ParamIntSlice`
- `ParamTime`
- `ParamDuration`

说明：

- `Input(...)` 的读取顺序是“路径参数 -> query -> form”
- `ParamInt` / `ParamBool` 等虽然保留了 `Param` 前缀，但语义也是聚合解析

## 绑定与校验

- `BindAndValidate(obj)`
- `BindJSONOrAbort(obj)`
- `BindQueryOrAbort(obj)`
- `JSONOrAbort(obj)`
- `RequireParams(keys...)`
- `RequireParamsOrAbort(keys...)`
- `ExtractValidationErrors(err)`

## 标准响应

### 成功响应

- `Success(data)`
- `SuccessWithMessage(data, message)`
- `Created(data)`
- `CreatedWithLocation(data, location)`
- `Accepted(data)`
- `NoContent()`

### 分页响应

- `ParsePagination(defaults...)`
- `PaginationParams(opts...)`
- `Paginated(data, page, perPage, total)`
- `ParseCursorPagination(opts...)`
- `CursorPaginated(data, info)`

### 统一错误响应

- `BadRequest(message)`
- `Unauthorized(message)`
- `Forbidden(message)`
- `NotFound(message)`
- `Conflict(message)`
- `ValidationError(errors)`
- `InternalError(message)`
- `MethodNotAllowed(message)`
- `TooManyRequests(message)`
- `ServiceUnavailable(message)`
- `GatewayTimeout(message)`
- `Gone(message)`
- `ErrorResponse(code, message)`

### Problem Details

- `WriteProblem(problem)`
- `Problem(status, typeURI, title, detail)`
- `AbortWithProblem(status, typeURI, title, detail)`
- `ValidationProblem(errors, detail...)`

适合：

- 对外 API
- webhook / SDK / agent 机器消费
- 想要稳定错误模型和字段错误明细

## 内容协商

- `AcceptsJSON()`
- `AcceptsHTML()`
- `Negotiate(code, config)`
- `AutoNegotiate(data)`
- `RedirectPermanent(location)`
- `RedirectTemporary(location)`

## 流式响应

- `BeginSSE()`
- `SSE(event, data)`
- `SSEComment(comment)`
- `SSEHeartbeat()`
- `BeginNDJSON()`
- `StreamNDJSON(data)`

适合：

- AI 任务进度
- 日志尾流
- 长任务状态推送

## webhook 辅助

- `RawBody()`
- `MustRawBody()`
- `RawBodyString()`
- `WebhookEventID(headers...)`
- `WebhookSignature(headers...)`
- `WebhookTimestamp(headers...)`

典型流程：

1. `RawBody()` 读取原始请求体
2. 根据 `WebhookSignature()` 做验签
3. 读取 `WebhookEventID()` 做幂等去重

## Cookie 与请求状态

- `SetSecureCookie(...)`
- `GetCookieOr(name, def)`
- `DeleteCookie(name)`
- `SetCookieWithOptions(name, value, opts)`
- `IsMethod(method)`
- `IsGET()` / `IsPOST()` / `IsPUT()` / `IsPATCH()` / `IsDELETE()` / `IsOPTIONS()`
- `IsAjax()` / `IsJSON()` / `IsForm()` / `IsMultipart()` / `IsWebSocket()`

## 文件、导出、认证、WebSocket

### 上传与下载

- `SaveFile(...)`
- `SaveFiles(...)`
- `ValidateFile(...)`
- `ValidateFiles(...)`
- `StreamFile(...)`
- `StreamFileInline(...)`

说明：

- `AsName(...)` 只接收纯文件名
- 需要目录分类时，使用 `ToSubDir(...)` 显式落到上传根目录下的安全子目录
- `SaveFiles(...)` 需要唯一目标名；批量自定义命名请用 `NameBy(...)`
- `UploadResult.RelativePath` 是相对上传根目录的稳定路径

模板：

- `../assets/examples/file_upload_download.go.tmpl`

### 导出

- `ExportExcel(...)`
- `ExportCSV(...)`
- `StreamExcel(...)`
- `StreamCSV(...)`

模板：

- `../assets/examples/export_excel_csv.go.tmpl`

### 认证

- `Auth()`

### Cache / Mail / SMS

- `Cache()`
- `Mailer()`
- `SMS()`

说明：

- `c.Cache()` 返回 Engine 托管的 `cache.Cache`
- 注入 `WithCache(...)` 的实例会随 Engine 关闭

继续读：

- `./cache-storage-integration.md`

### WebSocket

- `UpgradeWebSocket(userID, opts...)`

## 图片与脱敏

### 图片处理

- `SaveImage(...)`
- `ProcessImages(...)`

适合：

- 上传即压缩 / 裁剪 / 转格式
- 一次请求内生成多规格图片

### 脱敏输出

- `OKMasked(...)`
- `PaginatedMasked(...)`

适合：

- 用户资料、手机号、证件号等字段的对外输出脱敏
- 列表响应的统一脱敏返回

## 最常见误用

- 把 `c.Param(...)` 当聚合取值入口
- 把 `c.Error(...)` 当统一错误响应
- 直接调用 `Negotiate(data)` 这种旧签名
- 流式写出后再补 `Success(...)`

如果你正在写 handler，下一步通常读：

- 路由相关：`./router-patterns.md`
- 现代 API 配方：`./feature-recipes.md`
