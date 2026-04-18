# Feature Recipes

这份文件面向“我要快速落一个能力”的场景，不讲内部实现，只讲推荐用法。

## 目录

- 对外 API 使用标准错误模型
- 流式输出
- webhook 接收器
- cursor pagination
- 探针
- Swagger / OpenAPI 机器友好输出
- OTel
- 上传 / 下载 / 导出
- 图片处理与脱敏
- WebSocket
- 推荐组合
- 对应模板与示例

## 1. 对外 API 使用标准错误模型

推荐优先级：

1. 简单内部接口：`BadRequest` / `Unauthorized` / `InternalError`
2. 对外 API / SDK / agent：`Problem(...)` / `ValidationProblem(...)`

示例：

```go
if err := c.BindAndValidate(&req); err != nil {
    c.ValidationProblem(gin.ExtractValidationErrors(err), "请求参数验证失败")
    return
}

c.Problem(
    http.StatusConflict,
    "https://example.com/problems/user-conflict",
    "用户冲突",
    "当前用户正被其他流程编辑",
)
```

## 2. 流式输出

### SSE

适合：

- AI 任务进度
- 审批状态推送
- 前端订阅式进度展示

核心方法：

- `BeginSSE()`
- `SSE(event, data)`
- `SSEHeartbeat()`

### NDJSON

适合：

- 日志尾流
- 批量任务逐条结果返回

核心方法：

- `BeginNDJSON()`
- `StreamNDJSON(data)`

模板：

- `../assets/examples/streaming_webhook.go.tmpl`

repo 示例：

- `examples/streaming/main.go`

## 3. webhook 接收器

推荐流程：

1. `RawBody()` 读取原始 body
2. `WebhookSignature()` 取签名头
3. `WebhookEventID()` 取事件 ID 做幂等
4. 验签成功后再解析 body

模板：

- `../assets/examples/streaming_webhook.go.tmpl`

## 4. cursor pagination

适合：

- 消息列表
- 时间线
- 增量列表

推荐写法：

```go
params := c.ParseCursorPagination(
    gin.WithDefaultCursorLimit(20),
    gin.WithMaxCursorLimit(100),
)

c.CursorPaginated(data, &gin.CursorPageInfo{
    NextCursor: nextCursor,
    PrevCursor: prevCursor,
    Limit:      params.Limit,
    HasMore:    hasMore,
})
```

## 5. 探针

推荐直接挂：

- `HealthCheck()`
- `Liveness()`
- `Readiness(...)`
- `Startup(...)`

推荐检查项写法：

```go
r.Readiness(
    gin.NamedProbe("database", func(c *gin.Context) error { ... }),
    gin.NamedProbe("cache", func(c *gin.Context) error { ... }),
)
```

repo 示例：

- `examples/probes/main.go`

## 6. Swagger / OpenAPI 机器友好输出

如果你要给 SDK、agent、API catalog 使用，推荐补齐这些字段：

- `OperationID(...)`
- `RequestExample(...)` / `RequestExamples(...)`
- `ResponseExample(...)` / `ResponseExamples(...)`
- `ProblemResponse(...)`
- `DefaultErrors(...)`

推荐入口：

- `GETDoc(...)`
- `POSTDoc(...)`

repo 示例：

- `examples/swagger-demo/main.go`

## 7. OTel

最简单的接法：

```go
e.UseAny(
    middleware.OTel("order-service"),
    middleware.CORS(),
)
```

请求内读取：

- `c.TraceID()`
- `c.SpanID()`

## 8. 上传 / 下载 / 导出

高频能力真实存在：

- `SaveFile / SaveFiles`
- `StreamFile / StreamFileInline`
- `ExportExcel / StreamExcel`
- `ExportCSV / StreamCSV`

适合：

- 后台附件上传
- 文件下载接口
- 报表导出

模板：

- `../assets/examples/file_upload_download.go.tmpl`
- `../assets/examples/export_excel_csv.go.tmpl`

## 9. 图片处理与脱敏

图片处理能力：

- `SaveImage(...)`
- `ProcessImages(...)`

脱敏响应能力：

- `OKMasked(...)`
- `PaginatedMasked(...)`

适合：

- 上传图片时顺手压缩、裁剪、生成多尺寸
- 对用户资料、手机号、证件字段做统一脱敏输出

## 10. WebSocket

根包真实提供：

- `UpgradeWebSocket(userID, opts...)`

适合：

- 在线通知
- 即时消息
- 状态订阅

## 11. 推荐组合

### 现代对外 API

- `Problem Details`
- `DefaultErrors`
- `OperationID`
- `Request/Response Examples`
- `RequestID`
- `OTel`

### AI / Agent / Streaming API

- `SSE` 或 `NDJSON`
- `Problem Details`
- `cursor pagination`
- `Webhook helper`

### 平台化服务

- `Readiness` / `Startup`
- `OTel`
- `RequestID`

## 12. 对应模板与示例

- 模板：`../assets/examples/streaming_webhook.go.tmpl`
- 模板：`../assets/examples/file_upload_download.go.tmpl`
- 模板：`../assets/examples/export_excel_csv.go.tmpl`
- repo 示例：`examples/streaming/main.go`
- repo 示例：`examples/probes/main.go`
- repo 示例：`examples/swagger-demo/main.go`
