# 流式与游标分页示例

本示例演示以下能力：

- `SSE()` / `SSEHeartbeat()` 的流式任务进度输出
- `StreamNDJSON()` 的日志尾流
- `ParseCursorPagination()` / `CursorPaginated()` 的游标分页
- `Problem()` / `ValidationProblem()` 的标准错误响应
- `RawBody()`、`WebhookEventID()`、`WebhookSignature()`、`WebhookTimestamp()` 的 webhook 辅助方法

## 运行示例

```bash
cd examples/streaming
go run main.go
```

服务默认监听 `http://localhost:8080`。

## 1. SSE 任务进度流

```bash
curl -N http://localhost:8080/events
```

输出示例：

```text
event: progress
data: {"message":"已接收任务","step":1,"total":5}

event: progress
data: {"message":"正在检索历史上下文","step":2,"total":5}

event: done
data: {"status":"completed"}
```

## 2. NDJSON 日志流

```bash
curl -N http://localhost:8080/logs
```

输出示例：

```text
{"index":1,"level":"info","message":"任务已进入队列","timestamp":"2026-04-17T12:00:00+08:00"}
{"index":2,"level":"info","message":"开始执行提示词模板","timestamp":"2026-04-17T12:00:01+08:00"}
```

## 3. Cursor 分页

首次请求：

```bash
curl http://localhost:8080/messages?limit=2
```

继续请求下一页：

```bash
curl "http://localhost:8080/messages?cursor=2&limit=2"
```

返回结构中会包含：

- `next_cursor`
- `limit`
- `has_more`

## 4. Problem Details

校验错误示例：

```bash
curl "http://localhost:8080/problems/demo?mode=validation"
```

配额错误示例：

```bash
curl "http://localhost:8080/problems/demo?mode=quota"
```

## 5. Webhook 辅助

```bash
curl -X POST http://localhost:8080/webhooks/demo \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Delivery: delivery-001" \
  -H "X-Hub-Signature-256: sha256=test-signature" \
  -H "X-Timestamp: 1710000000" \
  -d '{"event":"build.completed","ok":true}'
```

服务会返回提取到的事件 ID、签名、时间戳以及原始请求体。
