package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/darkit/gin"
)

// Message 表示聊天消息。
type Message struct {
	ID        int       `json:"id"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

var messages = []Message{
	{ID: 1, Role: "system", Content: "欢迎进入流式示例", CreatedAt: time.Now().Add(-5 * time.Minute)},
	{ID: 2, Role: "user", Content: "帮我生成日报", CreatedAt: time.Now().Add(-4 * time.Minute)},
	{ID: 3, Role: "assistant", Content: "正在整理今日关键事项", CreatedAt: time.Now().Add(-3 * time.Minute)},
	{ID: 4, Role: "assistant", Content: "已生成初稿，请继续补充数据", CreatedAt: time.Now().Add(-2 * time.Minute)},
	{ID: 5, Role: "user", Content: "请补上销售数据趋势", CreatedAt: time.Now().Add(-1 * time.Minute)},
}

func main() {
	e := gin.Default(
		gin.WithAddr(":8080"),
	)

	r := e.Router()

	// SSE 示例：模拟 AI 任务进度。
	r.GET("/events", func(c *gin.Context) {
		steps := []string{
			"已接收任务",
			"正在检索历史上下文",
			"正在生成结构化结果",
			"正在补充统计信息",
			"任务完成",
		}

		c.BeginSSE()
		for idx, step := range steps {
			select {
			case <-c.Done():
				return
			default:
			}

			if err := c.SSE("progress", gin.H{
				"step":    idx + 1,
				"total":   len(steps),
				"message": step,
			}); err != nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}

		_ = c.SSE("done", gin.H{
			"status": "completed",
		})
	})

	// NDJSON 示例：模拟日志尾流。
	r.GET("/logs", func(c *gin.Context) {
		lines := []map[string]any{
			{"level": "info", "message": "任务已进入队列"},
			{"level": "info", "message": "开始执行提示词模板"},
			{"level": "warn", "message": "外部数据源延迟较高"},
			{"level": "info", "message": "结果已写入缓存"},
		}

		c.BeginNDJSON()
		for idx, line := range lines {
			select {
			case <-c.Done():
				return
			default:
			}

			line["index"] = idx + 1
			line["timestamp"] = time.Now().Format(time.RFC3339)
			if err := c.StreamNDJSON(line); err != nil {
				return
			}
			time.Sleep(350 * time.Millisecond)
		}
	})

	// Cursor 分页示例：模拟消息列表。
	r.GET("/messages", func(c *gin.Context) {
		params := c.ParseCursorPagination(
			gin.WithDefaultCursorLimit(2),
			gin.WithMaxCursorLimit(3),
		)

		start := 0
		if params.Cursor != "" {
			cursorID, err := strconv.Atoi(params.Cursor)
			if err != nil {
				c.Problem(
					http.StatusBadRequest,
					"https://example.com/problems/invalid-cursor",
					"无效游标",
					"cursor 必须是整数 ID",
				)
				return
			}
			start = findMessageStart(cursorID)
		}

		end := start + params.Limit
		if end > len(messages) {
			end = len(messages)
		}

		chunk := messages[start:end]
		nextCursor := ""
		hasMore := end < len(messages)
		if hasMore && len(chunk) > 0 {
			nextCursor = strconv.Itoa(chunk[len(chunk)-1].ID)
		}

		c.CursorPaginated(chunk, &gin.CursorPageInfo{
			NextCursor: nextCursor,
			Limit:      params.Limit,
			HasMore:    hasMore,
		})
	})

	// Problem Details 示例。
	r.GET("/problems/demo", func(c *gin.Context) {
		mode := c.Input("mode", "validation")
		switch mode {
		case "validation":
			c.ValidationProblem([]gin.ValidationError{
				{Field: "prompt", Message: "prompt 不能为空"},
				{Field: "model", Message: "model 不在允许列表中"},
			}, "请求参数验证失败")
		case "quota":
			c.Problem(
				http.StatusTooManyRequests,
				"https://example.com/problems/quota-exceeded",
				"配额不足",
				"当前租户的调用额度已用尽，请稍后重试",
			)
		default:
			c.Problem(
				http.StatusBadRequest,
				"https://example.com/problems/invalid-mode",
				"无效模式",
				"仅支持 validation 或 quota",
			)
		}
	})

	// Webhook 辅助示例。
	r.POST("/webhooks/demo", func(c *gin.Context) {
		body, err := c.RawBody()
		if err != nil {
			c.InternalError("读取原始请求体失败")
			return
		}

		c.Success(gin.H{
			"event_id":  c.WebhookEventID(),
			"signature": c.WebhookSignature(),
			"timestamp": c.WebhookTimestamp(),
			"raw_body":  string(body),
		})
	})

	fmt.Println("Streaming example is running on http://localhost:8080")
	fmt.Println("  - GET  /events           SSE 任务进度流")
	fmt.Println("  - GET  /logs             NDJSON 日志流")
	fmt.Println("  - GET  /messages         Cursor 分页消息列表")
	fmt.Println("  - GET  /problems/demo    Problem Details 示例")
	fmt.Println("  - POST /webhooks/demo    Webhook 辅助方法示例")

	if err := e.Run(); err != nil {
		panic(err)
	}
}

func findMessageStart(cursorID int) int {
	for idx, message := range messages {
		if message.ID > cursorID {
			return idx
		}
	}
	return len(messages)
}
