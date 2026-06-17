// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const (
	sseContentType    = "text/event-stream; charset=utf-8"
	ndjsonContentType = "application/x-ndjson; charset=utf-8"
)

// Flush 立即将缓冲区内容刷新到客户端。
func (c *Context) Flush() bool {
	if c == nil || c.Writer == nil {
		return false
	}
	c.Writer.Flush()
	return true
}

// BeginSSE 初始化 Server-Sent Events 响应头。
func (c *Context) BeginSSE() {
	if c == nil || c.Writer == nil {
		return
	}

	header := c.Writer.Header()
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", sseContentType)
	}
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache")
	}
	if header.Get("Connection") == "" {
		header.Set("Connection", "keep-alive")
	}
	header.Set("X-Accel-Buffering", "no")

	if !c.Writer.Written() {
		c.Status(http.StatusOK)
	}
	c.Flush()
}

// SSE 输出一条 Server-Sent Events 消息。
func (c *Context) SSE(event string, data any) error {
	if c == nil || c.Writer == nil {
		return nil
	}

	c.BeginSSE()
	if event == "" {
		event = "message"
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if _, err = io.WriteString(c.Writer, "event: "+sanitizeSSEField(event)+"\n"); err != nil {
		return err
	}
	if _, err = io.WriteString(c.Writer, "data: "+string(payload)+"\n\n"); err != nil {
		return err
	}

	c.Flush()
	return nil
}

// SSEComment 输出一条注释型 SSE 消息，常用于心跳。
func (c *Context) SSEComment(comment string) error {
	if c == nil || c.Writer == nil {
		return nil
	}

	c.BeginSSE()
	lines := strings.SplitSeq(strings.ReplaceAll(comment, "\r\n", "\n"), "\n")
	for line := range lines {
		if _, err := io.WriteString(c.Writer, ":"+line+"\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(c.Writer, "\n"); err != nil {
		return err
	}

	c.Flush()
	return nil
}

// SSEHeartbeat 输出一条默认心跳注释。
func (c *Context) SSEHeartbeat() error {
	return c.SSEComment("heartbeat")
}

// BeginNDJSON 初始化 NDJSON 流式响应头。
func (c *Context) BeginNDJSON() {
	if c == nil || c.Writer == nil {
		return
	}

	header := c.Writer.Header()
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", ndjsonContentType)
	}
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache")
	}

	if !c.Writer.Written() {
		c.Status(http.StatusOK)
	}
	c.Flush()
}

// StreamNDJSON 输出一条 NDJSON 记录并立即刷新。
func (c *Context) StreamNDJSON(data any) error {
	if c == nil || c.Writer == nil {
		return nil
	}

	c.BeginNDJSON()
	if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
		return err
	}

	c.Flush()
	return nil
}

func sanitizeSSEField(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}
