package middleware

import (
	"github.com/darkit/gin"
)

// headResponseWriter 包装 gin.ResponseWriter，丢弃响应体但保留响应头。
type headResponseWriter struct {
	gin.ResponseWriter
}

// Write 丢弃写入的数据，但返回成功状态。
func (w *headResponseWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

// WriteString 丢弃写入的字符串，但返回成功状态。
func (w *headResponseWriter) WriteString(s string) (int, error) {
	return len(s), nil
}

// WrapHeadHandler 将 HandlerFunc 包装为 HEAD 处理器。
// 内部使用，由 Router.GetHead() 调用。
func WrapHeadHandler(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		originalWriter := c.Writer
		c.Writer = &headResponseWriter{ResponseWriter: c.Writer}
		handler(c)
		c.Writer = originalWriter
	}
}
