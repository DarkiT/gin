package middleware

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"net/http"

	"github.com/darkit/gin"
)

// etagResponseWriter ETag 响应写入器
type etagResponseWriter struct {
	gin.ResponseWriter
	body   *bytes.Buffer
	status int
}

// newEtagResponseWriter 创建新的 ETag 响应写入器
func newEtagResponseWriter(w gin.ResponseWriter) *etagResponseWriter {
	return &etagResponseWriter{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		status:         http.StatusOK,
	}
}

// Write 写入响应体
func (w *etagResponseWriter) Write(data []byte) (int, error) {
	return w.body.Write(data)
}

// WriteString 写入字符串响应体
func (w *etagResponseWriter) WriteString(s string) (int, error) {
	return w.body.WriteString(s)
}

// WriteHeader 写入响应状态码
func (w *etagResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

// Status 获取响应状态码
func (w *etagResponseWriter) Status() int {
	return w.status
}

// ETag ETag 中间件
// 自动计算响应内容的 ETag，并处理 If-None-Match 请求头
func ETag() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 只处理 GET 和 HEAD 请求
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Next()
			return
		}

		// 创建自定义响应写入器
		writer := newEtagResponseWriter(c.Writer)
		c.Writer = writer

		// 继续处理请求
		c.Next()

		// 只处理成功的响应（2xx）
		if writer.Status() < 200 || writer.Status() >= 300 {
			// 非成功响应，直接写入原始响应
			c.Writer = writer.ResponseWriter
			c.Writer.WriteHeader(writer.status)
			if _, err := c.Writer.Write(writer.body.Bytes()); err != nil {
				_ = c.Error(err)
				c.Abort()
			}
			return
		}

		// 计算响应内容的 MD5 哈希作为 ETag
		bodyBytes := writer.body.Bytes()
		etag := generateETag(bodyBytes)

		// 检查客户端的 If-None-Match 头
		clientETag := c.GetHeader("If-None-Match")
		if clientETag != "" && clientETag == etag {
			// ETag 匹配，返回 304 Not Modified
			c.Writer = writer.ResponseWriter
			c.Writer.Header().Set("ETag", etag)
			c.Writer.WriteHeader(http.StatusNotModified)
			return
		}

		// ETag 不匹配或客户端未提供，返回完整响应
		c.Writer = writer.ResponseWriter
		c.Writer.Header().Set("ETag", etag)
		c.Writer.WriteHeader(writer.status)
		if _, err := c.Writer.Write(bodyBytes); err != nil {
			_ = c.Error(err)
			c.Abort()
		}
	}
}

// generateETag 生成 ETag
// 使用 MD5 哈希计算内容的 ETag
func generateETag(data []byte) string {
	hash := md5.Sum(data)
	return fmt.Sprintf(`"%x"`, hash)
}
