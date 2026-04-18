package middleware

import (
	"bytes"

	"github.com/darkit/gin"
)

// RequestInterceptor 请求拦截器
type RequestInterceptor func(*gin.Context) error

// ResponseInterceptor 响应拦截器
type ResponseInterceptor func(*gin.Context, []byte) ([]byte, error)

// InterceptorConfig 拦截器中间件配置
type InterceptorConfig struct {
	OnRequest  RequestInterceptor
	OnResponse ResponseInterceptor
}

// Interceptor 创建拦截器中间件
func Interceptor(config InterceptorConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 请求拦截
		if config.OnRequest != nil {
			if err := config.OnRequest(c); err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				c.Abort()
				return
			}
		}

		// 响应拦截
		if config.OnResponse != nil {
			// 包装 ResponseWriter
			w := &interceptorResponseWriter{
				ResponseWriter: c.Writer,
				body:           &bytes.Buffer{},
			}
			c.Writer = w

			c.Next()

			// 拦截响应
			newBody, err := config.OnResponse(c, w.body.Bytes())
			if err != nil {
				// 恢复原始 Writer 并返回错误响应
				c.Writer = w.ResponseWriter
				c.JSON(500, gin.H{"error": "响应处理失败"})
				return
			}

			// 写入新响应
			c.Writer = w.ResponseWriter
			if _, err := c.Writer.Write(newBody); err != nil {
				_ = c.Error(err)
				c.Abort()
			}
		} else {
			c.Next()
		}
	}
}

type interceptorResponseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *interceptorResponseWriter) Write(b []byte) (int, error) {
	// 只写入 buffer，不写入原始 ResponseWriter
	// 在拦截器处理完成后再统一写入修改后的内容
	return w.body.Write(b)
}
