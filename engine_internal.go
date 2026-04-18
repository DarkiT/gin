package gin

import "github.com/google/uuid"

// middlewareRegistry 保留扩展引擎中的中间件注册位，避免泄露到公开 API。
type middlewareRegistry struct{}

func newMiddlewareRegistry() *middlewareRegistry {
	return &middlewareRegistry{}
}

func requestIDMiddleware() HandlerFunc {
	return func(c *Context) {
		requestID := c.GetHeader(requestIDHeader)
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set("request_id", requestID)
		c.Header(requestIDHeader, requestID)
		c.Next()
	}
}
