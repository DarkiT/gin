package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/darkit/gin"
)

func Timeout(d time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), d)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		finish := make(chan struct{})
		panicChan := make(chan any, 1)

		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicChan <- p
				}
			}()
			c.Next()
			close(finish)
		}()

		select {
		case <-finish:
			// 处理器正常完成，检查是否超时
			select {
			case p := <-panicChan:
				panic(p)
			default:
			}
			// 如果在处理过程中超时了，且没有写响应，则返回超时错误
			if ctx.Err() == context.DeadlineExceeded && !c.Writer.Written() {
				c.AbortWithStatus(http.StatusRequestTimeout)
			}
		case <-ctx.Done():
			// 超时发生，等待 handler 完成后再写响应
			<-finish
			select {
			case p := <-panicChan:
				panic(p)
			default:
			}
			// Handler 完成后，如果没有写响应，则返回超时错误
			if !c.Writer.Written() {
				c.AbortWithStatus(http.StatusRequestTimeout)
			}
		}
	}
}
