package middleware

import (
	"log"
	"os"
	"time"

	"github.com/darkit/gin"
)

func Logger() gin.HandlerFunc {
	logger := log.New(os.Stdout, "[GIN] ", log.LstdFlags)

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()

		logger.Printf("%s %s %d %v %s",
			method,
			path,
			status,
			latency,
			clientIP,
		)
	}
}
