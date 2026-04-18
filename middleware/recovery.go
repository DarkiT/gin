package middleware

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/darkit/gin"
)

func Recovery() gin.HandlerFunc {
	return RecoveryWithWriter(os.Stderr)
}

func RecoveryWithWriter(out io.Writer) gin.HandlerFunc {
	var logger *log.Logger
	if out != nil {
		logger = log.New(out, "\n\n[Recovery] ", log.LstdFlags)
	}
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				var brokenPipe bool
				switch e := err.(type) {
				case *net.OpError:
					if se, ok := e.Err.(*os.SyscallError); ok {
						seStr := strings.ToLower(se.Error())
						if strings.Contains(seStr, "broken pipe") || strings.Contains(seStr, "connection reset") {
							brokenPipe = true
						}
					}
				case *os.SyscallError:
					seStr := strings.ToLower(e.Error())
					if strings.Contains(seStr, "broken pipe") || strings.Contains(seStr, "connection reset") {
						brokenPipe = true
					}
				}

				if logger != nil {
					logger.Printf("[Recovery] panic recovered:\n%v", err)
				}

				if brokenPipe {
					if e, ok := err.(error); ok {
						_ = c.Error(e)
					} else {
						_ = c.Error(fmt.Errorf("panic: %v", err))
					}
					c.Abort()
					return
				}

				c.AbortWithStatus(500)
			}
		}()
		c.Next()
	}
}
