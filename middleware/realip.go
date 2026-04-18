package middleware

import (
	"strings"

	"github.com/darkit/gin"
)

const realIPKey = "real_ip"

// RealIP 提取真实客户端 IP，并保存到上下文。
func RealIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ip string

		// 1. X-Forwarded-For
		if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			ip = strings.TrimSpace(ips[0])
		}

		// 2. X-Real-IP
		if ip == "" {
			ip = c.GetHeader("X-Real-IP")
		}

		// 3. RemoteAddr
		if ip == "" {
			ip = c.Request.RemoteAddr
			if idx := strings.LastIndex(ip, ":"); idx != -1 {
				ip = ip[:idx]
			}
		}

		c.Set(realIPKey, ip)
		c.Next()
	}
}

// GetRealIP 获取 RealIP 中间件保存的 IP。
func GetRealIP(c *gin.Context) string {
	if ip, exists := c.Get(realIPKey); exists {
		if str, ok := ip.(string); ok {
			return str
		}
	}
	return ""
}
