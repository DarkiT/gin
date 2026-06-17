package middleware

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/darkit/gin"
)

type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	MaxAge           int
	AllowCredentials bool
}

func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{},
		MaxAge:           12 * 3600,
		AllowCredentials: false,
	}
}

func CORS(config ...CORSConfig) gin.HandlerFunc {
	cfg := DefaultCORSConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Origin 处理（安全收紧）：
		//  - 通配 "*" 仅在 **非凭证** 模式下回写；凭证模式下反射任意 Origin 等于任意站点跨域带凭证
		//    访问（CSRF / 数据外泄），故凭证 + 通配时不回写 ACAO（拒绝跨域），用户应配置显式 allowlist。
		//  - 显式 allowlist 走精确匹配，并拒绝 "null" Origin（防 null origin 反射攻击）。
		//  - 拒绝空 Origin（同源请求不携带 Origin 头，无需 CORS 头）。
		if len(cfg.AllowOrigins) > 0 && origin != "" && origin != "null" {
			wildcard := len(cfg.AllowOrigins) == 1 && cfg.AllowOrigins[0] == "*"
			switch {
			case wildcard && !cfg.AllowCredentials:
				c.Header("Access-Control-Allow-Origin", "*")
			case wildcard && cfg.AllowCredentials:
				// 规范禁止 "*" + credentials，且反射任意 origin 是高危——保持不回写 ACAO。
			case contains(cfg.AllowOrigins, origin):
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}
		}

		if len(cfg.AllowMethods) > 0 {
			c.Header("Access-Control-Allow-Methods", strings.Join(cfg.AllowMethods, ", "))
		}
		if len(cfg.AllowHeaders) > 0 {
			c.Header("Access-Control-Allow-Headers", strings.Join(cfg.AllowHeaders, ", "))
		}
		if len(cfg.ExposeHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(cfg.ExposeHeaders, ", "))
		}
		if cfg.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if cfg.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", strconv.Itoa(cfg.MaxAge))
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func contains(s []string, e string) bool {
	return slices.Contains(s, e)
}
