package middleware

import (
	"net/http"
	"time"

	"github.com/darkit/gin"
)

// Sunset 设置 API 废弃通知头 (RFC 8594)
// 用于通知客户端 API 即将废弃的时间和替代资源
//
// RFC 8594: https://www.rfc-editor.org/rfc/rfc8594.html
//
// 响应头说明:
//   - Sunset: API 停止服务的时间 (HTTP-date 格式)
//   - Deprecation: 同 Sunset,表示废弃时间
//   - Link: 指向替代资源或迁移指南的链接
//
// 使用场景:
//   - API 版本升级
//   - 端点废弃通知
//   - 服务迁移公告
//
// 使用示例:
//
//	// 单个废弃端点
//	v1Group := router.Group("/v1")
//	v1Group.Use(middleware.Sunset(
//	    time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
//	    "<https://api.example.com/v2>; rel=\"successor-version\"",
//	))
//
//	// 带迁移指南的废弃通知
//	v1Users := router.Group("/v1/users")
//	v1Users.Use(middleware.Sunset(
//	    time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
//	    "<https://api.example.com/v2/users>; rel=\"successor-version\"",
//	    "<https://docs.example.com/migration>; rel=\"alternate\"; type=\"text/html\"",
//	))
//
//	// 不设置 Sunset 时间(仅通知已废弃)
//	oldAPI := router.Group("/old-api")
//	oldAPI.Use(middleware.Sunset(time.Time{})) // 零值表示不设置时间
func Sunset(sunsetAt time.Time, links ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !sunsetAt.IsZero() {
			// 设置 Sunset 和 Deprecation 头
			// 使用 HTTP-date 格式 (RFC 7231)
			httpDate := sunsetAt.Format(http.TimeFormat)
			c.Header("Sunset", httpDate)
			c.Header("Deprecation", httpDate)

			// 添加 Link 头指向替代资源
			for _, link := range links {
				c.Writer.Header().Add("Link", link)
			}
		}

		c.Next()
	}
}
