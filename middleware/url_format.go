package middleware

import (
	"strings"

	"github.com/darkit/gin"
)

const (
	// URLFormatKey 是存储 URL 格式的 Context 键
	URLFormatKey = "middleware.urlformat"
)

// URLFormat 解析 URL 扩展名中间件
//
// 从请求路径中提取扩展名（如 .json, .xml）并存储到 Context 中。
//
// 重要说明:
//   - 此中间件仅解析和存储格式，不影响路由匹配
//   - 路由定义应使用通配符或参数匹配带扩展名的路径
//   - 例如: router.GET("/articles/:id") 可以匹配 "/articles/123.json"
//
// 使用场景:
//   - 支持多种响应格式（JSON/XML/HTML）
//   - 内容协商的替代方案
//   - RESTful API 版本控制
//
// 使用示例:
//
//	router.Use(middleware.URLFormat())
//
//	// 方式1：使用参数匹配（推荐）
//	router.GET("/articles/:id", func(c *gin.Context) {
//	    format := middleware.GetURLFormat(c)
//	    id := strings.TrimSuffix(c.Param("id"), "."+format)
//	    // ... 处理请求
//	})
//
//	// 方式2：使用通配符
//	router.GET("/articles/*path", func(c *gin.Context) {
//	    format := middleware.GetURLFormat(c)
//	    // ... 处理请求
//	})
//
// 支持的 URL 格式:
//   - /articles/1        → format = ""
//   - /articles/1.json   → format = "json"
//   - /articles/1.xml    → format = "xml"
//   - /api/users/123.csv → format = "csv"
func URLFormat() gin.HandlerFunc {
	return func(c *gin.Context) {
		var format string
		path := c.Request.URL.Path

		// 查找最后一个点号
		if strings.Contains(path, ".") {
			// 查找最后一个斜杠后的内容
			base := strings.LastIndex(path, "/")
			idx := strings.LastIndex(path[base:], ".")

			if idx > 0 {
				// 计算点号的绝对位置
				idx += base
				format = path[idx+1:]
			}
		}

		// 存储格式到 Context
		c.Set(URLFormatKey, format)

		c.Next()
	}
}

// GetURLFormat 获取 URL 格式
//
// 从 Context 中获取由 URLFormat 中间件解析的格式字符串。
// 如果没有扩展名或中间件未启用，返回空字符串。
//
// 使用示例:
//
//	func handler(c *gin.Context) {
//	    format := middleware.GetURLFormat(c)
//	    if format == "" {
//	        format = "json" // 默认格式
//	    }
//
//	    switch format {
//	    case "json":
//	        c.JSON(200, data)
//	    case "xml":
//	        c.XML(200, data)
//	    case "csv":
//	        c.String(200, toCSV(data))
//	    }
//	}
func GetURLFormat(c *gin.Context) string {
	if format, exists := c.Get(URLFormatKey); exists {
		if str, ok := format.(string); ok {
			return str
		}
	}
	return ""
}

// URLFormatWithFormats 带格式白名单的 URL 格式解析中间件
//
// 只允许指定的格式，其他格式会被忽略。
// 这可以避免将非格式后缀（如 .tar.gz）误识别为格式。
//
// 使用示例:
//
//	// 只允许 json 和 xml 格式
//	router.Use(middleware.URLFormatWithFormats("json", "xml"))
//
//	router.GET("/articles/*path", handler)
//
// 效果:
//   - /articles/1.json    → format = "json"  ✓
//   - /articles/1.xml     → format = "xml"   ✓
//   - /articles/1.tar.gz  → format = ""      ✗ (不在白名单中)
func URLFormatWithFormats(allowedFormats ...string) gin.HandlerFunc {
	allowed := make(map[string]bool)
	for _, format := range allowedFormats {
		allowed[format] = true
	}

	return func(c *gin.Context) {
		var format string
		path := c.Request.URL.Path

		if strings.Contains(path, ".") {
			base := strings.LastIndex(path, "/")
			idx := strings.LastIndex(path[base:], ".")

			if idx > 0 {
				idx += base
				candidateFormat := path[idx+1:]

				// 检查格式是否在白名单中
				if allowed[candidateFormat] {
					format = candidateFormat
				}
			}
		}

		c.Set(URLFormatKey, format)
		c.Next()
	}
}
