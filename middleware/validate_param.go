package middleware

import (
	"regexp"

	"github.com/darkit/gin"
)

// ValidateParam 返回用于校验路由参数格式的中间件。
func ValidateParam(param string, pattern *regexp.Regexp) gin.HandlerFunc {
	return func(c *gin.Context) {
		value := c.Param(param)

		// 参数为空,可能是可选参数,继续执行
		if value == "" {
			c.Next()
			return
		}

		// 验证参数格式
		if !pattern.MatchString(value) {
			c.JSON(400, gin.H{
				"error":  "invalid parameter",
				"param":  param,
				"value":  value,
				"format": pattern.String(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ParamValidator 定义路由参数校验函数，返回是否通过及错误信息。
type ParamValidator func(value string) (bool, string)

// ValidateParamFunc 返回使用自定义校验函数的路由参数中间件。
func ValidateParamFunc(param string, validateFn ParamValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		value := c.Param(param)

		if value == "" {
			c.Next()
			return
		}

		valid, message := validateFn(value)
		if !valid {
			c.JSON(400, gin.H{
				"error":   "invalid parameter",
				"param":   param,
				"value":   value,
				"message": message,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// 常用预定义验证模式。

var (
	// PatternNumeric 匹配纯数字。
	PatternNumeric = regexp.MustCompile(`^\d+$`)

	// PatternAlpha 匹配纯字母。
	PatternAlpha = regexp.MustCompile(`^[a-zA-Z]+$`)

	// PatternAlphanumeric 匹配字母和数字。
	PatternAlphanumeric = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

	// PatternUUID 匹配 UUID 格式 8-4-4-4-12。
	PatternUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	// PatternSlug 匹配 URL 友好的 slug 格式。
	PatternSlug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

	// PatternEmail 匹配邮箱格式（简化版）。
	PatternEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// PatternURL 匹配 URL 格式。
	PatternURL = regexp.MustCompile(`^https?://[^\s]+$`)

	// PatternHex 匹配十六进制。
	PatternHex = regexp.MustCompile(`^[0-9a-fA-F]+$`)

	// PatternBase64 匹配 Base64 编码。
	PatternBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)

	// PatternDate 匹配日期格式 YYYY-MM-DD。
	PatternDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

	// PatternTime 匹配时间格式 HH:MM:SS。
	PatternTime = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}$`)

	// PatternIPv4 匹配 IPv4 地址。
	PatternIPv4 = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)

	// PatternPhone 匹配手机号（中国）。
	PatternPhone = regexp.MustCompile(`^1[3-9]\d{9}$`)

	// PatternUsername 匹配用户名（字母数字下划线，3-20 位）。
	PatternUsername = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)
)
