package middleware

import "github.com/darkit/gin"

// Maybe 条件性中间件执行
// 当 maybeFn 返回 true 时执行 mw,否则跳过该中间件直接执行后续处理
//
// 使用场景:
//   - 仅对特定路径应用中间件
//   - 根据请求头或查询参数动态应用中间件
//   - A/B 测试或功能开关
//
// 使用示例:
//
//	// 仅对 API 路径应用认证
//	router.Use(middleware.Maybe(authMiddleware, func(c *gin.Context) bool {
//	    return strings.HasPrefix(c.Request.URL.Path, "/api/")
//	}))
//
//	// 根据环境变量应用日志
//	router.Use(middleware.Maybe(verboseLogger, func(c *gin.Context) bool {
//	    return os.Getenv("DEBUG") == "true"
//	}))
//
//	// 根据请求头应用 CORS
//	router.Use(middleware.Maybe(corsMiddleware, func(c *gin.Context) bool {
//	    return c.GetHeader("Origin") != ""
//	}))
func Maybe(mw gin.HandlerFunc, maybeFn func(c *gin.Context) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if maybeFn(c) {
			// 条件满足,执行中间件
			mw(c)
		} else {
			// 条件不满足,跳过中间件直接执行后续处理
			c.Next()
		}
	}
}
