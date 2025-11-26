package gin

import (
	"fmt"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestRouterValidationRealWorldExample 真实世界的路由验证示例
func TestRouterValidationRealWorldExample(t *testing.T) {
	t.Run("电商API路由设计", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		output, errorOutput := captureOutputAndError(func() {
			// 用户相关路由
			userAPI := router.Group("/api/v1/users")
			userAPI.GET("", func(c *Context) { c.String(200, "用户列表") })
			userAPI.GET("/:id", func(c *Context) { c.String(200, "用户详情") })
			userAPI.POST("", func(c *Context) { c.String(200, "创建用户") })
			userAPI.PUT("/:id", func(c *Context) { c.String(200, "更新用户") })
			userAPI.DELETE("/:id", func(c *Context) { c.String(200, "删除用户") })

			// 商品相关路由
			productAPI := router.Group("/api/v1/products")
			productAPI.GET("", func(c *Context) { c.String(200, "商品列表") })
			productAPI.GET("/:id", func(c *Context) { c.String(200, "商品详情") })
			productAPI.GET("/:id/reviews", func(c *Context) { c.String(200, "商品评价") })
			productAPI.POST("/:id/reviews", func(c *Context) { c.String(200, "添加评价") })

			// 订单相关路由
			orderAPI := router.Group("/api/v1/orders")
			orderAPI.GET("", func(c *Context) { c.String(200, "订单列表") })
			orderAPI.GET("/:id", func(c *Context) { c.String(200, "订单详情") })
			orderAPI.POST("", func(c *Context) { c.String(200, "创建订单") })
			orderAPI.PUT("/:id/status", func(c *Context) { c.String(200, "更新订单状态") })

			// 文件上传路由
			router.POST("/api/v1/upload/*filepath", func(c *Context) {
				c.String(200, "文件上传")
			})

			// 静态文件服务
			router.GET("/static/*filepath", func(c *Context) {
				c.String(200, "静态文件")
			})

			// 尝试注册一些无效路由
			router.GET("/api/v1/invalid/:123param", func(c *Context) {
				c.String(200, "无效路由")
			})

			// 尝试注册冲突路由
			router.GET("/api/v1/users/:name", func(c *Context) {
				c.String(200, "按名称获取用户")
			})
		})

		// 合并输出和错误输出进行断言
		allOutput := output + errorOutput

		// 验证有效路由注册成功
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v1/users/:id")
		assert.Contains(t, allOutput, "注册路由组路由: PUT /api/v1/users/:id")
		assert.Contains(t, allOutput, "注册路由组路由: DELETE /api/v1/users/:id")
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v1/products/:id")
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v1/products/:id/reviews")
		assert.Contains(t, allOutput, "注册路由组路由: POST /api/v1/products/:id/reviews")
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v1/orders/:id")
		assert.Contains(t, allOutput, "注册路由组路由: PUT /api/v1/orders/:id/status")
		assert.Contains(t, allOutput, "注册路由: POST /api/v1/upload/*filepath")
		assert.Contains(t, allOutput, "注册路由: GET /static/*filepath")

		// 验证无效路由被拒绝
		assert.Contains(t, allOutput, "[GIN-ROUTER] ERROR: 路由注册失败 'GET /api/v1/invalid/:123param'")

		// 验证冲突路由被检测
		assert.Contains(t, allOutput, "[GIN-ROUTER] WARN: 路由冲突检测 'GET /api/v1/users/:name' 与现有路由")

		// 验证路由数量
		routes := router.GetRoutes()
		assert.GreaterOrEqual(t, len(routes), 15) // 应该有至少15个有效路由

		// 验证特定路由存在
		assert.Contains(t, routes, "GET:/api/v1/users")
		assert.Contains(t, routes, "GET:/api/v1/users/:id")
		assert.Contains(t, routes, "POST:/api/v1/users")
		assert.Contains(t, routes, "GET:/api/v1/products/:id/reviews")
		assert.Contains(t, routes, "POST:/api/v1/upload/*filepath")
		assert.Contains(t, routes, "GET:/static/*filepath")

		// 验证无效路由不存在
		assert.NotContains(t, routes, "GET:/api/v1/invalid/:123param")
		assert.NotContains(t, routes, "GET:/api/v1/users/:name")
	})

	t.Run("博客系统路由设计", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		output, errorOutput := captureOutputAndError(func() {
			// 博客文章路由
			blogAPI := router.Group("/blog")
			blogAPI.GET("", func(c *Context) { c.String(200, "博客首页") })
			blogAPI.GET("/posts", func(c *Context) { c.String(200, "文章列表") })
			blogAPI.GET("/posts/:slug", func(c *Context) { c.String(200, "文章详情") })
			blogAPI.GET("/posts/:slug/comments", func(c *Context) { c.String(200, "文章评论") })
			blogAPI.POST("/posts/:slug/comments", func(c *Context) { c.String(200, "添加评论") })

			// 分类和标签路由
			blogAPI.GET("/categories", func(c *Context) { c.String(200, "分类列表") })
			blogAPI.GET("/categories/:name", func(c *Context) { c.String(200, "分类文章") })
			blogAPI.GET("/tags", func(c *Context) { c.String(200, "标签列表") })
			blogAPI.GET("/tags/:name", func(c *Context) { c.String(200, "标签文章") })

			// 管理后台路由
			adminAPI := router.Group("/admin")
			adminAPI.GET("/dashboard", func(c *Context) { c.String(200, "管理面板") })
			adminAPI.Resource("/posts", &RestfulHandler{})
			adminAPI.Resource("/users", &RestfulHandler{})

			// RSS和搜索
			router.GET("/rss.xml", func(c *Context) { c.String(200, "RSS订阅") })
			router.GET("/search", func(c *Context) { c.String(200, "搜索") })

			// 尝试一些边界情况
			router.GET("/blog/posts/:slug/comments/:comment_id", func(c *Context) {
				c.String(200, "评论详情")
			})

			// 无效的路由模式
			router.GET("/blog/posts/:slug/invalid/*path/more", func(c *Context) {
				c.String(200, "无效路由")
			})
		})

		// 合并输出和错误输出进行断言
		allOutput := output + errorOutput

		// 验证博客路由注册
		assert.Contains(t, allOutput, "注册路由组路由: GET /blog/posts/:slug")
		assert.Contains(t, allOutput, "注册路由组路由: GET /blog/posts/:slug/comments")
		assert.Contains(t, allOutput, "注册路由组路由: POST /blog/posts/:slug/comments")
		assert.Contains(t, allOutput, "注册路由组路由: GET /blog/categories/:name")
		assert.Contains(t, allOutput, "注册路由组路由: GET /blog/tags/:name")

		// 验证管理后台资源路由
		assert.Contains(t, allOutput, "注册路由组路由: GET /admin/posts/:id")
		assert.Contains(t, allOutput, "注册路由组路由: PUT /admin/posts/:id")
		assert.Contains(t, allOutput, "注册路由组路由: DELETE /admin/posts/:id")
		assert.Contains(t, allOutput, "注册路由组路由: GET /admin/users/:id")

		// 验证复杂参数路由
		assert.Contains(t, allOutput, "注册路由: GET /blog/posts/:slug/comments/:comment_id")

		// 验证无效路由被拒绝
		assert.Contains(t, allOutput, "[GIN-ROUTER] ERROR: 路由注册失败")
		assert.Contains(t, allOutput, "必须是路径的最后一个段")

		routes := router.GetRoutes()
		assert.Greater(t, len(routes), 20) // 博客系统应该有很多路由

		// 验证关键路由存在
		assert.Contains(t, routes, "GET:/blog/posts/:slug")
		assert.Contains(t, routes, "GET:/blog/posts/:slug/comments/:comment_id")
		assert.Contains(t, routes, "GET:/admin/posts/:id")
		assert.Contains(t, routes, "POST:/admin/posts")
		assert.Contains(t, routes, "GET:/rss.xml")
		assert.Contains(t, routes, "GET:/search")

		// 验证无效路由不存在
		assert.NotContains(t, routes, "GET:/blog/posts/:slug/invalid/*path/more")
	})

	t.Run("API版本控制和命名空间", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		output, errorOutput := captureOutputAndError(func() {
			// API v1
			v1 := router.Group("/api/v1")
			v1.GET("/users/:id", func(c *Context) { c.String(200, "v1 用户") })
			v1.GET("/products/:id", func(c *Context) { c.String(200, "v1 商品") })

			// API v2 - 新版本
			v2 := router.Group("/api/v2")
			v2.GET("/users/:id", func(c *Context) { c.String(200, "v2 用户") })
			v2.GET("/users/:id/profile", func(c *Context) { c.String(200, "v2 用户资料") })
			v2.GET("/products/:id", func(c *Context) { c.String(200, "v2 商品") })
			v2.GET("/products/:id/variants", func(c *Context) { c.String(200, "v2 商品变体") })

			// 移动端专用API
			mobile := router.Group("/mobile/api")
			mobile.GET("/users/:id", func(c *Context) { c.String(200, "移动端用户") })
			mobile.GET("/products/:id", func(c *Context) { c.String(200, "移动端商品") })

			// 内部API
			internal := router.Group("/internal")
			internal.GET("/health", func(c *Context) { c.String(200, "健康检查") })
			internal.GET("/metrics", func(c *Context) { c.String(200, "指标") })
			internal.GET("/debug/*path", func(c *Context) { c.String(200, "调试信息") })

			// 尝试注册一些可能冲突的路由
			router.GET("/api/:version/users/:id", func(c *Context) {
				c.String(200, "动态版本用户")
			})
		})

		// 合并输出和错误输出进行断言
		allOutput := output + errorOutput

		// 验证不同版本的路由都注册成功
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v1/users/:id")
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v1/products/:id")
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v2/users/:id")
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v2/users/:id/profile")
		assert.Contains(t, allOutput, "注册路由组路由: GET /api/v2/products/:id/variants")
		assert.Contains(t, allOutput, "注册路由组路由: GET /mobile/api/users/:id")
		assert.Contains(t, allOutput, "注册路由组路由: GET /internal/debug/*path")
		// 动态版本路由因为冲突被拒绝了
		assert.Contains(t, allOutput, "[GIN-ROUTER] WARN: 路由冲突检测 'GET /api/:version/users/:id'")

		routes := router.GetRoutes()

		// 验证所有版本的路由都存在且不冲突
		assert.Contains(t, routes, "GET:/api/v1/users/:id")
		assert.Contains(t, routes, "GET:/api/v2/users/:id")
		assert.Contains(t, routes, "GET:/mobile/api/users/:id")
		assert.Contains(t, routes, "GET:/internal/debug/*path")

		// 动态版本路由因为冲突被拒绝，所以不应该存在
		assert.NotContains(t, routes, "GET:/api/:version/users/:id")

		// 验证路由数量合理
		assert.Greater(t, len(routes), 10)
	})
}

// TestRouterValidationPerformanceImpact 测试验证功能对性能的影响
func TestRouterValidationPerformanceImpact(t *testing.T) {
	// 重定向输出以避免测试中的打印影响
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	t.Run("大量路由注册性能", func(t *testing.T) {
		router := NewRouter(nil)

		// 注册1000个不同的路由
		for i := 0; i < 1000; i++ {
			router.GET(fmt.Sprintf("/api/v1/resource%d/:id", i), func(c *Context) {
				c.String(200, "test")
			})
		}

		routes := router.GetRoutes()
		assert.Equal(t, 1000, len(routes))
	})

	t.Run("冲突检测性能", func(t *testing.T) {
		router := NewRouter(nil)

		// 先注册一个路由
		router.GET("/users/:id", func(c *Context) {
			c.String(200, "user")
		})

		// 尝试注册100个冲突的路由
		for i := 0; i < 100; i++ {
			router.GET(fmt.Sprintf("/users/:param%d", i), func(c *Context) {
				c.String(200, "conflict")
			})
		}

		routes := router.GetRoutes()
		assert.Equal(t, 1, len(routes)) // 只有第一个路由被注册
	})
}

// BenchmarkRouterValidationRealWorld 真实世界场景的基准测试
func BenchmarkRouterValidationRealWorld(b *testing.B) {
	// 重定向输出以避免基准测试中的打印影响
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.Run("电商API路由注册", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			router := NewRouter(nil)

			// 模拟电商API路由注册
			userAPI := router.Group("/api/v1/users")
			userAPI.GET("", func(c *Context) {})
			userAPI.GET("/:id", func(c *Context) {})
			userAPI.POST("", func(c *Context) {})
			userAPI.PUT("/:id", func(c *Context) {})
			userAPI.DELETE("/:id", func(c *Context) {})

			productAPI := router.Group("/api/v1/products")
			productAPI.GET("", func(c *Context) {})
			productAPI.GET("/:id", func(c *Context) {})
			productAPI.GET("/:id/reviews", func(c *Context) {})
			productAPI.POST("/:id/reviews", func(c *Context) {})

			orderAPI := router.Group("/api/v1/orders")
			orderAPI.GET("", func(c *Context) {})
			orderAPI.GET("/:id", func(c *Context) {})
			orderAPI.POST("", func(c *Context) {})
			orderAPI.PUT("/:id/status", func(c *Context) {})

			router.POST("/api/v1/upload/*filepath", func(c *Context) {})
			router.GET("/static/*filepath", func(c *Context) {})
		}
	})

	b.Run("复杂路由模式验证", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			router := NewRouter(nil)

			// 复杂的路由模式
			router.GET("/api/:version/users/:userId/posts/:postId/comments/:commentId/*action", func(c *Context) {})
			router.GET("/blog/:year/:month/:day/:slug", func(c *Context) {})
			router.GET("/files/:category/*filepath", func(c *Context) {})
			router.GET("/admin/users/:id/permissions/:permission/roles/:role", func(c *Context) {})
		}
	})
}
