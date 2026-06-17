package main

import (
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
)

// ==================== 基础控制器示例 ====================

// HelloController 基础控制器（不带 Controller 后缀）
type Hello struct{}

// GetTest 标准路由：GET /hello/test
func (h *Hello) GetTest(c *gin.Context) {
	c.Success(gin.H{"message": "test endpoint"})
}

// PostLogin 标准路由：POST /hello/login
func (h *Hello) PostLogin(c *gin.Context) {
	c.Created(gin.H{"token": "mock-jwt-token"})
}

// GetUserProfile 驼峰转路径：GET /hello/user/profile
func (h *Hello) GetUserProfile(c *gin.Context) {
	c.Success(gin.H{"profile": "user profile data"})
}

// GetUserIDRegex 正则路由（默认推断）：GET /hello/user/{id:[0-9]+}
func (h *Hello) GetUserIDRegex(c *gin.Context) {
	id := c.Param("id")
	c.Success(gin.H{"id": id, "source": "default pattern inference"})
}

// ==================== 接口实现示例 ====================

// UserController 使用 RegexPatternProvider 接口自定义正则模式
type User struct{}

// RegexPatterns 实现 RegexPatternProvider 接口（优先级 2）
func (u *User) RegexPatterns() map[string]string {
	return map[string]string{
		// 自定义 email 正则
		"GetByEmailRegex": "/user/by/{email:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}}",
		// 多参数路由
		"GetOrdersDateRegex": "/user/orders/{year:[0-9]{4}}/{month:[0-9]{2}}",
		// UUID 路由
		"GetByUUIDRegex": "/user/by/{uuid:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}}",
	}
}

// GetList 标准路由：GET /user/list
func (u *User) GetList(c *gin.Context) {
	users := []gin.H{
		{"id": 1, "name": "张三", "email": "zhangsan@example.com"},
		{"id": 2, "name": "李四", "email": "lisi@example.com"},
	}
	c.Success(gin.H{"users": users, "total": 2})
}

// GetByEmailRegex 正则路由（接口配置）：GET /user/by/{email:正则}
func (u *User) GetByEmailRegex(c *gin.Context) {
	email := c.Param("email")
	c.Success(gin.H{
		"email":  email,
		"source": "RegexPatternProvider interface",
	})
}

// GetOrdersDateRegex 正则路由（接口配置）：GET /user/orders/{year}/{month}
func (u *User) GetOrdersDateRegex(c *gin.Context) {
	year := c.Param("year")
	month := c.Param("month")
	c.Success(gin.H{
		"year":   year,
		"month":  month,
		"source": "RegexPatternProvider interface",
	})
}

// GetByUUIDRegex 正则路由（接口配置）：GET /user/by/{uuid}
func (u *User) GetByUUIDRegex(c *gin.Context) {
	uuid := c.Param("uuid")
	c.Success(gin.H{
		"uuid":   uuid,
		"source": "RegexPatternProvider interface",
	})
}

// ==================== 选项覆盖示例 ====================

// ArticleController 使用注册选项覆盖正则模式
type Article struct{}

// GetBySlugRegex 正则路由：将通过 WithRegexPattern 覆盖路径
func (a *Article) GetBySlugRegex(c *gin.Context) {
	slug := c.Param("slug")
	c.Success(gin.H{
		"slug":   slug,
		"source": "WithRegexPattern option (highest priority)",
	})
}

// GetByTagRegex 正则路由：将通过选项定义多标签路由
func (a *Article) GetByTagRegex(c *gin.Context) {
	tag := c.Param("tag")
	c.Success(gin.H{
		"tag":    tag,
		"source": "WithRegexPattern option",
	})
}

// ==================== 自定义前缀示例 ====================

// AdminController 实现 AutoController 接口自定义前缀
type Admin struct{}

// RoutePrefix 实现 AutoController 接口
func (a *Admin) RoutePrefix() string {
	return "/admin/dashboard"
}

// GetStats 标准路由：GET /admin/dashboard/stats
func (a *Admin) GetStats(c *gin.Context) {
	c.Success(gin.H{
		"users":    1234,
		"articles": 567,
		"comments": 8901,
	})
}

// ==================== 认证中间件示例 ====================

func authMiddleware(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.Unauthorized("缺少 Authorization 头")
		c.Abort()
		return
	}
	// 简单验证（实际应验证 JWT）
	if token != "Bearer mock-token" {
		c.Forbidden("无效的 token")
		c.Abort()
		return
	}
	c.Next()
}

// ==================== 主函数 ====================

func main() {
	// 创建 Engine
	e := gin.Default(
		gin.WithAddr(":8080"),
		gin.WithReadTimeout(30*time.Second),
		gin.WithWriteTimeout(30*time.Second),
		gin.WithGracefulShutdown(10*time.Second),
	)

	// 全局中间件
	e.Use(middleware.CORS())

	// 获取 Router
	r := e.Router()

	// ==================== 1. 基础自动注册 ====================
	r.AutoRegister(&Hello{})
	// 生成路由:
	// GET  /hello/test         → Hello.GetTest
	// POST /hello/login        → Hello.PostLogin
	// GET  /hello/user/profile → Hello.GetUserProfile
	// GET  /hello/user/{id:[0-9]+} → Hello.GetUserIDRegex (正则，默认推断)

	// ==================== 2. 接口实现注册 ====================
	r.AutoRegister(&User{})
	// 生成路由:
	// GET /user/list                   → User.GetList
	// GET /user/by/{email:正则}        → User.GetByEmailRegex (接口配置)
	// GET /user/orders/{year}/{month} → User.GetOrdersDateRegex (接口配置)
	// GET /user/by/{uuid}             → User.GetByUUIDRegex (接口配置)

	// ==================== 3. 选项覆盖注册（优先级最高） ====================
	r.AutoRegister(
		&Article{},
		gin.WithPrefix("/api/v1/articles"),
		gin.WithRegexPattern("GetBySlugRegex", "/api/v1/articles/by/{slug:[a-z0-9]+(?:-[a-z0-9]+)*}"),
		gin.WithRegexPattern("GetByTagRegex", "/api/v1/articles/by/tag/{tag:[a-zA-Z0-9-]+}"),
	)
	// 生成路由:
	// GET /api/v1/articles/by/{slug:正则}       → Article.GetBySlugRegex (选项覆盖)
	// GET /api/v1/articles/by/tag/{tag:正则}   → Article.GetByTagRegex (选项覆盖)

	// ==================== 4. 带中间件注册 ====================
	r.AutoRegister(
		&Admin{},
		gin.WithMiddleware(authMiddleware, middleware.RateLimit(middleware.RateLimitConfig{
			RequestsPerSecond: 10,
			Burst:             20,
		})),
	)
	// 生成路由:
	// GET /admin/dashboard/stats → Admin.GetStats (带认证和限流)

	// ==================== 5. 手动正则路由（对比） ====================
	rx := e.RegexRouter()
	rx.GET("/manual/{id:[0-9]+}", func(c *gin.Context) {
		id := c.Param("id")
		c.Success(gin.H{
			"id":     id,
			"source": "manual RegexRouter registration",
		})
	})

	// ==================== 打印所有路由 ====================
	println("\n========== 自动注册路由示例 ==========")
	println("\n【基础路由】")
	println("GET  http://localhost:8080/hello/test")
	println("POST http://localhost:8080/hello/login")
	println("GET  http://localhost:8080/hello/user/profile")
	println("\n【正则路由 - 默认推断】")
	println("GET  http://localhost:8080/hello/user/123")
	println("\n【正则路由 - 接口配置】")
	println("GET  http://localhost:8080/user/list")
	println("GET  http://localhost:8080/user/by/test@example.com")
	println("GET  http://localhost:8080/user/orders/2024/12")
	println("GET  http://localhost:8080/user/by/550e8400-e29b-41d4-a716-446655440000")
	println("\n【正则路由 - 选项覆盖】")
	println("GET  http://localhost:8080/api/v1/articles/by/hello-world")
	println("GET  http://localhost:8080/api/v1/articles/by/tag/golang")
	println("\n【带中间件路由（需认证）】")
	println("GET  http://localhost:8080/admin/dashboard/stats")
	println("     Header: Authorization: Bearer mock-token")
	println("\n【手动正则路由】")
	println("GET  http://localhost:8080/manual/456")
	println("\n=======================================\n")

	// 启动服务
	println("服务启动在 :8080...")
	if err := e.Run(); err != nil {
		panic(err)
	}
}
