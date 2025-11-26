package main

import (
	"log"
	"time"

	gin "github.com/darkit/gin"
)

func main() {
	// 创建路由器，启用JWT支持
	router := gin.NewRouter(
		gin.Default(),
		// JWT配置已移至 SecurityConfig，请参考 main.go 示例
	)

	// 添加OAuth认证路由 - 自动创建 /oauth/token, /oauth/refresh, /oauth/userinfo, /oauth/revoke 端点
	router.OAuth()

	// 自定义登录端点（可选，覆盖默认实现）
	router.POST("/login", func(c *gin.Context) {
		var loginReq struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginReq); err != nil {
			c.ValidationError(gin.H{"error": "请求参数错误"})
			return
		}

		// 实际应用中这里应该验证数据库中的用户密码
		if loginReq.Username == "admin" && loginReq.Password == "password" {
			// 创建用户声明
			userClaims := gin.UserClaims{
				UserID:   "user123",
				Username: "admin",
				Email:    "admin@example.com",
				Roles:    []string{"admin", "user"},
				Scope:    "read write admin",
			}

			// 自定义OAuth配置
			config := &gin.OAuthConfig{
				AccessTokenTTL:  30 * time.Minute,    // 访问令牌30分钟过期
				RefreshTokenTTL: 30 * 24 * time.Hour, // 刷新令牌30天过期
				Issuer:          "my-app",
				DefaultScope:    "read",
			}

			// 生成令牌对
			tokens, err := c.GenerateTokens(userClaims, config)
			if err != nil {
				c.ServerError("生成令牌失败: " + err.Error())
				return
			}

			c.Success(tokens)
		} else {
			c.Unauthorized("用户名或密码错误")
		}
	})

	// 需要认证的API端点
	api := router.Group("/api")
	{
		// 需要基本认证的端点
		api.GET("/profile", func(c *gin.Context) {
			payload := c.GetJWTPayload()
			c.Success(gin.H{
				"message": "这是受保护的用户资料",
				"user":    payload,
			})
		}, router.RequireAuth())

		// 需要特定权限的端点
		api.GET("/admin", func(c *gin.Context) {
			payload := c.GetJWTPayload()
			c.Success(gin.H{
				"message": "这是管理员专用端点",
				"user":    payload,
			})
		}, router.RequireAuth("admin"))

		// 需要多个权限的端点
		api.POST("/users", func(c *gin.Context) {
			payload := c.GetJWTPayload()
			c.Success(gin.H{
				"message": "创建用户成功",
				"user":    payload,
			})
		}, router.RequireAuth("write", "admin"))
	}

	// 公开端点
	router.GET("/public", func(c *gin.Context) {
		c.Success(gin.H{
			"message": "这是公开端点，无需认证",
			"time":    time.Now(),
		})
	})

	// 启动服务器
	log.Println("OAuth认证服务器启动在 :8080")
	log.Println()
	log.Println("🔐 OAuth端点:")
	log.Println("  POST /oauth/token    - 获取令牌 (用户名密码登录)")
	log.Println("  POST /oauth/refresh  - 刷新令牌")
	log.Println("  GET  /oauth/userinfo - 获取用户信息 (需要认证)")
	log.Println("  POST /oauth/revoke   - 撤销令牌")
	log.Println()
	log.Println("🔑 自定义端点:")
	log.Println("  POST /login          - 自定义登录")
	log.Println()
	log.Println("🛡️  受保护的API:")
	log.Println("  GET  /api/profile    - 用户资料 (需要认证)")
	log.Println("  GET  /api/admin      - 管理员端点 (需要admin权限)")
	log.Println("  POST /api/users      - 创建用户 (需要write+admin权限)")
	log.Println()
	log.Println("🌐 公开端点:")
	log.Println("  GET  /public         - 公开访问")
	log.Println()
	log.Println("📝 使用示例:")
	log.Println("  1. 登录获取令牌:")
	log.Println("     curl -X POST http://localhost:8080/oauth/token \\")
	log.Println("          -H 'Content-Type: application/json' \\")
	log.Println("          -d '{\"username\":\"admin\",\"password\":\"password\"}'")
	log.Println()
	log.Println("  2. 使用令牌访问受保护资源:")
	log.Println("     curl -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \\")
	log.Println("          http://localhost:8080/api/profile")
	log.Println()
	log.Println("  3. 刷新令牌:")
	log.Println("     curl -X POST http://localhost:8080/oauth/refresh \\")
	log.Println("          -H 'Content-Type: application/json' \\")
	log.Println("          -d '{\"refresh_token\":\"YOUR_REFRESH_TOKEN\"}'")

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}
