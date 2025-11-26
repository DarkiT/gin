package main

import (
	"log"
	"time"

	gin "github.com/darkit/gin"
)

func main() {
	// 创建支持JWT的路由器
	router := gin.NewRouter(
		gin.Default(),
		// JWT配置已移至 SecurityConfig，请参考 main.go 示例
	)

	// 添加OAuth认证路由
	router.OAuth()

	// 演示令牌撤销的测试端点
	router.POST("/demo/login", func(c *gin.Context) {
		// 模拟用户登录
		userClaims := gin.UserClaims{
			UserID:   "demo123",
			Username: "demo_user",
			Email:    "demo@example.com",
			Roles:    []string{"user"},
			Scope:    "read write",
		}

		tokens, err := c.GenerateTokens(userClaims)
		if err != nil {
			c.ServerError("生成令牌失败: " + err.Error())
			return
		}

		c.Success(gin.H{
			"message": "登录成功",
			"tokens":  tokens,
			"notice":  "请保存access_token和refresh_token用于后续测试",
		})
	})

	// 受保护的测试端点
	router.GET("/demo/protected", func(c *gin.Context) {
		payload := c.GetJWTPayload()
		jti, _ := payload.GetClaim("jti")

		c.Success(gin.H{
			"message":     "这是受保护的资源",
			"user_info":   payload,
			"token_jti":   jti,
			"access_time": time.Now().Unix(),
		})
	}, router.RequireAuth())

	// 测试撤销后的访问
	router.GET("/demo/test-revoked", func(c *gin.Context) {
		c.Success(gin.H{
			"message": "如果看到这条消息，说明令牌未被撤销",
			"time":    time.Now().Unix(),
		})
	}, router.RequireAuth())

	// 批量撤销令牌的测试端点（管理员功能）
	router.POST("/demo/admin/revoke-all", func(c *gin.Context) {
		var req struct {
			UserID string `json:"user_id" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.ValidationError(gin.H{"error": "请求参数错误"})
			return
		}

		// 实际应用中，这里可以查询数据库中该用户的所有活跃令牌并撤销
		// 这里只是演示概念
		c.Success(gin.H{
			"message": "已撤销用户所有令牌",
			"user_id": req.UserID,
			"note":    "实际应用中需要实现用户令牌管理机制",
		})
	}, router.RequireAuth("admin"))

	log.Println("🔐 令牌撤销功能演示服务器启动在 :8080")
	log.Println()
	log.Println("📋 测试步骤:")
	log.Println("1. 获取令牌:")
	log.Println("   curl -X POST http://localhost:8080/demo/login")
	log.Println()
	log.Println("2. 使用令牌访问受保护资源:")
	log.Println("   curl -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \\")
	log.Println("        http://localhost:8080/demo/protected")
	log.Println()
	log.Println("3. 撤销令牌:")
	log.Println("   curl -X POST http://localhost:8080/oauth/revoke \\")
	log.Println("        -H 'Content-Type: application/json' \\")
	log.Println("        -d '{\"token\":\"YOUR_ACCESS_TOKEN\"}'")
	log.Println()
	log.Println("4. 再次尝试访问受保护资源（应该失败）:")
	log.Println("   curl -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \\")
	log.Println("        http://localhost:8080/demo/test-revoked")
	log.Println()
	log.Println("💡 注意:")
	log.Println("   - 撤销access_token后，该令牌将立即失效")
	log.Println("   - 撤销refresh_token后，无法再刷新获取新令牌")
	log.Println("   - 令牌撤销信息会持久化存储")
	log.Println("   - JWT管理器会自动清理过期的撤销记录")

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}
