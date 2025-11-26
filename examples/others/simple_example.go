package others

import (
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/cache"
	"github.com/darkit/gin/pkg/sse"
)

// ExampleOptimizedAPI 演示新的优化API使用方式
func ExampleOptimizedAPI() {
	// 方式1: 使用新的选项模式API（推荐）
	router := gin.NewRouter(
		gin.WithGinMode("debug"),
		gin.WithCache(&cache.Config{
			TTL:             30 * time.Minute,
			CleanupInterval: 5 * time.Minute,
		}),
		gin.WithSSE(&sse.Config{
			HistorySize:  1000,
			PingInterval: 30 * time.Second,
		}),
	)

	// 方式2: 兼容旧的API调用方式
	// router := gin.NewRouter(nil)

	// 简洁的路由注册
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "ok",
			"timestamp": time.Now(),
		})
	})

	// 路由组使用
	api := router.Group("/api/v1")
	{
		users := api.Group("/users")
		{
			users.GET("", func(c *gin.Context) {
				c.JSON(200, gin.H{"users": []string{"Alice", "Bob"}})
			})
			users.POST("", func(c *gin.Context) {
				c.JSON(201, gin.H{"message": "用户创建成功"})
			})
			users.GET("/:id", func(c *gin.Context) {
				id := c.Param("id")
				c.JSON(200, gin.H{"id": id, "name": "User " + id})
			})
		}
	}

	// 启动服务器
	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

// ExampleMigration 演示传统API向新API的迁移
func ExampleMigration() {
	// 传统方式（仍然支持）
	// engine := gin.New()
	// router := gin.NewRouter(engine)

	// 新的简洁方式
	router := gin.NewRouter(
		gin.WithGinMode("release"),
		gin.WithCache(nil), // 使用默认缓存配置
	)

	router.GET("/old-style", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "传统风格路由"})
	})

	router.GET("/new-style", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "新风格路由"})
	})

	if err := router.Run(":8081"); err != nil {
		panic(err)
	}
}
