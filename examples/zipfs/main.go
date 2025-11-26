package main

import (
	"log"
	"time"

	"github.com/darkit/gin"
	ginLib "github.com/gin-gonic/gin"
)

func main() {
	// 创建路由器
	router := gin.NewRouter(nil)

	// 示例1: 基础zip文件系统服务
	err := router.SetZipFS("./webapp.zip", "/app")
	if err != nil {
		log.Printf("设置基础zip文件系统失败: %v", err)
	}

	// 示例2: 带热更新的zip文件系统
	err = router.SetZipFS("./assets.zip", "/static",
		gin.WithHotReload(2*time.Second),
		gin.WithIndexFile("app.html"),
	)
	if err != nil {
		log.Printf("设置带热更新的zip文件系统失败: %v", err)
	}

	// 示例3: 子路径限制的zip文件系统
	err = router.SetZipFS("./resources.zip", "/res",
		gin.WithSubPaths("/images", "/css", "/js"),
		gin.WithHotReload(5*time.Second),
	)
	if err != nil {
		log.Printf("设置子路径限制的zip文件系统失败: %v", err)
	}

	// 示例4: 单个zip文件服务
	err = router.SetZipFile("/api/docs", "./docs.zip", "api.json",
		gin.WithFileHotReload(3*time.Second),
		gin.WithContentType("application/json"),
	)
	if err != nil {
		log.Printf("设置单个zip文件失败: %v", err)
	}

	// 示例5: 带中间件的zip文件系统
	config := gin.NewZipFSConfig("./admin.zip", "/admin",
		gin.WithHotReload(3*time.Second),
		gin.WithIndexFile("dashboard.html"),
	)
	err = router.SetZipFSWithMiddleware(config,
		func(c *ginLib.Context) {
			corsMiddleware()(newGinContext(c))
		},
		func(c *ginLib.Context) {
			authMiddleware()(newGinContext(c))
		},
	)
	if err != nil {
		log.Printf("设置带中间件的zip文件系统失败: %v", err)
	}

	// 示例6: 路由组zip文件系统
	apiGroup := router.Group("/api/v1")
	err = apiGroup.SetZipFS("./api-docs.zip",
		gin.WithHotReload(5*time.Second),
	)
	if err != nil {
		log.Printf("设置路由组zip文件系统失败: %v", err)
	}

	// 示例7: 路由组单个文件
	err = apiGroup.SetZipFile("/schema", "./schemas.zip", "openapi.yaml",
		gin.WithFileHotReload(3*time.Second),
		gin.WithContentType("text/yaml"),
	)
	if err != nil {
		log.Printf("设置路由组单个文件失败: %v", err)
	}

	// 示例8: 密码保护的zip文件系统
	err = router.SetZipFS("./protected.zip", "/secure",
		gin.WithPassword("mySecretPassword"),
		gin.WithHotReload(5*time.Second),
		gin.WithIndexFile("protected.html"),
	)
	if err != nil {
		log.Printf("设置密码保护的zip文件系统失败: %v", err)
	}

	// 示例9: 密码保护的单个zip文件
	err = router.SetZipFile("/secure/config", "./config.zip", "secret.json",
		gin.WithFilePassword("configPassword123"),
		gin.WithFileHotReload(3*time.Second),
		gin.WithContentType("application/json"),
	)
	if err != nil {
		log.Printf("设置密码保护的单个zip文件失败: %v", err)
	}

	// 添加一些API路由
	setupAPIRoutes(router)

	log.Println("服务器启动在 http://localhost:8080")
	log.Println("访问示例:")
	log.Println("  http://localhost:8080/app/         - 基础zip文件系统")
	log.Println("  http://localhost:8080/static/      - 带热更新的zip文件系统")
	log.Println("  http://localhost:8080/res/         - 子路径限制的zip文件系统")
	log.Println("  http://localhost:8080/api/docs     - 单个zip文件")
	log.Println("  http://localhost:8080/admin/       - 带中间件的zip文件系统")
	log.Println("  http://localhost:8080/api/v1/      - 路由组zip文件系统")
	log.Println("  http://localhost:8080/api/v1/schema - 路由组单个文件")
	log.Println("  http://localhost:8080/secure/      - 密码保护的zip文件系统")
	log.Println("  http://localhost:8080/secure/config - 密码保护的单个zip文件")

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

// newGinContext 将gin上下文包装为我们框架的上下文
func newGinContext(c *ginLib.Context) *gin.Context {
	return &gin.Context{Context: c}
}

// setupAPIRoutes 设置API路由
func setupAPIRoutes(router *gin.Router) {
	// 健康检查
	router.Health("/health")

	// API路由组
	api := router.Group("/api")
	{
		api.GET("/version", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"version": "1.0.0",
				"features": []string{
					"zip文件系统支持",
					"热更新机制",
					"中间件集成",
					"路由组支持",
				},
			})
		})

		// 示例zip文件创建API（用于演示）
		api.POST("/create-demo-zip", createDemoZip)
	}
}

// corsMiddleware CORS中间件示例
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Method() == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// authMiddleware 认证中间件示例
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 简单的认证检查示例
		token := c.GetHeader("Authorization")
		if token == "" {
			// 对于演示，允许无token访问
			log.Printf("访问管理页面无token: %s", c.Request.URL.Path)
		} else {
			log.Printf("访问管理页面有token: %s", token)
		}
		c.Next()
	}
}

// createDemoZip 创建演示zip文件
func createDemoZip(c *gin.Context) {
	// 这里可以实现创建演示zip文件的逻辑
	// 为简化示例，直接返回成功信息
	c.JSON(200, gin.H{
		"message": "演示zip文件创建功能",
		"tips": []string{
			"你可以手动创建zip文件来测试功能",
			"支持的文件类型: HTML, CSS, JS, 图片等",
			"热更新会自动检测文件变化",
		},
		"examples": gin.H{
			"webapp.zip": []string{
				"index.html",
				"style.css",
				"script.js",
			},
			"assets.zip": []string{
				"images/logo.png",
				"css/main.css",
				"js/app.js",
			},
		},
	})
}
