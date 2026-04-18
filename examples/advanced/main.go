package main

import (
	"context"
	"fmt"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
	"github.com/darkit/gin/pkg/routes"
)

// Product 产品结构
type Product struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Price float64 `json:"price"`
}

// ProductController RESTful 资源控制器
type ProductController struct{}

func (ctrl *ProductController) Index(c *gin.Context) {
	products := []Product{
		{ID: 1, Name: "商品 A", Price: 99.99},
		{ID: 2, Name: "商品 B", Price: 149.99},
		{ID: 3, Name: "商品 C", Price: 199.99},
	}
	c.Paginated(products, 1, 10, 3)
}

func (ctrl *ProductController) Show(c *gin.Context) {
	id := c.ParamInt("id")
	product := Product{ID: id, Name: fmt.Sprintf("商品 %d", id), Price: 99.99}
	c.Success(product)
}

func (ctrl *ProductController) Create(c *gin.Context) {
	var product Product
	if err := c.ShouldBindJSON(&product); err != nil {
		c.BadRequest("请求格式错误: " + err.Error())
		return
	}
	product.ID = 100
	c.Created(product)
}

func (ctrl *ProductController) Update(c *gin.Context) {
	id := c.ParamInt("id")
	var product Product
	if err := c.ShouldBindJSON(&product); err != nil {
		c.BadRequest("请求格式错误: " + err.Error())
		return
	}
	product.ID = id
	c.Success(product)
}

func (ctrl *ProductController) Patch(c *gin.Context) {
	id := c.ParamInt("id")
	var updates map[string]any
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.BadRequest("请求格式错误: " + err.Error())
		return
	}
	c.Success(map[string]any{
		"id":      id,
		"updates": updates,
	})
}

func (ctrl *ProductController) Destroy(c *gin.Context) {
	id := c.ParamInt("id")
	c.Logger().Info("删除产品", "id", id)
	c.NoContent()
}

// Order 订单结构
type Order struct {
	ID     int       `json:"id"`
	UserID int       `json:"user_id"`
	Amount float64   `json:"amount"`
	Status string    `json:"status"`
	Time   time.Time `json:"time"`
}

func main() {
	// 创建自定义配置的 Engine
	e := gin.New(
		gin.WithAddr(":8080"),
		gin.WithReadTimeout(30*time.Second),
		gin.WithWriteTimeout(30*time.Second),
		gin.WithGracefulShutdown(10*time.Second),
	)

	// 全局中间件
	e.Use(
		middleware.Recovery(),
		middleware.RequestID(),
		middleware.Logger(),
		middleware.Secure(),
	)

	// 获取 Router
	r := e.Router()

	// ========== API 版本管理 ==========

	// V1 API
	v1 := routes.Version(r, "1")
	{
		// RESTful 资源路由
		routes.Resource(v1, "products", &ProductController{})

		// 自定义路由
		v1.GET("/stats", func(c *gin.Context) {
			c.Success(map[string]any{
				"version": "v1",
				"total":   100,
				"active":  85,
			})
		})
	}

	// V2 API - 不同的实现
	v2 := routes.Version(r, "2")
	{
		v2.GET("/products", func(c *gin.Context) {
			c.Success(map[string]any{
				"version": "v2",
				"message": "V2 产品列表（增强版）",
				"data":    []Product{},
			})
		})

		v2.GET("/stats", func(c *gin.Context) {
			c.Success(map[string]any{
				"version":    "v2",
				"total":      100,
				"active":     85,
				"inactive":   15,
				"new_today":  5,
				"updated_at": time.Now().Unix(),
			})
		})
	}

	// ========== 中间件分组 ==========

	// API 分组 - 应用多个中间件
	api := r.Group("/api")
	api.Use(
		middleware.CORS(middleware.CORSConfig{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
			ExposeHeaders:    []string{"Content-Length"},
			MaxAge:           12 * 3600,
			AllowCredentials: true,
		}),
		middleware.RateLimit(middleware.RateLimitConfig{
			RequestsPerSecond: 10,
			Burst:             20,
		}),
		middleware.Timeout(30*time.Second),
	)

	// 受限流和超时保护的端点
	api.GET("/orders", func(c *gin.Context) {
		// 模拟慢查询
		time.Sleep(100 * time.Millisecond)

		orders := []Order{
			{
				ID:     1,
				UserID: 1,
				Amount: 299.99,
				Status: "completed",
				Time:   time.Now().Add(-24 * time.Hour),
			},
			{
				ID:     2,
				UserID: 1,
				Amount: 499.99,
				Status: "pending",
				Time:   time.Now().Add(-1 * time.Hour),
			},
		}
		c.Paginated(orders, 1, 10, 2)
	})

	// ========== 缓存示例 ==========

	// 缓存端点
	r.GET("/cached", func(c *gin.Context) {
		cache := c.Cache()
		key := "demo_data"

		// 尝试从缓存获取
		if data, err := cache.Get(context.Background(), key); err == nil {
			c.Success(map[string]any{
				"source": "cache",
				"data":   string(data),
			})
			return
		}

		// 缓存未命中，生成数据
		data := fmt.Sprintf("Generated at %s", time.Now().Format(time.RFC3339))
		if err := cache.Set(context.Background(), key, []byte(data), 1*time.Minute); err != nil {
			fmt.Printf("cache set failed: %v\n", err)
		}

		c.Success(map[string]any{
			"source": "generated",
			"data":   data,
		})
	})

	// ========== 日志示例 ==========

	r.POST("/log-demo", func(c *gin.Context) {
		logger := c.Logger()

		var payload map[string]any
		if err := c.ShouldBindJSON(&payload); err != nil {
			logger.Error("解析请求失败", "error", err)
			c.BadRequest("请求格式错误")
			return
		}

		logger.Info("收到请求", "payload", payload)
		logger.Debug("调试信息", "keys", len(payload))

		c.Success(map[string]any{
			"message": "日志已记录",
			"payload": payload,
		})
	})

	// ========== 健康检查 ==========

	routes.HealthCheck(r)

	// 自定义健康检查
	r.GET("/health/detailed", func(c *gin.Context) {
		c.Success(map[string]any{
			"status": "healthy",
			"checks": map[string]any{
				"database": "ok",
				"cache":    "ok",
				"queue":    "ok",
			},
			"uptime":    time.Since(time.Now().Add(-1 * time.Hour)).String(),
			"timestamp": time.Now().Unix(),
		})
	})

	// ========== 认证示例（模拟） ==========

	// 受保护的路由组
	protected := r.Group("/protected")
	protected.Use(authMiddleware(e)) // 自定义认证中间件

	protected.GET("/profile", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		c.Success(map[string]any{
			"user_id": userID,
			"name":    "张三",
			"email":   "zhangsan@example.com",
		})
	})

	// ========== 启动服务 ==========

	fmt.Println("🚀 服务启动在 http://localhost:8080")
	fmt.Println("\n📚 可用端点：")
	fmt.Println("  - GET  /v1/products      - V1 产品列表")
	fmt.Println("  - GET  /v2/products      - V2 产品列表")
	fmt.Println("  - GET  /api/orders       - 订单列表（限流 + 超时）")
	fmt.Println("  - GET  /cached           - 缓存示例")
	fmt.Println("  - POST /log-demo         - 日志示例")
	fmt.Println("  - GET  /health           - 健康检查")
	fmt.Println("  - GET  /protected/profile - 受保护的端点")
	fmt.Println()

	if err := e.Run(); err != nil {
		panic(err)
	}
}

// authMiddleware 模拟认证中间件
func authMiddleware(e *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")

		if token == "" {
			c.Unauthorized("缺少 Authorization 头")
			c.Abort()
			return
		}

		if token != "Bearer valid-token" {
			c.Unauthorized("无效的 token")
			c.Abort()
			return
		}

		// 模拟从 token 解析用户信息
		c.Set("user_id", 1)
		c.Next()
	}
}
