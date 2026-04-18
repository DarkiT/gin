package main

import (
	"fmt"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
	"github.com/darkit/gin/pkg/diagnostic"
	"github.com/darkit/gin/pkg/routes"
)

// ProductController RESTful 资源控制器
type ProductController struct{}

func (ctrl *ProductController) Index(c *gin.Context)   { c.Success([]string{"A", "B", "C"}) }
func (ctrl *ProductController) Show(c *gin.Context)    { c.Success("Product") }
func (ctrl *ProductController) Create(c *gin.Context)  { c.Created("Product") }
func (ctrl *ProductController) Update(c *gin.Context)  { c.Success("Updated") }
func (ctrl *ProductController) Patch(c *gin.Context)   { c.Success("Patched") }
func (ctrl *ProductController) Destroy(c *gin.Context) { c.NoContent() }

func main() {
	// 创建 Engine
	e := gin.Default(
		gin.WithAddr(":8080"),
		gin.WithGracefulShutdown(10*time.Second),
	)

	// 添加中间件
	e.Use(middleware.CORS())

	// 创建诊断工具
	inspector := diagnostic.NewInspector(e)

	// 打印路由表到控制台
	fmt.Println("📋 注册的路由：")
	inspector.PrintRoutes()
	fmt.Println()

	// 获取 Router
	r := e.Router()

	// ========== 业务路由 ==========

	r.GET("/users/:id", func(c *gin.Context) {
		id := c.ParamInt("id")
		c.Success(map[string]any{
			"id":   id,
			"name": "用户" + fmt.Sprint(id),
		})
	})

	r.POST("/users", func(c *gin.Context) {
		var req map[string]any
		if err := c.ShouldBindJSON(&req); err != nil {
			c.BadRequest("请求格式错误")
			return
		}
		c.Created(req)
	})

	// RESTful 资源路由
	routes.Resource(r, "products", &ProductController{})

	// ========== 诊断端点 ==========

	// 系统状态（JSON）
	r.GET("/diagnostic/status", inspector.Handler())

	// 自定义诊断端点
	r.GET("/diagnostic/metrics", func(c *gin.Context) {
		status := inspector.GetStatus()
		c.Success(map[string]any{
			"runtime": map[string]any{
				"go_version":    status.GoVersion,
				"num_goroutine": status.NumGoroutine,
				"memory": map[string]any{
					"alloc":       status.Memory.Alloc / 1024 / 1024,      // MB
					"total_alloc": status.Memory.TotalAlloc / 1024 / 1024, // MB
					"sys":         status.Memory.Sys / 1024 / 1024,        // MB
					"num_gc":      status.Memory.NumGC,
				},
			},
			"server": map[string]any{
				"uptime":  status.Uptime,
				"version": status.Version,
			},
			"routes": map[string]any{
				"count": status.Routes.Count,
				"items": status.Routes.Items,
			},
		})
	})

	// 健康检查
	routes.HealthCheck(r)

	// ========== 启动服务 ==========

	fmt.Println("🚀 服务启动在 http://localhost:8080")
	fmt.Println("\n📚 诊断端点：")
	fmt.Println("  - GET /health                  - 健康检查")
	fmt.Println("  - GET /diagnostic/status       - 系统状态（JSON）")
	fmt.Println("  - GET /diagnostic/metrics      - 详细指标")
	fmt.Println("\n📚 业务端点：")
	fmt.Println("  - GET  /users/:id              - 获取用户")
	fmt.Println("  - POST /users                  - 创建用户")
	fmt.Println("  - GET  /products               - 产品列表")
	fmt.Println("  - GET  /products/:id           - 产品详情")
	fmt.Println()

	if err := e.Run(); err != nil {
		panic(err)
	}
}
