package others

import (
	"mime/multipart"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/cache"
	"github.com/darkit/gin/pkg/sse"
)

// ExampleEnhancedFeatures 展示增强功能的使用示例
func ExampleEnhancedFeatures() {
	// 1. 使用新的选项式API创建路由器
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
		gin.WithCORS("http://localhost:3000", "https://example.com"),
		gin.WithRateLimit(100), // 100 requests per minute
		gin.WithRequestID(),
		gin.WithTimeout(30*time.Second),
	)

	// 2. 添加健康检查和指标端点
	router.Health()  // GET /health
	router.Metrics() // GET /metrics

	// 3. 使用新的便捷响应方法
	router.GET("/users", func(c *gin.Context) {
		users := []gin.H{
			{"id": 1, "name": "Alice", "email": "alice@example.com"},
			{"id": 2, "name": "Bob", "email": "bob@example.com"},
		}

		// 分页响应
		c.Paginated(users, 1, 10, 2)
	})

	router.POST("/users", func(c *gin.Context) {
		var user gin.H
		if !c.BindJSON(&user) {
			c.ValidationError(gin.H{"error": "无效的JSON数据"})
			return
		}

		// 创建成功响应
		c.Created(user)
	})

	router.GET("/users/:id", func(c *gin.Context) {
		id := c.Param("id")

		// 模拟用户不存在
		if id == "999" {
			c.NotFound("用户不存在")
			return
		}

		user := gin.H{"id": id, "name": "User " + id}
		c.Success(user)
	})

	// 4. 使用CRUD快捷方法
	router.CRUD("posts", &PostResource{})

	// 5. API版本管理
	v1 := router.API("v1")
	{
		v1.GET("/profile", func(c *gin.Context) {
			c.Success(gin.H{"version": "v1", "user": "current_user"})
		})
	}

	v2 := router.API("v2")
	{
		v2.GET("/profile", func(c *gin.Context) {
			c.Success(gin.H{"version": "v2", "user": "enhanced_user_data"})
		})
	}

	// 6. 文件上传路由
	router.Upload("/upload", func(c *gin.Context, file *multipart.FileHeader) error {
		// 这里可以添加文件处理逻辑
		// 例如：验证文件类型、大小等
		return nil // 返回nil表示处理成功
	})

	// 7. 静态文件服务
	router.StaticFiles("/static", "./public")

	// 8. 资源路由（实现ResourceHandler接口）
	userHandler := &UserResourceHandler{}
	router.Resource("/api/users", userHandler)

	// 9. 错误处理示例
	router.GET("/error", func(c *gin.Context) {
		c.ServerError("模拟服务器错误")
	})

	router.GET("/forbidden", func(c *gin.Context) {
		c.Forbidden("访问被拒绝")
	})

	router.GET("/unauthorized", func(c *gin.Context) {
		c.Unauthorized("需要身份验证")
	})

	// 启动服务器
	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

// UserResourceHandler 实现ResourceHandler接口
type UserResourceHandler struct{}

func (h *UserResourceHandler) Index(c *gin.Context) {
	users := []gin.H{
		{"id": 1, "name": "Alice"},
		{"id": 2, "name": "Bob"},
	}
	c.Success(users)
}

func (h *UserResourceHandler) Show(c *gin.Context) {
	id := c.Param("id")
	user := gin.H{"id": id, "name": "User " + id}
	c.Success(user)
}

func (h *UserResourceHandler) Create(c *gin.Context) {
	var user gin.H
	if !c.BindJSON(&user) {
		c.ValidationError(gin.H{"error": "无效的用户数据"})
		return
	}
	user["id"] = "new_id"
	c.Created(user)
}

func (h *UserResourceHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var updates gin.H
	if !c.BindJSON(&updates) {
		c.ValidationError(gin.H{"error": "无效的更新数据"})
		return
	}
	updates["id"] = id
	c.Success(updates)
}

func (h *UserResourceHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	c.Success(gin.H{"message": "用户 " + id + " 已删除"})
}

// PostResource 实现资源化 CRUD
type PostResource struct{}

func (p *PostResource) Index(c *gin.Context) {
	posts := []gin.H{
		{"id": 1, "title": "First Post", "content": "Hello World"},
		{"id": 2, "title": "Second Post", "content": "Gin is awesome"},
	}
	c.Success(posts)
}

func (p *PostResource) Show(c *gin.Context) {
	id := c.Param("id")
	post := gin.H{"id": id, "title": "Post " + id, "content": "Content of post " + id}
	c.Success(post)
}

func (p *PostResource) Create(c *gin.Context) {
	var post gin.H
	if !c.BindJSON(&post) {
		c.ValidationError(gin.H{"error": "无效的数据格式"})
		return
	}
	c.Created(post)
}

func (p *PostResource) Update(c *gin.Context) {
	id := c.Param("id")
	var updates gin.H
	if !c.BindJSON(&updates) {
		c.ValidationError(gin.H{"error": "无效的数据格式"})
		return
	}
	updates["id"] = id
	c.Success(updates)
}

func (p *PostResource) Delete(c *gin.Context) {
	id := c.Param("id")
	c.Success(gin.H{"message": "帖子 " + id + " 已删除"})
}
