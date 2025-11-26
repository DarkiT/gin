package main

import (
	"log"

	gin "github.com/darkit/gin"
)

// User 用户结构体
type User struct {
	ID       int    `json:"id" example:"1"`
	Username string `json:"username" example:"john_doe"`
	Email    string `json:"email" example:"john@example.com"`
	Name     string `json:"name" example:"John Doe"`
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Username string `json:"username" binding:"required" example:"john_doe"`
	Email    string `json:"email" binding:"required,email" example:"john@example.com"`
	Name     string `json:"name" binding:"required" example:"John Doe"`
}

// ErrorResponse 错误响应
type ErrorResponse struct {
	Error   string `json:"error" example:"用户未找到"`
	Code    int    `json:"code" example:"404"`
	Message string `json:"message" example:"请求的用户不存在"`
}

// ValidationError 验证错误
type ValidationError struct {
	Error  string            `json:"error" example:"参数验证失败"`
	Fields map[string]string `json:"fields" example:"{\"username\":\"用户名不能为空\"}"`
}

func main() {
	// 创建路由器并启用OpenAPI
	router := gin.NewRouter(
		gin.WithGinMode("debug"),
		gin.WithOpenAPI(&gin.OpenAPI{
			Title:   "用户管理系统 API",
			Version: "1.0.0",
			Servers: gin.Servers{
				{URL: "http://localhost:8080", Description: "开发服务器"},
				{URL: "https://api.example.com", Description: "生产服务器"},
			},
			License: gin.License{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
			Contact: gin.Contact{
				Name:  "API Support",
				Email: "support@example.com",
				URL:   "https://www.example.com/support",
			},
			SecuritySchemes: gin.SecuritySchemes{
				{
					Name:         "bearerAuth",
					Type:         "http",
					Scheme:       "bearer",
					BearerFormat: "JWT",
				},
			},
		}),
		gin.WithCORS("*"),
		// JWT配置已移至 SecurityConfig，请参考 ../main.go 示例
	)

	// 公开API
	public := router.Group("/api/public").
		WithTags("Public API")

	public.GET("/health", healthHandler,
		gin.Summary("健康检查"),
		gin.Description("检查系统健康状态"),
		gin.Response(200, gin.H{"status": "ok"}),
	)

	// 认证API
	auth := router.Group("/api/auth").
		WithTags("Authentication")

	auth.POST("/login", loginHandler,
		gin.Summary("用户登录"),
		gin.Description("用户通过用户名和密码登录系统"),
		gin.RequestBody(gin.H{
			"username": "john_doe",
			"password": "secret123",
		}),
		gin.Response(200, gin.H{
			"token":         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			"refresh_token": "refresh_token_here",
			"expires_in":    3600,
		}),
		gin.Response(401, ErrorResponse{}),
	)

	// 用户管理API
	users := router.Group("/api/users").
		WithTags("User Management").
		WithSecurity("bearerAuth")

	users.GET("/", listUsersHandler,
		gin.Summary("获取用户列表"),
		gin.Description("分页获取用户列表"),
		gin.QueryParam("page", "int", "页码", false),
		gin.QueryParam("size", "int", "每页数量", false),
		gin.QueryParam("search", "string", "搜索关键词", false),
		gin.Response(200, []User{}),
		gin.Response(401, ErrorResponse{}),
	)

	users.GET("/:id", getUserHandler,
		gin.Summary("获取用户详情"),
		gin.Description("根据用户ID获取用户详细信息"),
		gin.PathParam("id", "int", "用户ID"),
		gin.Resp[User](200),          // 使用泛型方式
		gin.Resp[ErrorResponse](404), // 使用泛型方式
		gin.Resp[ErrorResponse](401),
	)

	users.POST("/", createUserHandler,
		gin.Summary("创建用户"),
		gin.Description("创建新用户账户"),
		gin.ReqBody[CreateUserRequest](), // 使用泛型方式
		gin.Resp[User](201),
		gin.Resp[ValidationError](400),
		gin.Resp[ErrorResponse](401),
	)

	users.PUT("/:id", updateUserHandler,
		gin.Summary("更新用户"),
		gin.Description("更新用户信息"),
		gin.PathParam("id", "int", "用户ID"),
		gin.RequestBody(CreateUserRequest{}),
		gin.Response(200, User{}),
		gin.Response(400, ValidationError{}),
		gin.Response(401, ErrorResponse{}),
		gin.Response(404, ErrorResponse{}),
	)

	users.DELETE("/:id", deleteUserHandler,
		gin.Summary("删除用户"),
		gin.Description("删除用户账户"),
		gin.PathParam("id", "int", "用户ID"),
		gin.Response(204, nil), // 无内容响应
		gin.Response(401, ErrorResponse{}),
		gin.Response(404, ErrorResponse{}),
	)

	// 管理员API（继承用户API的安全配置并添加额外标签）
	admin := users.Group("/admin").
		WithTags("Admin Management").
		WithSecurity("bearerAuth", "admin:write")

	admin.POST("/reset-password/:id", resetPasswordHandler,
		gin.Summary("重置用户密码"),
		gin.Description("管理员重置指定用户密码"),
		gin.PathParam("id", "int", "用户ID"),
		gin.RequestBody(gin.H{
			"new_password": "new_secret123",
		}),
		gin.Response(200, gin.H{"message": "密码重置成功"}),
		gin.Response(401, ErrorResponse{}),
		gin.Response(403, ErrorResponse{}),
		gin.Response(404, ErrorResponse{}),
		gin.Deprecated(), // 标记为已弃用
	)

	// 启用Swagger UI
	router.EnableSwagger("/swagger")

	// 添加根路径重定向到Swagger
	router.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/swagger/index.html")
	})

	log.Println("服务器启动在 http://localhost:8080")
	log.Println("Swagger UI: http://localhost:8080/swagger/index.html")
	log.Println("OpenAPI规范: http://localhost:8080/swagger/doc.json")

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

// 处理函数实现
func healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":    "ok",
		"timestamp": gin.H{},
		"uptime":    "running",
	})
}

func loginHandler(c *gin.Context) {
	// 简化的登录逻辑
	c.JSON(200, gin.H{
		"token":         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
		"refresh_token": "refresh_token_here",
		"expires_in":    3600,
		"user": User{
			ID:       1,
			Username: "john_doe",
			Email:    "john@example.com",
			Name:     "John Doe",
		},
	})
}

func listUsersHandler(c *gin.Context) {
	users := []User{
		{ID: 1, Username: "john_doe", Email: "john@example.com", Name: "John Doe"},
		{ID: 2, Username: "jane_doe", Email: "jane@example.com", Name: "Jane Doe"},
	}
	c.JSON(200, users)
}

func getUserHandler(c *gin.Context) {
	id := c.Param("id")
	if id == "1" {
		c.JSON(200, User{
			ID:       1,
			Username: "john_doe",
			Email:    "john@example.com",
			Name:     "John Doe",
		})
	} else {
		c.JSON(404, ErrorResponse{
			Error:   "用户未找到",
			Code:    404,
			Message: "请求的用户不存在",
		})
	}
}

func createUserHandler(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ValidationError{
			Error:  "参数验证失败",
			Fields: map[string]string{"username": "用户名不能为空"},
		})
		return
	}

	user := User{
		ID:       3,
		Username: req.Username,
		Email:    req.Email,
		Name:     req.Name,
	}
	c.JSON(201, user)
}

func updateUserHandler(c *gin.Context) {
	id := c.Param("id")
	if id != "1" {
		c.JSON(404, ErrorResponse{
			Error:   "用户未找到",
			Code:    404,
			Message: "请求的用户不存在",
		})
		return
	}

	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ValidationError{
			Error:  "参数验证失败",
			Fields: map[string]string{"email": "邮箱格式不正确"},
		})
		return
	}

	user := User{
		ID:       1,
		Username: req.Username,
		Email:    req.Email,
		Name:     req.Name,
	}
	c.JSON(200, user)
}

func deleteUserHandler(c *gin.Context) {
	id := c.Param("id")
	if id == "1" {
		c.Status(204) // No Content
	} else {
		c.JSON(404, ErrorResponse{
			Error:   "用户未找到",
			Code:    404,
			Message: "请求的用户不存在",
		})
	}
}

func resetPasswordHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "密码重置成功",
		"user_id": c.Param("id"),
	})
}
