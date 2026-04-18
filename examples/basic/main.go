package main

import (
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
)

// User 用户结构
type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required,email"`
}

func main() {
	// 创建 Engine（内置 RequestID + Recovery + Logger）
	e := gin.Default(
		gin.WithAddr(":8080"),
		gin.WithReadTimeout(30*time.Second),
		gin.WithWriteTimeout(30*time.Second),
		gin.WithGracefulShutdown(10*time.Second),
	)

	// 添加 CORS 中间件
	e.Use(middleware.CORS())

	// 获取 Router
	r := e.Router()

	// GET 请求 - 获取单个用户
	r.GET("/users/:id", func(c *gin.Context) {
		id := c.ParamInt("id")
		if id == 0 {
			c.BadRequest("无效的用户 ID")
			return
		}

		user := User{
			ID:    id,
			Name:  "张三",
			Email: "zhangsan@example.com",
		}
		c.Success(user)
	})

	// GET 请求 - 获取用户列表（带分页）
	r.GET("/users", func(c *gin.Context) {
		page := c.ParamInt("page", 1)
		perPage := c.ParamInt("per_page", 10)

		users := []User{
			{ID: 1, Name: "张三", Email: "zhangsan@example.com"},
			{ID: 2, Name: "李四", Email: "lisi@example.com"},
			{ID: 3, Name: "王五", Email: "wangwu@example.com"},
		}

		// 分页响应
		c.Paginated(users, page, perPage, 3)
	})

	// POST 请求 - 创建用户
	r.POST("/users", func(c *gin.Context) {
		var req CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.BadRequest("请求格式错误: " + err.Error())
			return
		}

		// 创建用户
		user := User{
			ID:    100,
			Name:  req.Name,
			Email: req.Email,
		}

		c.Created(user)
	})

	// PUT 请求 - 更新用户
	r.PUT("/users/:id", func(c *gin.Context) {
		id := c.ParamInt("id")
		if id == 0 {
			c.BadRequest("无效的用户 ID")
			return
		}

		var req CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.BadRequest("请求格式错误: " + err.Error())
			return
		}

		user := User{
			ID:    id,
			Name:  req.Name,
			Email: req.Email,
		}

		c.Success(user)
	})

	// DELETE 请求 - 删除用户
	r.DELETE("/users/:id", func(c *gin.Context) {
		id := c.ParamInt("id")
		if id == 0 {
			c.BadRequest("无效的用户 ID")
			return
		}

		c.NoContent()
	})

	// 错误响应示例
	r.GET("/errors/demo", func(c *gin.Context) {
		errorType := c.Input("type", "400")

		switch errorType {
		case "400":
			c.BadRequest("错误的请求参数")
		case "401":
			c.Unauthorized("未授权，请先登录")
		case "403":
			c.Forbidden("没有权限访问该资源")
		case "404":
			c.NotFound("请求的资源不存在")
		case "409":
			c.Conflict("资源冲突")
		case "422":
			c.ValidationError([]gin.ValidationError{
				{Field: "name", Message: "名称不能为空"},
				{Field: "email", Message: "邮箱格式不正确"},
			})
		case "500":
			c.InternalError("服务器内部错误")
		default:
			c.ErrorResponse(418, "I'm a teapot")
		}
	})

	// 请求信息辅助方法
	r.GET("/info", func(c *gin.Context) {
		info := map[string]any{
			"ip":         c.GetIP(),
			"user_agent": c.GetUserAgent(),
			"is_ajax":    c.IsAjax(),
			"is_json":    c.IsJSON(),
		}
		c.Success(info)
	})

	// 启动服务（内置优雅停机）
	if err := e.Run(); err != nil {
		panic(err)
	}
}
