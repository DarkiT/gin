package main

import (
	"net/http"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/swagger"
)

// User 用户模型
type User struct {
	ID    int64  `json:"id" description:"用户ID"`
	Name  string `json:"name" binding:"required" description:"用户名"`
	Email string `json:"email" description:"邮箱"`
	Age   int    `json:"age" description:"年龄"`
}

// ErrorResponse 错误响应
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	// 创建引擎并启用 Swagger
	e := gin.New(
		gin.EnableSwagger(swagger.SwaggerConfig{
			Title:       "示例 API",
			Description: "这是一个演示 Swagger 文档生成的示例项目",
			Version:     "v1.0.0",
			BasePath:    "/api",
			Host:        "localhost:8080",
			Schemes:     []string{"http"},
			Contact: swagger.Contact{
				Name:  "开发团队",
				Email: "dev@example.com",
			},
		}),
	)

	// 创建 API 路由组
	api := e.Router().Group("/api")

	// 用户列表 - 完整的文档注解示例
	api.GETDoc("/users", func(c *gin.Context) {
		users := []User{
			{ID: 1, Name: "张三", Email: "zhangsan@example.com", Age: 25},
			{ID: 2, Name: "李四", Email: "lisi@example.com", Age: 30},
		}
		c.Success(users)
	}).
		Doc("获取用户列表").
		OperationID("listUsers").
		Description("分页获取所有用户信息，支持按名称搜索").
		Param("page", "query", "integer", "页码，默认为 1", false).
		Param("per_page", "query", "integer", "每页数量，默认为 20", false).
		Param("search", "query", "string", "搜索关键词", false).
		Response(200, "成功返回用户列表", []User{}).
		ResponseExample(200, []User{
			{ID: 1, Name: "张三", Email: "zhangsan@example.com", Age: 25},
			{ID: 2, Name: "李四", Email: "lisi@example.com", Age: 30},
		}).
		Tag("用户管理")

	// 获取用户详情
	api.GETDoc("/users/:id", func(c *gin.Context) {
		user := User{
			ID:    1,
			Name:  "张三",
			Email: "zhangsan@example.com",
			Age:   25,
		}
		c.Success(user)
	}).
		Doc("获取用户详情").
		OperationID("getUserByID").
		Description("根据用户 ID 获取用户的详细信息").
		Param("id", "path", "integer", "用户 ID", true).
		Response(200, "成功返回用户信息", User{}).
		ResponseExample(200, User{
			ID:    1,
			Name:  "张三",
			Email: "zhangsan@example.com",
			Age:   25,
		}).
		DefaultErrors(404, 500).
		Tag("用户管理")

	// 创建用户
	api.POSTDoc("/users", func(c *gin.Context) {
		var user User
		if err := c.BindAndValidate(&user); err != nil {
			c.ValidationProblem(gin.ExtractValidationErrors(err), "用户参数校验失败")
			return
		}
		user.ID = 1 // 模拟生成 ID
		c.Created(user)
	}).
		Doc("创建用户").
		OperationID("createUser").
		Description("创建一个新用户").
		ParamModel("body", "body", "用户信息", true, User{}).
		RequestExample(User{
			Name:  "赵六",
			Email: "zhaoliu@example.com",
			Age:   28,
		}).
		Response(201, "创建成功", User{}).
		ResponseExample(201, User{
			ID:    1,
			Name:  "赵六",
			Email: "zhaoliu@example.com",
			Age:   28,
		}).
		DefaultErrors(400, 422, 500).
		Tag("用户管理")

	// 更新用户
	api.PUTDoc("/users/:id", func(c *gin.Context) {
		var user User
		if err := c.BindAndValidate(&user); err != nil {
			c.ValidationProblem(gin.ExtractValidationErrors(err), "用户参数校验失败")
			return
		}
		c.Success(user)
	}).
		Doc("更新用户").
		OperationID("replaceUser").
		Description("更新用户的完整信息").
		Param("id", "path", "integer", "用户 ID", true).
		ParamModel("body", "body", "用户信息", true, User{}).
		RequestExamples(map[string]swagger.Example{
			"basic": {
				Summary: "基础更新示例",
				Value: User{
					Name:  "王五",
					Email: "wangwu@example.com",
					Age:   32,
				},
			},
			"senior": {
				Summary: "资深用户示例",
				Value: User{
					Name:  "周七",
					Email: "zhouqi@example.com",
					Age:   40,
				},
			},
		}).
		Response(200, "更新成功", User{}).
		ResponseExamples(200, map[string]swagger.Example{
			"updated": {
				Summary: "更新成功示例",
				Value: User{
					ID:    1,
					Name:  "王五",
					Email: "wangwu@example.com",
					Age:   32,
				},
			},
		}).
		DefaultErrors(400, 404, 422, 500).
		Tag("用户管理")

	// 删除用户
	api.DELETEDoc("/users/:id", func(c *gin.Context) {
		c.Status(204)
	}).
		Doc("删除用户").
		OperationID("deleteUser").
		Description("根据用户 ID 删除用户").
		Param("id", "path", "integer", "用户 ID", true).
		Response(204, "删除成功", nil).
		DefaultErrors(404, 500).
		Tag("用户管理")

	// 搜索用户（演示安全认证）
	api.GETDoc("/users/search", func(c *gin.Context) {
		c.Success([]User{})
	}).
		Doc("搜索用户").
		OperationID("searchUsers").
		Description("根据条件搜索用户，需要认证").
		Param("q", "query", "string", "搜索关键词", true).
		Param("X-API-Key", "header", "string", "API密钥", true).
		Response(200, "搜索成功", []User{}).
		DefaultErrors(401, 429, 500).
		Tag("用户管理").
		Security("apiKey")

	// 冲突示例（演示 ProblemResponse）
	api.GETDoc("/users/:id/conflict", func(c *gin.Context) {
		c.Problem(
			http.StatusConflict,
			"https://example.com/problems/user-conflict",
			"用户冲突",
			"当前用户正在被其他流程编辑，请稍后重试",
		)
	}).
		Doc("用户冲突示例").
		OperationID("getUserConflictExample").
		Description("演示 Problem Details 与 Swagger ProblemResponse 的配合方式").
		Param("id", "path", "integer", "用户 ID", true).
		ProblemResponse(409, "用户冲突").
		Tag("用户管理")

	// 旧版 API（演示废弃标记）
	api.GETDoc("/v1/users", func(c *gin.Context) {
		c.Success([]User{})
	}).
		Doc("获取用户列表（旧版）").
		OperationID("listUsersLegacy").
		Description("这是旧版 API，请使用 /api/users 代替").
		Response(200, "成功", []User{}).
		Tag("用户管理").
		Deprecated()

	// 启动服务器
	println("Swagger UI: http://localhost:8080/swagger")
	println("Swagger JSON: http://localhost:8080/swagger/doc.json")
	_ = e.Run(":8080")
}
