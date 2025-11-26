package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/darkit/gin/pkg/errors"
	"github.com/gin-gonic/gin"
)

// 模拟数据库操作
func simulateDBOperation(userID string) error {
	// 模拟数据库错误
	if userID == "error" {
		return fmt.Errorf("数据库连接失败: 连接超时")
	}

	if userID == "" {
		return errors.NotFound("用户")
	}

	return nil
}

// 模拟业务逻辑
func getUserInfo(userID string) (map[string]interface{}, error) {
	// 调用数据库操作
	if err := simulateDBOperation(userID); err != nil {
		// 包装错误
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery)
	}

	// 返回用户信息
	return map[string]interface{}{
		"id":       userID,
		"username": "测试用户",
		"email":    "test@example.com",
		"created":  time.Now().Format(time.RFC3339),
	}, nil
}

// 用户信息处理器
func getUserHandler(c *gin.Context) {
	userID := c.Param("id")

	// 参数校验
	if userID == "admin" {
		errors.GinForbidden(c, "不允许访问管理员信息")
		return
	}

	// 调用业务逻辑
	user, err := getUserInfo(userID)
	if err != nil {
		// 使用我们的错误处理
		if errors.Is(err, errors.ErrCodeDBQuery) {
			// 记录详细错误
			log.Printf("数据库查询错误: %v", err)

			// 返回友好错误
			errors.GinCustomError(c, errors.ErrCodeDBQuery, "获取用户数据失败，请稍后再试")
			return
		}

		// 直接传递错误
		_ = c.Error(err)
		return
	}

	// 返回成功响应
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 200,
		"msg":  "success",
		"data": user,
	})
}

// 触发 panic 的处理器
func panicHandler(c *gin.Context) {
	// 故意触发 panic
	var p *int = nil
	*p = 1 // 空指针引用将触发 panic
}

// 无效参数处理器
func invalidParamHandler(c *gin.Context) {
	errors.GinInvalidParam(c, "id")
}

func main() {
	// 设置生产模式
	gin.SetMode(gin.ReleaseMode)

	// 创建路由
	r := gin.New()

	// 使用错误处理中间件
	r.Use(errors.GinDefaultErrorMiddleware())

	// 添加路由
	r.GET("/api/users/:id", getUserHandler)
	r.GET("/api/panic", panicHandler)
	r.GET("/api/invalid", invalidParamHandler)

	// 404 处理
	r.NoRoute(func(c *gin.Context) {
		errors.GinNotFound(c, "API路径")
	})

	// 启动服务器
	port := ":8080"
	fmt.Printf("服务器启动在 http://localhost%s\n", port)
	fmt.Println("测试路由:")
	fmt.Println("- 正常请求: http://localhost" + port + "/api/users/123")
	fmt.Println("- 未找到用户: http://localhost" + port + "/api/users/")
	fmt.Println("- 数据库错误: http://localhost" + port + "/api/users/error")
	fmt.Println("- 禁止访问: http://localhost" + port + "/api/users/admin")
	fmt.Println("- 无效参数: http://localhost" + port + "/api/invalid")
	fmt.Println("- 触发panic: http://localhost" + port + "/api/panic")
	fmt.Println("- 路径不存在: http://localhost" + port + "/api/notfound")

	if err := r.Run(port); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}
