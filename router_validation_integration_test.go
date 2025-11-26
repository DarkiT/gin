package gin

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// captureOutputAndError 同时捕获标准输出和错误输出
func captureOutputAndError(f func()) (string, string) {
	// 保存原始的输出
	originalWriter := gin.DefaultWriter
	originalErrorWriter := gin.DefaultErrorWriter
	defer func() {
		gin.DefaultWriter = originalWriter
		gin.DefaultErrorWriter = originalErrorWriter
	}()

	// 创建缓冲区来捕获输出
	var outputBuf bytes.Buffer
	var errorBuf bytes.Buffer
	gin.DefaultWriter = &outputBuf
	gin.DefaultErrorWriter = &errorBuf

	f()

	return outputBuf.String(), errorBuf.String()
}

// TestRouterValidationIntegration 测试路由器集成的验证功能
func TestRouterValidationIntegration(t *testing.T) {
	t.Run("有效路由注册", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		output, _ := captureOutputAndError(func() {
			router.GET("/users", func(c *Context) {
				c.String(200, "users")
			})

			router.GET("/users/:id", func(c *Context) {
				c.String(200, "user detail")
			})

			router.GET("/static/*filepath", func(c *Context) {
				c.String(200, "static file")
			})
		})

		// 验证路由注册成功并输出了参数信息
		assert.Contains(t, output, "注册路由: GET /users/:id (参数: [id]")
		assert.Contains(t, output, "注册路由: GET /static/*filepath (参数: [filepath]")
		assert.Contains(t, output, "通配符: true")

		// 验证路由已注册
		routes := router.GetRoutes()
		assert.Contains(t, routes, "GET:/users")
		assert.Contains(t, routes, "GET:/users/:id")
		assert.Contains(t, routes, "GET:/static/*filepath")
	})

	t.Run("无效路由模式拒绝", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		_, errorOutput := captureOutputAndError(func() {
			// 无效HTTP方法
			router.Register("INVALID", "/users", func(c *Context) {})

			// 无效参数名
			router.GET("/users/:123invalid", func(c *Context) {})

			// 通配符不在末尾
			router.GET("/static/*filepath/more", func(c *Context) {})

			// 重复参数名
			router.GET("/users/:id/posts/:id", func(c *Context) {})
		})

		// 验证错误信息输出
		assert.Contains(t, errorOutput, "路由注册失败")
		assert.Contains(t, errorOutput, "无效的HTTP方法: INVALID")
		assert.Contains(t, errorOutput, "参数段格式无效")
		assert.Contains(t, errorOutput, "必须是路径的最后一个段")
		assert.Contains(t, errorOutput, "参数名 'id' 重复")

		// 验证无效路由未被注册
		routes := router.GetRoutes()
		assert.NotContains(t, routes, "INVALID:/users")
		assert.NotContains(t, routes, "GET:/users/:123invalid")
		assert.NotContains(t, routes, "GET:/static/*filepath/more")
		assert.NotContains(t, routes, "GET:/users/:id/posts/:id")
	})

	t.Run("路由冲突检测", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		output, _ := captureOutputAndError(func() {
			// 注册第一个路由
			router.GET("/users/:id", func(c *Context) {
				c.String(200, "user by id")
			})

			// 尝试注册冲突的路由
			router.GET("/users/:name", func(c *Context) {
				c.String(200, "user by name")
			})

			// 尝试注册完全相同的路由
			router.GET("/users/:id", func(c *Context) {
				c.String(200, "duplicate")
			})
		})

		// 验证冲突检测输出
		assert.Contains(t, output, "路由冲突检测")
		assert.Contains(t, output, "与现有路由")
		assert.Contains(t, output, "冲突，忽略注册")

		// 验证只有第一个路由被注册
		routes := router.GetRoutes()
		assert.Contains(t, routes, "GET:/users/:id")
		assert.Len(t, routes, 1) // 只有一个路由被注册
	})

	t.Run("路由组验证功能", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)
		api := router.Group("/api/v1")

		output, errorOutput := captureOutputAndError(func() {
			// 有效路由
			api.GET("/users/:id", func(c *Context) {
				c.String(200, "api user")
			})

			// 无效路由
			api.GET("/posts/:123invalid", func(c *Context) {
				c.String(200, "invalid")
			})

			// 冲突路由
			api.GET("/users/:name", func(c *Context) {
				c.String(200, "conflict")
			})
		})

		// 验证路由组路由注册信息
		assert.Contains(t, output, "注册路由组路由: GET /api/v1/users/:id")
		assert.Contains(t, errorOutput, "路由组路由注册失败")
		assert.Contains(t, output, "路由组路由冲突检测")

		// 验证只有有效路由被注册
		routes := router.GetRoutes()
		assert.Contains(t, routes, "GET:/api/v1/users/:id")
		assert.NotContains(t, routes, "GET:/api/v1/posts/:123invalid")
		assert.NotContains(t, routes, "GET:/api/v1/users/:name")
	})

	t.Run("复杂路由模式验证", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		output, errorOutput := captureOutputAndError(func() {
			// 复杂但有效的路由
			router.GET("/api/:version/users/:id/posts/:postId/*action", func(c *Context) {
				c.String(200, "complex route")
			})

			// 参数名使用保留关键字
			router.GET("/test/:if", func(c *Context) {
				c.String(200, "reserved keyword")
			})

			// 参数名过长
			longName := strings.Repeat("a", 51)
			router.GET("/test/:"+longName, func(c *Context) {
				c.String(200, "long name")
			})
		})

		// 验证复杂路由注册成功
		assert.Contains(t, output, "注册路由: GET /api/:version/users/:id/posts/:postId/*action")
		assert.Contains(t, output, "参数: [version id postId action]")
		assert.Contains(t, output, "通配符: true")

		// 验证保留关键字错误
		assert.Contains(t, errorOutput, "不能使用保留关键字: if")

		// 验证参数名过长错误
		assert.Contains(t, errorOutput, "段名称过长")

		// 验证路由注册状态
		routes := router.GetRoutes()
		longName := strings.Repeat("a", 51)
		assert.Contains(t, routes, "GET:/api/:version/users/:id/posts/:postId/*action")
		assert.NotContains(t, routes, "GET:/test/:if")
		assert.NotContains(t, routes, "GET:/test/:"+longName)
	})

	t.Run("路由优先级信息", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		router := NewRouter(nil)

		output, _ := captureOutputAndError(func() {
			// 不同优先级的路由
			router.GET("/", func(c *Context) {})            // 根路径，最高优先级
			router.GET("/static/css", func(c *Context) {})  // 静态段
			router.GET("/users/:id", func(c *Context) {})   // 参数段
			router.GET("/files/*path", func(c *Context) {}) // 通配符段
		})

		// 验证优先级信息输出
		// 根路径和静态段不会输出优先级信息（因为没有参数和通配符）
		assert.Contains(t, output, "优先级: 190") // 参数段 (2*100 + 10 - 20)
		assert.Contains(t, output, "优先级: 160") // 通配符段 (2*100 + 10 - 50)
	})
}

// TestRouterResourceValidation 测试资源路由的验证功能
func TestRouterResourceValidation(t *testing.T) {
	router := NewRouter(nil)
	handler := &RestfulHandler{}

	output, _ := captureOutputAndError(func() {
		// 注册资源路由
		router.Resource("/users", handler)

		// 尝试注册冲突的资源路由
		router.Resource("/users", handler)
	})

	// 验证资源路由注册（只有带参数的路由会输出注册信息）
	assert.Contains(t, output, "注册路由: GET /users/:id")
	assert.Contains(t, output, "注册路由: PUT /users/:id")
	assert.Contains(t, output, "注册路由: DELETE /users/:id")

	// 验证冲突检测
	assert.Contains(t, output, "路由冲突检测")

	// 验证路由已注册
	routes := router.GetRoutes()
	assert.Contains(t, routes, "GET:/users")
	assert.Contains(t, routes, "GET:/users/:id")
	assert.Contains(t, routes, "POST:/users")
	assert.Contains(t, routes, "PUT:/users/:id")
	assert.Contains(t, routes, "DELETE:/users/:id")
}

// TestRouterGroupResourceValidation 测试路由组资源路由的验证功能
func TestRouterGroupResourceValidation(t *testing.T) {
	router := NewRouter(nil)
	api := router.Group("/api")
	handler := &RestfulHandler{}

	output, _ := captureOutputAndError(func() {
		// 在路由组中注册资源路由
		api.Resource("/users", handler)
	})

	// 验证路由组资源路由注册（只有带参数的路由会输出注册信息）
	assert.Contains(t, output, "注册路由组路由: GET /api/users/:id")
	assert.Contains(t, output, "注册路由组路由: PUT /api/users/:id")
	assert.Contains(t, output, "注册路由组路由: DELETE /api/users/:id")

	// 验证路由已注册
	routes := router.GetRoutes()
	assert.Contains(t, routes, "GET:/api/users")
	assert.Contains(t, routes, "GET:/api/users/:id")
	assert.Contains(t, routes, "POST:/api/users")
	assert.Contains(t, routes, "PUT:/api/users/:id")
	assert.Contains(t, routes, "DELETE:/api/users/:id")
}

// BenchmarkRouterValidationIntegration 基准测试路由器验证集成
func BenchmarkRouterValidationIntegration(b *testing.B) {
	router := NewRouter(nil)

	// 重定向输出以避免基准测试中的打印影响
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("/users/:id%d", i)
		router.GET(path, func(c *Context) {
			c.String(200, "test")
		})
	}
}
