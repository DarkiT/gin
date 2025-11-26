package gin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestRouterLoggingWithGinLogger 测试使用Gin日志组件的路由日志功能
func TestRouterLoggingWithGinLogger(t *testing.T) {
	// 保存原始的gin输出
	originalWriter := gin.DefaultWriter
	originalErrorWriter := gin.DefaultErrorWriter
	defer func() {
		gin.DefaultWriter = originalWriter
		gin.DefaultErrorWriter = originalErrorWriter
	}()

	t.Run("调试模式下的路由注册日志", func(t *testing.T) {
		// 设置为调试模式
		gin.SetMode(gin.DebugMode)

		var buf bytes.Buffer
		var errBuf bytes.Buffer
		gin.DefaultWriter = &buf
		gin.DefaultErrorWriter = &errBuf

		router := NewRouter(nil)

		// 注册一些路由
		router.GET("/users", func(c *Context) {})
		router.GET("/users/:id", func(c *Context) {})
		router.POST("/users/:id/posts", func(c *Context) {})
		router.GET("/static/*filepath", func(c *Context) {})

		output := buf.String()

		// 验证调试日志输出
		assert.Contains(t, output, "[GIN-ROUTER] DEBUG: 注册路由: GET /users")
		assert.Contains(t, output, "[GIN-ROUTER] INFO: 注册路由: GET /users/:id")
		assert.Contains(t, output, "[GIN-ROUTER] INFO: 注册路由: POST /users/:id/posts")
		assert.Contains(t, output, "[GIN-ROUTER] INFO: 注册路由: GET /static/*filepath")
		assert.Contains(t, output, "参数: [id]")
		assert.Contains(t, output, "通配符: true")
	})

	t.Run("发布模式下的路由注册日志", func(t *testing.T) {
		// 设置为发布模式
		gin.SetMode(gin.ReleaseMode)

		var buf bytes.Buffer
		var errBuf bytes.Buffer
		gin.DefaultWriter = &buf
		gin.DefaultErrorWriter = &errBuf

		router := NewRouter(nil)

		// 注册一些路由
		router.GET("/users", func(c *Context) {})
		router.GET("/users/:id", func(c *Context) {})

		output := buf.String()

		// 发布模式下不应该有调试和信息日志
		assert.NotContains(t, output, "[GIN-ROUTER] DEBUG:")
		assert.NotContains(t, output, "[GIN-ROUTER] INFO:")
	})

	t.Run("路由冲突警告日志", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)

		var buf bytes.Buffer
		var errBuf bytes.Buffer
		gin.DefaultWriter = &buf
		gin.DefaultErrorWriter = &errBuf

		router := NewRouter(nil)

		// 注册第一个路由
		router.GET("/users/:id", func(c *Context) {})

		// 清空缓冲区
		buf.Reset()

		// 尝试注册冲突的路由
		router.GET("/users/:name", func(c *Context) {})

		output := buf.String()

		// 验证警告日志
		assert.Contains(t, output, "[GIN-ROUTER] WARN:")
		assert.Contains(t, output, "路由冲突检测")
		assert.Contains(t, output, "冲突，忽略注册")
	})

	t.Run("路由注册错误日志", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)

		var buf bytes.Buffer
		var errBuf bytes.Buffer
		gin.DefaultWriter = &buf
		gin.DefaultErrorWriter = &errBuf

		router := NewRouter(nil)

		// 尝试注册无效的路由
		router.Register("INVALID", "/users", func(c *Context) {})
		router.GET("/users/:123invalid", func(c *Context) {})

		errorOutput := errBuf.String()

		// 验证错误日志
		assert.Contains(t, errorOutput, "[GIN-ROUTER] ERROR:")
		assert.Contains(t, errorOutput, "路由注册失败")
		assert.Contains(t, errorOutput, "无效的HTTP方法")
	})

	t.Run("路由组日志", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)

		var buf bytes.Buffer
		var errBuf bytes.Buffer
		gin.DefaultWriter = &buf
		gin.DefaultErrorWriter = &errBuf

		router := NewRouter(nil)
		api := router.Group("/api/v1")

		// 注册路由组路由
		api.GET("/users/:id", func(c *Context) {})
		api.POST("/users/:id/posts", func(c *Context) {})

		output := buf.String()

		// 验证路由组日志
		assert.Contains(t, output, "[GIN-ROUTER] INFO: 注册路由组路由: GET /api/v1/users/:id")
		assert.Contains(t, output, "[GIN-ROUTER] INFO: 注册路由组路由: POST /api/v1/users/:id/posts")
		assert.Contains(t, output, "参数: [id]")
	})

	t.Run("路由组冲突和错误日志", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)

		var buf bytes.Buffer
		var errBuf bytes.Buffer
		gin.DefaultWriter = &buf
		gin.DefaultErrorWriter = &errBuf

		router := NewRouter(nil)
		api := router.Group("/api/v1")

		// 注册第一个路由
		api.GET("/users/:id", func(c *Context) {})

		// 清空缓冲区
		buf.Reset()
		errBuf.Reset()

		// 尝试注册冲突的路由
		api.GET("/users/:name", func(c *Context) {})

		// 尝试注册无效的路由
		api.GET("/posts/:123invalid", func(c *Context) {})

		output := buf.String()
		errorOutput := errBuf.String()

		// 验证路由组警告和错误日志
		assert.Contains(t, output, "[GIN-ROUTER] WARN:")
		assert.Contains(t, output, "路由组路由冲突检测")
		assert.Contains(t, errorOutput, "[GIN-ROUTER] ERROR:")
		assert.Contains(t, errorOutput, "路由组路由注册失败")
	})
}

// TestRouterLoggingInDifferentModes 测试不同模式下的日志行为
func TestRouterLoggingInDifferentModes(t *testing.T) {
	originalWriter := gin.DefaultWriter
	originalErrorWriter := gin.DefaultErrorWriter
	originalMode := gin.Mode()
	defer func() {
		gin.DefaultWriter = originalWriter
		gin.DefaultErrorWriter = originalErrorWriter
		gin.SetMode(originalMode)
	}()

	modes := []string{gin.DebugMode, gin.ReleaseMode, gin.TestMode}

	for _, mode := range modes {
		t.Run("模式_"+mode, func(t *testing.T) {
			gin.SetMode(mode)

			var buf bytes.Buffer
			var errBuf bytes.Buffer
			gin.DefaultWriter = &buf
			gin.DefaultErrorWriter = &errBuf

			router := NewRouter(nil)

			// 注册正常路由
			router.GET("/users", func(c *Context) {})
			router.GET("/users/:id", func(c *Context) {})

			// 尝试注册冲突路由
			router.GET("/users/:name", func(c *Context) {})

			// 尝试注册无效路由
			router.GET("/invalid/:123param", func(c *Context) {})

			output := buf.String()
			errorOutput := errBuf.String()

			switch mode {
			case gin.DebugMode:
				// 调试模式应该有所有类型的日志
				assert.Contains(t, output, "[GIN-ROUTER] DEBUG:")
				assert.Contains(t, output, "[GIN-ROUTER] INFO:")
				assert.Contains(t, output, "[GIN-ROUTER] WARN:")
				assert.Contains(t, errorOutput, "[GIN-ROUTER] ERROR:")

			case gin.ReleaseMode:
				// 发布模式只应该有警告日志
				assert.NotContains(t, output, "[GIN-ROUTER] DEBUG:")
				assert.NotContains(t, output, "[GIN-ROUTER] INFO:")
				assert.Contains(t, output, "[GIN-ROUTER] WARN:")
				assert.Contains(t, errorOutput, "[GIN-ROUTER] ERROR:")

			case gin.TestMode:
				// 测试模式不应该有调试和信息日志
				assert.NotContains(t, output, "[GIN-ROUTER] DEBUG:")
				assert.NotContains(t, output, "[GIN-ROUTER] INFO:")
				assert.Contains(t, output, "[GIN-ROUTER] WARN:")
				assert.Contains(t, errorOutput, "[GIN-ROUTER] ERROR:")
			}
		})
	}
}

// TestRouterLoggingFormat 测试日志格式
func TestRouterLoggingFormat(t *testing.T) {
	originalWriter := gin.DefaultWriter
	originalErrorWriter := gin.DefaultErrorWriter
	defer func() {
		gin.DefaultWriter = originalWriter
		gin.DefaultErrorWriter = originalErrorWriter
	}()

	gin.SetMode(gin.DebugMode)

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	gin.DefaultWriter = &buf
	gin.DefaultErrorWriter = &errBuf

	router := NewRouter(nil)

	// 注册带参数的路由
	router.GET("/users/:id/posts/:postId", func(c *Context) {})

	// 注册通配符路由
	router.GET("/static/*filepath", func(c *Context) {})

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// 验证日志格式
	for _, line := range lines {
		if strings.Contains(line, "[GIN-ROUTER]") {
			// 验证日志前缀格式
			assert.True(t, strings.HasPrefix(line, "[GIN-ROUTER]"))

			// 验证包含必要信息
			if strings.Contains(line, "参数:") {
				assert.Contains(t, line, "通配符:")
				assert.Contains(t, line, "优先级:")
			}
		}
	}
}

// BenchmarkRouterLogging 基准测试路由日志性能
func BenchmarkRouterLogging(b *testing.B) {
	originalWriter := gin.DefaultWriter
	originalErrorWriter := gin.DefaultErrorWriter
	defer func() {
		gin.DefaultWriter = originalWriter
		gin.DefaultErrorWriter = originalErrorWriter
	}()

	// 使用空的writer来避免实际输出影响性能测试
	gin.DefaultWriter = &bytes.Buffer{}
	gin.DefaultErrorWriter = &bytes.Buffer{}

	b.Run("调试模式路由注册", func(b *testing.B) {
		gin.SetMode(gin.DebugMode)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			router := NewRouter(nil)
			router.GET("/users/:id", func(c *Context) {})
		}
	})

	b.Run("发布模式路由注册", func(b *testing.B) {
		gin.SetMode(gin.ReleaseMode)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			router := NewRouter(nil)
			router.GET("/users/:id", func(c *Context) {})
		}
	})
}
