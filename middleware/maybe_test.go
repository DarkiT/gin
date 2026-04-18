package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darkit/gin"
)

func TestMaybe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name             string
		path             string
		maybeCondition   func(*gin.Context) bool
		expectMiddleware bool
	}{
		{
			name: "condition true - middleware executed",
			path: "/api/users",
			maybeCondition: func(c *gin.Context) bool {
				return strings.HasPrefix(c.Request.URL.Path, "/api/")
			},
			expectMiddleware: true,
		},
		{
			name: "condition false - middleware skipped",
			path: "/public/page",
			maybeCondition: func(c *gin.Context) bool {
				return strings.HasPrefix(c.Request.URL.Path, "/api/")
			},
			expectMiddleware: false,
		},
		{
			name: "header based condition - true",
			path: "/any/path",
			maybeCondition: func(c *gin.Context) bool {
				return c.GetHeader("X-Auth") != ""
			},
			expectMiddleware: true,
		},
		{
			name: "header based condition - false",
			path: "/any/path",
			maybeCondition: func(c *gin.Context) bool {
				return c.GetHeader("X-Missing") != ""
			},
			expectMiddleware: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middlewareCalled := false

			// 创建测试中间件
			testMiddleware := func(c *gin.Context) {
				middlewareCalled = true
				c.Next()
			}

			router := gin.New()
			router.Use(Maybe(testMiddleware, tt.maybeCondition))

			router.GET(tt.path, func(c *gin.Context) {
				c.String(200, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)

			// 为 header 测试添加必要的请求头
			if tt.expectMiddleware && strings.Contains(tt.name, "header based") {
				req.Header.Set("X-Auth", "token")
			}

			middlewareCalled = false
			router.ServeHTTP(w, req)

			if middlewareCalled != tt.expectMiddleware {
				t.Errorf("middleware called = %v, want %v", middlewareCalled, tt.expectMiddleware)
			}

			if w.Code != 200 {
				t.Errorf("status code = %d, want 200", w.Code)
			}
		})
	}
}

// TestMaybe_Abort 测试 Maybe 中间件中断执行
func TestMaybe_Abort(t *testing.T) {
	gin.SetMode(gin.TestMode)

	abortMiddleware := func(c *gin.Context) {
		c.AbortWithStatus(403)
	}

	router := gin.New()
	router.Use(Maybe(abortMiddleware, func(c *gin.Context) bool {
		return true // 总是执行
	}))

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("status code = %d, want 403", w.Code)
	}

	if handlerCalled {
		t.Error("handler should not be called when middleware aborts")
	}
}

// TestMaybe_Chain 测试 Maybe 中间件链
func TestMaybe_Chain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var callOrder []string

	mw1 := func(c *gin.Context) {
		callOrder = append(callOrder, "mw1")
		c.Next()
	}

	mw2 := func(c *gin.Context) {
		callOrder = append(callOrder, "mw2")
		c.Next()
	}

	router := gin.New()

	// mw1 总是执行
	router.Use(Maybe(mw1, func(c *gin.Context) bool {
		return true
	}))

	// mw2 仅对 /api/ 路径执行
	router.Use(Maybe(mw2, func(c *gin.Context) bool {
		return strings.HasPrefix(c.Request.URL.Path, "/api/")
	}))

	router.GET("/api/test", func(c *gin.Context) {
		callOrder = append(callOrder, "handler")
		c.String(200, "ok")
	})

	router.GET("/public/test", func(c *gin.Context) {
		callOrder = append(callOrder, "handler")
		c.String(200, "ok")
	})

	// 测试 /api/ 路径 - 两个中间件都执行
	callOrder = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/test", nil)
	router.ServeHTTP(w, req)

	expected := []string{"mw1", "mw2", "handler"}
	if len(callOrder) != len(expected) {
		t.Fatalf("/api/ call order length = %d, want %d", len(callOrder), len(expected))
	}
	for i, call := range expected {
		if callOrder[i] != call {
			t.Errorf("/api/ callOrder[%d] = %q, want %q", i, callOrder[i], call)
		}
	}

	// 测试 /public/ 路径 - 只有 mw1 执行
	callOrder = nil
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/public/test", nil)
	router.ServeHTTP(w, req)

	expected = []string{"mw1", "handler"}
	if len(callOrder) != len(expected) {
		t.Fatalf("/public/ call order length = %d, want %d", len(callOrder), len(expected))
	}
	for i, call := range expected {
		if callOrder[i] != call {
			t.Errorf("/public/ callOrder[%d] = %q, want %q", i, callOrder[i], call)
		}
	}
}

// BenchmarkMaybe 性能基准测试
func BenchmarkMaybe(b *testing.B) {
	gin.SetMode(gin.TestMode)

	middleware := func(c *gin.Context) {
		c.Next()
	}

	router := gin.New()
	router.Use(Maybe(middleware, func(c *gin.Context) bool {
		return strings.HasPrefix(c.Request.URL.Path, "/api/")
	}))

	router.GET("/api/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		router.ServeHTTP(w, req)
	}
}
