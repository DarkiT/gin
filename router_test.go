package gin

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// 测试路由器初始化
func TestNewRouter(t *testing.T) {
	router := NewRouter(nil)
	assert.NotNil(t, router)
	assert.NotNil(t, router.engine)
	assert.NotNil(t, router.groups)
	assert.NotNil(t, router.routes)
}

// 测试路由注册
func TestRouterRegister(t *testing.T) {
	router := NewRouter(nil)

	// 注册路由
	router.GET("/test", func(c *Context) {
		c.String(http.StatusOK, "test")
	})

	// 验证路由已注册
	routes := router.GetRoutes()
	assert.Equal(t, 1, len(routes))
	assert.Contains(t, routes, "GET:/test")
}

// 测试路由冲突检测
func TestRouterConflict(t *testing.T) {
	router := NewRouter(nil)

	// 注册首个路由
	router.GET("/test", func(c *Context) {
		c.String(http.StatusOK, "test1")
	})

	// 尝试注册冲突路由，应该被忽略
	router.GET("/test", func(c *Context) {
		c.String(http.StatusOK, "test2")
	})

	// 验证路由数量仍为1
	routes := router.GetRoutes()
	assert.Equal(t, 1, len(routes))

	// 测试请求以验证第一个处理程序仍然生效
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "test1", w.Body.String()) // 应该是第一个处理程序的输出
}

// 测试路由组
func TestRouterGroup(t *testing.T) {
	router := NewRouter(nil)

	// 创建路由组
	api := router.Group("/api")

	// 在组中注册路由
	api.GET("/test", func(c *Context) {
		c.String(http.StatusOK, "api-test")
	})

	// 验证路由已注册
	routes := router.GetRoutes()
	assert.Equal(t, 1, len(routes))
	assert.Contains(t, routes, "GET:/api/test")

	// 测试请求
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/test", nil)
	router.engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "api-test", w.Body.String())
}

// 测试嵌套路由组和路径处理
func TestNestedRouterGroup(t *testing.T) {
	router := NewRouter(nil)

	// 创建嵌套路由组
	api := router.Group("/api/")
	v1 := api.Group("/v1/")
	users := v1.Group("users")

	// 在最深层组中注册路由
	users.GET("/list", func(c *Context) {
		c.String(http.StatusOK, "users-list")
	})

	// 验证路由已正确注册（路径正确规范化）
	routes := router.GetRoutes()
	assert.Equal(t, 1, len(routes))
	assert.Contains(t, routes, "GET:/api/v1/users/list")

	// 测试请求
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/users/list", nil)
	router.engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "users-list", w.Body.String())
}

// 测试并发注册路由
func TestConcurrentRouteRegistration(t *testing.T) {
	router := NewRouter(nil)
	var wg sync.WaitGroup

	// 并发注册100个路由
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/test/" + string(rune('a'+i%26))
			router.GET(path, func(c *Context) {
				c.String(http.StatusOK, path)
			})
		}(i)
	}

	wg.Wait()

	// 验证路由数量（可能少于100因为有冲突）
	routes := router.GetRoutes()
	assert.LessOrEqual(t, 26, len(routes)) // 至少应该有26个不同的路由（a-z）
}

// 测试RESTful资源路由
func TestResourceRouting(t *testing.T) {
	router := NewRouter(nil)

	// 创建自定义资源处理器
	handler := &testResourceHandler{}

	// 注册资源
	router.Resource("/users", handler)

	// 验证6个RESTful路由已注册（GET, GET/:id, POST, PUT/:id, PATCH/:id, DELETE/:id）
	routes := router.GetRoutes()
	assert.Equal(t, 6, len(routes))
	assert.Contains(t, routes, "GET:/users")
	assert.Contains(t, routes, "GET:/users/:id")
	assert.Contains(t, routes, "POST:/users")
	assert.Contains(t, routes, "PUT:/users/:id")
	assert.Contains(t, routes, "PATCH:/users/:id")
	assert.Contains(t, routes, "DELETE:/users/:id")
}

// 测试路由组中的资源路由
func TestResourceRoutingInGroup(t *testing.T) {
	router := NewRouter(nil)
	api := router.Group("/api")

	// 创建自定义资源处理器
	handler := &testResourceHandler{}

	// 在组中注册资源
	api.Resource("/users", handler)

	// 验证6个RESTful路由已注册
	routes := router.GetRoutes()
	assert.Equal(t, 6, len(routes))
	assert.Contains(t, routes, "GET:/api/users")
	assert.Contains(t, routes, "GET:/api/users/:id")
	assert.Contains(t, routes, "POST:/api/users")
	assert.Contains(t, routes, "PUT:/api/users/:id")
	assert.Contains(t, routes, "PATCH:/api/users/:id")
	assert.Contains(t, routes, "DELETE:/api/users/:id")
}

// 测试缓存中间件
func TestCacheMiddleware(t *testing.T) {
	router := NewRouter(nil)

	// 添加缓存中间件
	router.Use(router.SetGlobalCacheMiddleware(5*time.Minute, 10*time.Minute))

	// 验证路由器的缓存实例已设置
	assert.NotNil(t, router.cache)

	// 注册测试路由
	router.GET("/cache-test", func(c *Context) {
		// 获取全局缓存
		cache := c.GetGlobalCache()
		assert.NotNil(t, cache)

		// 尝试使用缓存
		cache.Set("test-key", "test-value", 1*time.Minute)
		value, found := cache.Get("test-key")

		assert.True(t, found)
		assert.Equal(t, "test-value", value)

		c.String(http.StatusOK, "cache-ok")
	})

	// 测试请求
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/cache-test", nil)
	router.engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "cache-ok", w.Body.String())
}

// 测试Close方法
func TestRouterClose(t *testing.T) {
	router := NewRouter(nil)

	// 添加缓存中间件
	router.Use(router.SetGlobalCacheMiddleware(5*time.Minute, 10*time.Minute))

	// 注册一些路由
	router.GET("/test1", func(c *Context) {})
	router.GET("/test2", func(c *Context) {})

	// 关闭路由器
	err := router.Close()
	assert.Nil(t, err)

	// 验证资源已释放
	assert.Nil(t, router.cache)
	assert.Equal(t, 0, len(router.groups))
	assert.Equal(t, 0, len(router.routes))
}

// 测试资源处理器
type testResourceHandler struct {
	RestfulHandler // 嵌入默认实现
}

// 覆盖一些方法以进行测试
func (h *testResourceHandler) Index(c *Context) {
	c.String(http.StatusOK, "index")
}

func (h *testResourceHandler) Show(c *Context) {
	c.String(http.StatusOK, "show:"+c.Param("id"))
}
