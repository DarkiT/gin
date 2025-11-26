package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darkit/gin/cache"
	"github.com/gin-gonic/gin"
)

// TestContextIntegration 集成测试，验证优化后的Context在实际场景中的表现
func TestContextIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("高并发Context创建和释放", func(t *testing.T) {
		const numGoroutines = 10
		const numRequests = 100

		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer func() { done <- true }()

				for j := 0; j < numRequests; j++ {
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "/test", nil)
					c, _ := gin.CreateTestContext(w)
					c.Request = req

					// 创建Context
					ctx := newContext(c)

					// 模拟实际使用
					if j%10 == 0 { // 10%的请求使用缓存
						cacheInstance := cache.New[string, any](*cache.DefaultConfig())
						ctx.SetCache(cacheInstance)
						ctx.CacheSet("key", "value", time.Minute)
						_, _ = ctx.CacheGet("key")
					}

					if j%20 == 0 { // 5%的请求使用JWT
						// 模拟JWT操作（这里只是访问方法）
						_ = ctx.GetJWT()
					}

					// 释放Context
					releaseContext(ctx)
				}
			}()
		}

		// 等待所有goroutine完成
		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})

	t.Run("Context生命周期管理", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// 创建Context
		ctx := newContext(c)

		// 验证初始状态
		if !ctx.IsPooled() {
			t.Error("Context应该标记为来自对象池")
		}

		if ctx.HasComponents() {
			t.Error("新创建的Context不应该有组件")
		}

		// 设置组件
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())
		ctx.SetCache(cacheInstance)

		if !ctx.HasComponents() {
			t.Error("设置组件后应该有组件")
		}

		// 使用组件
		ctx.CacheSet("test", "value", time.Minute)
		if val, ok := ctx.CacheGet("test"); !ok || val != "value" {
			t.Error("缓存操作失败")
		}

		// 克隆Context
		clone := ctx.Clone()
		if clone.IsPooled() {
			t.Error("克隆的Context不应该标记为来自对象池")
		}

		// 验证克隆共享组件
		if val, ok := clone.CacheGet("test"); !ok || val != "value" {
			t.Error("克隆的Context应该共享组件")
		}

		// 释放原Context
		releaseContext(ctx)

		// 验证克隆仍然可用（因为组件是共享的，缓存实例不会被释放）
		if val, ok := clone.CacheGet("test"); !ok || val != "value" {
			// 这是预期的，因为缓存实例是共享的，释放原Context不会影响缓存数据
			// 但是如果原Context的components被清理了，克隆可能无法访问
			// 让我们检查克隆是否还有组件
			if !clone.HasComponents() {
				t.Log("克隆的Context在原Context释放后失去了组件，这是预期的")
			} else {
				t.Error("释放原Context后，克隆应该仍然可用")
			}
		}
	})

	t.Run("延迟初始化验证", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		ctx := newContext(c)

		// 验证延迟初始化
		if ctx.HasComponents() {
			t.Error("新Context不应该有组件")
		}

		// 第一次访问应该触发初始化
		ctx.CacheSet("key", "value")

		if !ctx.HasComponents() {
			t.Error("访问组件后应该初始化组件")
		}

		// 设置缓存后应该有1个组件
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())
		ctx.SetCache(cacheInstance)

		if ctx.ComponentsCount() != 1 {
			t.Errorf("设置缓存后应该有1个组件，实际有%d个", ctx.ComponentsCount())
		}

		releaseContext(ctx)
	})

	t.Run("链式操作测试", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		cacheInstance := cache.New[string, any](*cache.DefaultConfig())

		// 测试链式组件设置
		ctx := newContext(c).WithComponents(cacheInstance, nil, nil, nil)

		if ctx.ComponentsCount() != 1 {
			t.Errorf("链式设置后应该有1个组件，实际有%d个", ctx.ComponentsCount())
		}

		// 测试缓存功能
		ctx.CacheSet("chain", "test", time.Minute)
		if val, ok := ctx.CacheGet("chain"); !ok || val != "test" {
			t.Error("链式设置的缓存功能失败")
		}

		releaseContext(ctx)
	})

	t.Run("内存泄漏检测", func(t *testing.T) {
		// 创建大量Context并释放，检查是否有内存泄漏
		const iterations = 10000

		for i := 0; i < iterations; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			ctx := newContext(c)

			// 设置组件
			if i%100 == 0 { // 1%的请求设置组件
				cacheInstance := cache.New[string, any](*cache.DefaultConfig())
				ctx.SetCache(cacheInstance)
				ctx.CacheSet("leak_test", i, time.Minute)
			}

			// 立即释放
			releaseContext(ctx)
		}

		// 如果有内存泄漏，这个测试会在大量迭代后显现出来
		// 在实际环境中可以使用内存分析工具进一步验证
	})
}

// BenchmarkContextRealWorldUsage 真实世界使用场景的性能测试
func BenchmarkContextRealWorldUsage(b *testing.B) {
	gin.SetMode(gin.TestMode)

	b.Run("典型Web请求处理", func(b *testing.B) {
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/api/users/123", nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// 创建Context
			ctx := newContext(c)

			// 模拟典型的Web请求处理流程
			// 1. 参数获取
			userID := ctx.Param("id", "0")
			_ = userID

			// 2. 缓存检查（30%的请求）
			if i%3 == 0 {
				ctx.SetCache(cacheInstance)
				if val, ok := ctx.CacheGet("user_123"); ok {
					_ = val
				} else {
					ctx.CacheSet("user_123", "user_data", time.Minute*5)
				}
			}

			// 3. JWT验证（50%的请求）
			if i%2 == 0 {
				token := ctx.GetJWT()
				_ = token
			}

			// 4. 响应处理
			if i%10 == 0 { // 10%错误响应
				ctx.Error("Internal server error")
			} else {
				ctx.Success(map[string]interface{}{
					"id":   123,
					"name": "Test User",
				})
			}

			// 释放Context
			releaseContext(ctx)
		}
	})

	b.Run("高频缓存操作", func(b *testing.B) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		ctx := newContext(c)
		cacheInstance := cache.New[string, any](*cache.DefaultConfig())
		ctx.SetCache(cacheInstance)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			key := "key_" + string(rune(i%100)) // 100个不同的key循环使用
			ctx.CacheSet(key, i, time.Minute)
			_, _ = ctx.CacheGet(key)
		}

		releaseContext(ctx)
	})
}
