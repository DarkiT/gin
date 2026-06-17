package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/cache"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestCache_Hit 测试缓存命中
func TestCache_Hit(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.GET("/test", Cache(time.Minute), func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"message": "hello", "count": callCount})
	})

	// 第一次请求 - 缓存未命中
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
	assert.Contains(t, w1.Body.String(), `"count":1`)

	// 第二次请求 - 缓存命中
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
	assert.Contains(t, w2.Body.String(), `"count":1`) // 返回缓存的内容
	assert.Equal(t, 1, callCount)                     // 处理器只调用一次
}

// TestCache_Miss 测试缓存未命中
func TestCache_Miss(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.GET("/test/:id", Cache(time.Minute), func(c *gin.Context) {
		callCount++
		id := c.Param("id")
		c.JSON(http.StatusOK, gin.H{"id": id, "count": callCount})
	})

	// 请求不同的 URL，缓存未命中
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test/1", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
	assert.Contains(t, w1.Body.String(), `"id":"1"`)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test/2", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "MISS", w2.Header().Get("X-Cache"))
	assert.Contains(t, w2.Body.String(), `"id":"2"`)
	assert.Equal(t, 2, callCount) // 处理器调用两次
}

// TestCache_Expiry 测试缓存过期
func TestCache_Expiry(t *testing.T) {
	router := gin.New()
	callCount := 0

	// 设置 100ms 过期时间
	router.GET("/test", Cache(100*time.Millisecond), func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"message": "hello", "count": callCount})
	})

	// 第一次请求
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
	assert.Contains(t, w1.Body.String(), `"count":1`)

	// 第二次请求（立即） - 缓存命中
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
	assert.Contains(t, w2.Body.String(), `"count":1`)

	// 等待缓存过期
	time.Sleep(150 * time.Millisecond)

	// 第三次请求 - 缓存过期，重新请求
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w3, req3)

	assert.Equal(t, "MISS", w3.Header().Get("X-Cache"))
	assert.Contains(t, w3.Body.String(), `"count":2`)
	assert.Equal(t, 2, callCount)
}

// TestCacheIf_Condition 测试条件缓存
func TestCacheIf_Condition(t *testing.T) {
	router := gin.New()
	callCount := 0

	// 当没有 nocache 参数时缓存
	router.GET("/test", CacheIf(func(c *gin.Context) bool {
		return c.Query("nocache") == ""
	}, time.Minute), func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"message": "hello", "count": callCount})
	})

	// 第一次请求 - 不带 nocache 参数，缓存
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
	assert.Contains(t, w1.Body.String(), `"count":1`)

	// 第二次请求 - 不带 nocache 参数，缓存命中
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
	assert.Contains(t, w2.Body.String(), `"count":1`)
	assert.Equal(t, 1, callCount)

	// 第三次请求 - 带 nocache 参数，不缓存
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", "/test?nocache=1", nil)
	router.ServeHTTP(w3, req3)

	assert.Empty(t, w3.Header().Get("X-Cache")) // 不使用缓存
	assert.Contains(t, w3.Body.String(), `"count":2`)
	assert.Equal(t, 2, callCount)
}

// TestCache_CustomKey 测试自定义缓存键
func TestCache_CustomKey(t *testing.T) {
	router := gin.New()
	callCount := 0

	// 使用自定义键生成函数（只使用路径，忽略查询参数）
	router.GET("/test", Cache(
		time.Minute,
		WithCacheKey(func(c *gin.Context) string {
			return "cache:custom:" + c.Request.URL.Path
		}),
	), func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"message": "hello", "count": callCount})
	})

	// 第一次请求
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test?param=1", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
	assert.Contains(t, w1.Body.String(), `"count":1`)

	// 第二次请求 - 不同的查询参数，但路径相同，缓存命中
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test?param=2", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
	assert.Contains(t, w2.Body.String(), `"count":1`)
	assert.Equal(t, 1, callCount)
}

// TestCache_OnlyGetHead 测试只缓存 GET 和 HEAD 请求
func TestCache_OnlyGetHead(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.POST("/test", Cache(time.Minute), func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"message": "hello", "count": callCount})
	})

	// POST 请求不应该被缓存
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/test", nil)
	router.ServeHTTP(w1, req1)

	assert.Empty(t, w1.Header().Get("X-Cache"))

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Empty(t, w2.Header().Get("X-Cache"))
	assert.Equal(t, 2, callCount) // 每次都调用
}

// TestCache_OnlySuccessResponses 测试只缓存成功响应
func TestCache_OnlySuccessResponses(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.GET("/test", Cache(time.Minute), func(c *gin.Context) {
		callCount++
		if callCount == 1 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 第一次请求 - 失败响应
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusInternalServerError, w1.Code)

	// 第二次请求 - 成功响应（失败响应未被缓存）
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Contains(t, w2.Body.String(), "success")
	assert.Equal(t, 2, callCount)
}

// TestCache_WithCacheControl 测试 Cache-Control 头
func TestCache_WithCacheControl(t *testing.T) {
	router := gin.New()

	router.GET("/test", Cache(
		time.Minute,
		WithCacheControl("public, max-age=60"),
	), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "hello"})
	})

	// 第一次请求
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	// 第二次请求 - 检查 Cache-Control 头
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
	assert.Equal(t, "public, max-age=60", w2.Header().Get("Cache-Control"))
}

// TestCache_WithVary 测试 Vary 头
func TestCache_WithVary(t *testing.T) {
	router := gin.New()

	router.GET("/test", Cache(
		time.Minute,
		WithCacheVary("Accept-Language", "Accept-Encoding"),
	), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "hello"})
	})

	// 第一次请求
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	// 第二次请求 - 检查 Vary 头
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
	varyHeaders := w2.Header().Values("Vary")
	assert.Contains(t, varyHeaders, "Accept-Language")
	assert.Contains(t, varyHeaders, "Accept-Encoding")
}

// TestCache_WithCustomStore 测试自定义存储
func TestCache_WithCustomStore(t *testing.T) {
	store := cache.NewMemory()
	router := gin.New()
	callCount := 0

	router.GET("/test", Cache(
		time.Minute,
		WithCacheStore(store),
	), func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"message": "hello", "count": callCount})
	})

	// 第一次请求
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))

	// 第二次请求 - 缓存命中
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
	assert.Equal(t, 1, callCount)
}

// TestETag_NotModified 测试 304 Not Modified 响应
func TestETag_NotModified(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.GET("/test", ETag(), func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"message": "hello world"})
	})

	// 第一次请求 - 获取 ETag
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	etag := w1.Header().Get("ETag")
	assert.NotEmpty(t, etag)
	assert.Contains(t, w1.Body.String(), "hello world")

	// 第二次请求 - 带 If-None-Match 头，ETag 匹配
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("If-None-Match", etag)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusNotModified, w2.Code)
	assert.Equal(t, etag, w2.Header().Get("ETag"))
	assert.Empty(t, w2.Body.String()) // 304 响应不包含 body
	assert.Equal(t, 2, callCount)     // 处理器仍然被调用
}

// TestETag_Modified 测试 ETag 不匹配时返回完整响应
func TestETag_Modified(t *testing.T) {
	router := gin.New()

	router.GET("/test", ETag(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "hello world"})
	})

	// 第一次请求
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	etag1 := w1.Header().Get("ETag")

	// 第二次请求 - 带不匹配的 If-None-Match 头
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("If-None-Match", `"different-etag"`)
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, etag1, w2.Header().Get("ETag"))
	assert.Contains(t, w2.Body.String(), "hello world")
}

// TestETag_OnlyGetHead 测试只处理 GET 和 HEAD 请求
func TestETag_OnlyGetHead(t *testing.T) {
	router := gin.New()

	router.POST("/test", ETag(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "hello"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("ETag")) // POST 不生成 ETag
}

// TestETag_OnlySuccessResponses 测试只对成功响应生成 ETag
func TestETag_OnlySuccessResponses(t *testing.T) {
	router := gin.New()

	router.GET("/test", ETag(), func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Header().Get("ETag")) // 非成功响应不生成 ETag
}

// TestETag_DifferentContent 测试不同内容生成不同的 ETag
func TestETag_DifferentContent(t *testing.T) {
	router := gin.New()
	content := "hello"

	router.GET("/test", ETag(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": content})
	})

	// 第一次请求
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	etag1 := w1.Header().Get("ETag")

	// 修改内容
	content = "world"

	// 第二次请求
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w2, req2)

	etag2 := w2.Header().Get("ETag")

	assert.NotEqual(t, etag1, etag2) // 不同内容应该有不同的 ETag
}

func TestCache_SkipsAuthenticatedRequestsByDefault(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.GET("/profile", Cache(time.Minute), func(c *gin.Context) {
		callCount++
		c.String(http.StatusOK, c.GetHeader("Authorization")+":call-%d", callCount)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req1.Header.Set("Authorization", "Bearer user-a")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req2.Header.Set("Authorization", "Bearer user-b")
	router.ServeHTTP(w2, req2)

	assert.Empty(t, w1.Header().Get("X-Cache"))
	assert.Empty(t, w2.Header().Get("X-Cache"))
	assert.Contains(t, w1.Body.String(), "Bearer user-a:call-1")
	assert.Contains(t, w2.Body.String(), "Bearer user-b:call-2")
	assert.Equal(t, 2, callCount)
}

func TestCache_VaryRequestHeadersPartitionCacheKey(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.GET("/localized", Cache(
		time.Minute,
		WithCacheVary("Accept-Language"),
	), func(c *gin.Context) {
		callCount++
		c.String(http.StatusOK, c.GetHeader("Accept-Language")+":call-%d", callCount)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/localized", nil)
	req1.Header.Set("Accept-Language", "en-US")
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/localized", nil)
	req2.Header.Set("Accept-Language", "zh-CN")
	router.ServeHTTP(w2, req2)

	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/localized", nil)
	req3.Header.Set("Accept-Language", "en-US")
	router.ServeHTTP(w3, req3)

	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
	assert.Equal(t, "MISS", w2.Header().Get("X-Cache"))
	assert.Equal(t, "HIT", w3.Header().Get("X-Cache"))
	assert.Contains(t, w1.Body.String(), "en-US:call-1")
	assert.Contains(t, w2.Body.String(), "zh-CN:call-2")
	assert.Contains(t, w3.Body.String(), "en-US:call-1")
	assert.Equal(t, 2, callCount)
}

func TestCache_DoesNotStorePrivateOrCookieResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler func(*gin.Context, int)
	}{
		{
			name: "set cookie",
			handler: func(c *gin.Context, calls int) {
				c.SetCookie("sid", "abc", 60, "/", "", false, true)
				c.String(http.StatusOK, "cookie-call-%d", calls)
			},
		},
		{
			name: "private cache control",
			handler: func(c *gin.Context, calls int) {
				c.Header("Cache-Control", "private, max-age=60")
				c.String(http.StatusOK, "private-call-%d", calls)
			},
		},
		{
			name: "no store cache control",
			handler: func(c *gin.Context, calls int) {
				c.Header("Cache-Control", "no-store")
				c.String(http.StatusOK, "no-store-call-%d", calls)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			callCount := 0
			router.GET("/sensitive", Cache(time.Minute), func(c *gin.Context) {
				callCount++
				tt.handler(c, callCount)
			})

			w1 := httptest.NewRecorder()
			req1 := httptest.NewRequest(http.MethodGet, "/sensitive", nil)
			router.ServeHTTP(w1, req1)

			w2 := httptest.NewRecorder()
			req2 := httptest.NewRequest(http.MethodGet, "/sensitive", nil)
			router.ServeHTTP(w2, req2)

			assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
			assert.Equal(t, "MISS", w2.Header().Get("X-Cache"))
			assert.Equal(t, 2, callCount)
		})
	}
}

func TestCache_WithSkipFunc(t *testing.T) {
	router := gin.New()
	callCount := 0

	router.GET("/skip", Cache(
		time.Minute,
		WithCacheSkip(func(c *gin.Context) bool {
			return c.Query("skip") == "1"
		}),
	), func(c *gin.Context) {
		callCount++
		c.String(http.StatusOK, "call-%d", callCount)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/skip?skip=1", nil)
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/skip?skip=1", nil)
	router.ServeHTTP(w2, req2)

	assert.Empty(t, w1.Header().Get("X-Cache"))
	assert.Empty(t, w2.Header().Get("X-Cache"))
	assert.Equal(t, "call-1", w1.Body.String())
	assert.Equal(t, "call-2", w2.Body.String())
}
