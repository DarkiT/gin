package middleware

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/darkit/gin"
)

func TestThrottle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const limit = 10
	var processing atomic.Int32
	var maxProcessing atomic.Int32

	router := gin.New()
	router.Use(Throttle(limit))

	router.GET("/test", func(c *gin.Context) {
		current := processing.Add(1)
		defer processing.Add(-1)

		// 更新最大并发数
		for {
			max := maxProcessing.Load()
			if current <= max || maxProcessing.CompareAndSwap(max, current) {
				break
			}
		}

		// 模拟处理时间
		time.Sleep(10 * time.Millisecond)
		c.String(200, "ok")
	})

	// 发送 100 个并发请求
	var wg sync.WaitGroup
	successCount := atomic.Int32{}
	rejectedCount := atomic.Int32{}

	for range 100 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)

			switch w.Code {
			case 200:
				successCount.Add(1)
			case 429:
				rejectedCount.Add(1)
			}
		})
	}

	wg.Wait()

	// 验证最大并发数不超过限制
	if max := maxProcessing.Load(); max > int32(limit) {
		t.Errorf("max concurrent requests = %d, want <= %d", max, limit)
	}

	// 应该有请求成功，也应该有请求被拒绝
	if successCount.Load() == 0 {
		t.Error("expected some requests to succeed")
	}

	t.Logf("Success: %d, Rejected: %d, Max concurrent: %d",
		successCount.Load(), rejectedCount.Load(), maxProcessing.Load())
}

func TestThrottleBacklog(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const (
		limit        = 5
		backlogLimit = 10
		timeout      = 200 * time.Millisecond
	)

	var processing atomic.Int32

	router := gin.New()
	router.Use(ThrottleBacklog(limit, backlogLimit, timeout))

	router.GET("/test", func(c *gin.Context) {
		processing.Add(1)
		defer processing.Add(-1)

		// 长时间处理
		time.Sleep(100 * time.Millisecond)
		c.String(200, "ok")
	})

	// 发送请求
	var wg sync.WaitGroup
	results := make(chan int, 50)

	for range 50 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)

			results <- w.Code
		})
		time.Sleep(time.Millisecond) // 稍微错开请求时间
	}

	wg.Wait()
	close(results)

	// 统计结果
	var success, tooManyRequests, timedOut int
	for code := range results {
		switch code {
		case 200:
			success++
		case 429:
			if code == 429 {
				tooManyRequests++
			}
		}
	}

	t.Logf("Success: %d, TooManyRequests: %d, TimedOut: %d",
		success, tooManyRequests, timedOut)

	// 应该有成功的请求
	if success == 0 {
		t.Error("expected some successful requests")
	}

	// 应该有被限流的请求
	if tooManyRequests == 0 {
		t.Error("expected some throttled requests")
	}
}

func TestThrottle_ContextCancellation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Throttle(1)) // 限制为 1 个并发

	router.GET("/test", func(c *gin.Context) {
		time.Sleep(100 * time.Millisecond)
		c.String(200, "ok")
	})

	// 启动一个长时间运行的请求占用唯一的令牌
	go func() {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
	}()

	// 等待第一个请求开始处理
	time.Sleep(10 * time.Millisecond)

	// 创建一个会被取消的请求
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	router.ServeHTTP(w, req)

	if w.Code != 429 {
		t.Errorf("status code = %d, want 429", w.Code)
	}

	if body := w.Body.String(); body != errContextCanceled {
		t.Errorf("response body = %q, want %q", body, errContextCanceled)
	}
}

func TestThrottle_RetryAfter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ThrottleWithOpts(ThrottleOpts{
		Limit: 1,
		RetryAfterFn: func(ctxDone bool) time.Duration {
			if ctxDone {
				return 0
			}
			return 60 * time.Second
		},
	}))

	router.GET("/test", func(c *gin.Context) {
		time.Sleep(100 * time.Millisecond)
		c.String(200, "ok")
	})

	// 占用唯一的令牌
	go func() {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
	}()

	time.Sleep(10 * time.Millisecond)

	// 发送第二个请求，应该被拒绝并带有 Retry-After 头
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != 429 {
		t.Errorf("status code = %d, want 429", w.Code)
	}

	retryAfter := w.Header().Get("Retry-After")
	if retryAfter != "60" {
		t.Errorf("Retry-After = %q, want \"60\"", retryAfter)
	}
}

func TestThrottle_StatusCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ThrottleWithOpts(ThrottleOpts{
		Limit:      1,
		StatusCode: 503,
	}))

	router.GET("/test", func(c *gin.Context) {
		time.Sleep(100 * time.Millisecond)
		c.String(200, "ok")
	})

	// 占用唯一的令牌
	go func() {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
	}()

	time.Sleep(10 * time.Millisecond)

	// 第二个请求应该返回自定义状态码
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != 503 {
		t.Errorf("status code = %d, want 503", w.Code)
	}
}

func TestThrottle_Panic(t *testing.T) {
	tests := []struct {
		name string
		opts ThrottleOpts
	}{
		{
			name: "zero limit",
			opts: ThrottleOpts{Limit: 0},
		},
		{
			name: "negative limit",
			opts: ThrottleOpts{Limit: -1},
		},
		{
			name: "negative backlog",
			opts: ThrottleOpts{Limit: 10, BacklogLimit: -1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic, but didn't panic")
				}
			}()

			ThrottleWithOpts(tt.opts)
		})
	}
}

func TestThrottle_Sequential(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const limit = 5
	var count atomic.Int32

	router := gin.New()
	router.Use(Throttle(limit))

	router.GET("/test", func(c *gin.Context) {
		count.Add(1)
		c.String(200, "ok")
	})

	// 顺序发送请求（不并发）
	for i := range 20 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("request %d: status code = %d, want 200", i, w.Code)
		}
	}

	// 所有请求都应该成功
	if got := count.Load(); got != 20 {
		t.Errorf("processed requests = %d, want 20", got)
	}
}

// BenchmarkThrottle 性能基准测试
func BenchmarkThrottle(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Throttle(100))

	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkThrottle_Concurrent 并发基准测试
func BenchmarkThrottle_Concurrent(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Throttle(100))

	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)

		for pb.Next() {
			w.Body.Reset()
			router.ServeHTTP(w, req)
		}
	})
}
