package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darkit/gin"
)

func TestCircuitBreaker_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(CircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}))

	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// 发送成功请求
	for i := range 5 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, w.Code)
		}
	}
}

func TestCircuitBreaker_FailureThreshold(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(CircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          200 * time.Millisecond,
	}))

	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusInternalServerError)
	})

	// 发送失败请求直到熔断器打开
	for i := range 3 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("request %d: expected 500, got %d", i, w.Code)
		}
	}

	// 熔断器应该已打开，下一个请求应该被拒绝
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (circuit open), got %d", w.Code)
	}
}

func TestCircuitBreaker_HalfOpenRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	failureCount := 0
	r := gin.New()
	r.Use(CircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}))

	r.GET("/", func(c *gin.Context) {
		if failureCount < 2 {
			failureCount++
			c.Status(http.StatusInternalServerError)
		} else {
			c.Status(http.StatusOK)
		}
	})

	// 触发失败导致熔断器打开
	for range 2 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		r.ServeHTTP(w, req)
	}

	// 熔断器打开，请求被拒绝
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	// 等待超时进入半开状态
	time.Sleep(150 * time.Millisecond)

	// 半开状态，发送成功请求
	for i := range 2 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("half-open request %d: expected 200, got %d", i, w.Code)
		}
	}

	// 熔断器应该已关闭，请求正常通过
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (circuit closed), got %d", w.Code)
	}
}

func TestCircuitBreaker_DefaultConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(CircuitBreaker())

	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
