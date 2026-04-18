package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
)

func TestRateLimitBlocksAfterBurst(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := RateLimitConfig{RequestsPerSecond: 0, Burst: 1}
	r := gin.New()
	r.Use(RateLimit(cfg))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request ok, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}
}

func TestRateLimitAllowsWithinBurst(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := RateLimitConfig{RequestsPerSecond: 1000, Burst: 2}
	r := gin.New()
	r.Use(RateLimit(cfg))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected ok, got %d", w.Code)
		}
	}
}
