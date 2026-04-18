package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
)

func TestRealIPFromXForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got string
	r := gin.New()
	r.Use(RealIP())
	r.GET("/", func(c *gin.Context) {
		got = GetRealIP(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Real-IP", "198.51.100.10")
	req.RemoteAddr = "192.0.2.5:1234"
	r.ServeHTTP(w, req)

	if got != "203.0.113.1" {
		t.Fatalf("expected x-forwarded-for ip, got %q", got)
	}
}

func TestRealIPFromXForwardedForFirst(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got string
	r := gin.New()
	r.Use(RealIP())
	r.GET("/", func(c *gin.Context) {
		got = GetRealIP(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.10")
	req.RemoteAddr = "192.0.2.5:1234"
	r.ServeHTTP(w, req)

	if got != "203.0.113.1" {
		t.Fatalf("expected first x-forwarded-for ip, got %q", got)
	}
}

func TestRealIPFromXRealIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got string
	r := gin.New()
	r.Use(RealIP())
	r.GET("/", func(c *gin.Context) {
		got = GetRealIP(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.10")
	req.RemoteAddr = "192.0.2.5:1234"
	r.ServeHTTP(w, req)

	if got != "198.51.100.10" {
		t.Fatalf("expected x-real-ip, got %q", got)
	}
}

func TestRealIPFromRemoteAddr(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got string
	r := gin.New()
	r.Use(RealIP())
	r.GET("/", func(c *gin.Context) {
		got = GetRealIP(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.5:1234"
	r.ServeHTTP(w, req)

	if got != "192.0.2.5" {
		t.Fatalf("expected remote addr ip, got %q", got)
	}
}

func TestRealIPRemoteAddrNoPort(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got string
	r := gin.New()
	r.Use(RealIP())
	r.GET("/", func(c *gin.Context) {
		got = GetRealIP(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.5"
	r.ServeHTTP(w, req)

	if got != "192.0.2.5" {
		t.Fatalf("expected remote addr ip without port, got %q", got)
	}
}

// BenchmarkRealIP 性能基准测试。
func BenchmarkRealIP(b *testing.B) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RealIP())
	r.GET("/", func(c *gin.Context) {
		_ = GetRealIP(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		r.ServeHTTP(w, req)
	}
}
