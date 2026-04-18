package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
)

func TestNoCacheHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(NoCache())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	expected := map[string]string{
		"Cache-Control": "no-cache, no-store, max-age=0, must-revalidate",
		"Pragma":        "no-cache",
		"Expires":       "0",
	}
	for k, v := range expected {
		if w.Header().Get(k) != v {
			t.Fatalf("expected header %s=%s", k, v)
		}
	}
}

func TestNoCacheDoesNotChangeBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(NoCache())
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Body.String() != "ok" {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

// BenchmarkNoCache 性能基准测试。
func BenchmarkNoCache(b *testing.B) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(NoCache())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		r.ServeHTTP(w, req)
	}
}
