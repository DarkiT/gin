package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
)

func TestCORSDefaultConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(CORS())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected allow origin to be *")
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("expected allow methods")
	}
	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatalf("expected allow headers")
	}
}

func TestCORSCustomConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := CORSConfig{
		AllowOrigins:     []string{"https://allowed.com"},
		AllowMethods:     []string{"GET"},
		AllowHeaders:     []string{"X-Test"},
		ExposeHeaders:    []string{"X-Expose"},
		MaxAge:           123,
		AllowCredentials: true,
	}

	r := gin.New()
	r.Use(CORS(cfg))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://allowed.com")
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "https://allowed.com" {
		t.Fatalf("expected allow origin to match")
	}
	if w.Header().Get("Access-Control-Allow-Methods") != "GET" {
		t.Fatalf("expected allow methods GET")
	}
	if w.Header().Get("Access-Control-Allow-Headers") != "X-Test" {
		t.Fatalf("expected allow headers X-Test")
	}
	if w.Header().Get("Access-Control-Expose-Headers") != "X-Expose" {
		t.Fatalf("expected expose headers X-Expose")
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("expected allow credentials true")
	}
	if w.Header().Get("Access-Control-Max-Age") != "123" {
		t.Fatalf("expected max age 123")
	}
}

func TestCORSPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(CORS())
	r.OPTIONS("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
}
