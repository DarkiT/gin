package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
	"github.com/google/uuid"
)

func TestRequestIDGenerates(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RequestID())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	id := w.Header().Get(RequestIDKey)
	if id == "" {
		t.Fatalf("expected request id header")
	}
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("invalid uuid: %v", err)
	}
}

func TestRequestIDUsesExisting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got string
	r := gin.New()
	r.Use(RequestID())
	r.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("request_id"); ok {
			got, _ = v.(string)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDKey, "abc-123")
	r.ServeHTTP(w, req)

	if got != "abc-123" {
		t.Fatalf("expected request_id to match header")
	}
	if w.Header().Get(RequestIDKey) != "abc-123" {
		t.Fatalf("expected response header to match")
	}
}
