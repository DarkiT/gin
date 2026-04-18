package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darkit/gin"
)

func TestTimeoutAborts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Timeout(10 * time.Millisecond))
	r.GET("/", func(c *gin.Context) {
		time.Sleep(30 * time.Millisecond)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestTimeout {
		t.Fatalf("expected 408, got %d", w.Code)
	}
}

func TestTimeoutAllowsFastHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Timeout(50 * time.Millisecond))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
