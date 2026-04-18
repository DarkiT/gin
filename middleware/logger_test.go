package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/darkit/gin"
)

func TestLoggerOutputs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var buf bytes.Buffer
	oldStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = wPipe
	defer func() {
		os.Stdout = oldStdout
	}()

	r := gin.New()
	r.Use(Logger())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	_ = wPipe.Close()
	_, _ = io.Copy(&buf, rPipe)
	_ = rPipe.Close()

	out := buf.String()
	if !strings.Contains(out, "GET") || !strings.Contains(out, "/") || !strings.Contains(out, "201") {
		t.Fatalf("expected log output to contain method, path, status")
	}
	if !strings.Contains(out, "[GIN]") {
		t.Fatalf("expected log prefix")
	}
}
