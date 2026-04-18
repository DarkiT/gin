package middleware

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/darkit/gin"
)

func TestRecoveryRecoversPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RecoveryWithWriter(nil))
	r.GET("/", func(c *gin.Context) {
		panic("boom")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestRecoveryLogs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	buf := &strings.Builder{}
	r := gin.New()
	r.Use(RecoveryWithWriter(buf))
	r.GET("/", func(c *gin.Context) {
		panic("boom")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if !strings.Contains(buf.String(), "panic recovered") {
		t.Fatalf("expected recovery log")
	}
}

func TestRecoveryBrokenPipe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	syscallErr := &os.SyscallError{Syscall: "write", Err: errors.New("broken pipe")}
	opErr := &net.OpError{Err: syscallErr}

	r := gin.New()
	r.Use(RecoveryWithWriter(nil))
	r.GET("/", func(c *gin.Context) {
		panic(opErr)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for broken pipe, got %d", w.Code)
	}
}
