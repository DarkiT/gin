package diagnostic

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	engine "github.com/darkit/gin"
)

func TestInspectorGetStatus(t *testing.T) {
	e := engine.New()
	r := e.Router()
	r.GET("/ping", func(c *engine.Context) {
		c.String(http.StatusOK, "pong")
	})

	inspector := NewInspector(e)
	status := inspector.GetStatus()
	if status == nil {
		t.Fatalf("status nil")
	}
	if status.GoVersion == "" {
		t.Fatalf("go version empty")
	}
	if status.NumGoroutine <= 0 {
		t.Fatalf("num goroutine invalid")
	}
	if status.Memory == nil {
		t.Fatalf("memory nil")
	}
	if status.Routes == nil || status.Routes.Count == 0 {
		t.Fatalf("routes missing")
	}
}

func TestInspectorPrintRoutes(t *testing.T) {
	e := engine.New()
	e.GET("/print", func(c *engine.Context) {
		c.String(http.StatusOK, "ok")
	})
	e.RegexRouter().GET("/print/{id:[0-9]+}", func(c *engine.Context) {
		c.String(http.StatusOK, c.Param("id"))
	})

	inspector := NewInspector(e)
	buf := &bytes.Buffer{}
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w
	inspector.PrintRoutes()
	_ = w.Close()
	os.Stdout = old
	_, _ = io.Copy(buf, r)
	if !strings.Contains(buf.String(), "/print") {
		t.Fatalf("expected output contains route")
	}
	if !strings.Contains(buf.String(), "/print/{id:[0-9]+}") {
		t.Fatalf("expected output contains regex route")
	}
}

func TestInspectorHandler(t *testing.T) {
	e := engine.New()
	inspector := NewInspector(e)
	start := time.Now()

	e.GET("/diag", inspector.Handler())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/diag", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var status Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if status.Uptime == "" {
		t.Fatalf("uptime empty")
	}
	if time.Since(start) < 0 {
		t.Fatalf("invalid uptime")
	}
}

func TestInspectorNilEngine(t *testing.T) {
	inspector := NewInspector(nil)
	status := inspector.GetStatus()
	if status.Routes == nil {
		t.Fatalf("routes nil")
	}
	if status.Routes.Count != 0 {
		t.Fatalf("expected 0 routes")
	}

	inspector.PrintRoutes()
}
