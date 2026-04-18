package gin_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
)

func TestRouterProbeRoutes(t *testing.T) {
	e := gin.New()
	r := e.Router()

	r.Liveness()
	r.Readiness(
		gin.NamedProbe("database", func(c *gin.Context) error { return nil }),
		gin.NamedProbe("redis", func(c *gin.Context) error { return errors.New("连接失败") }),
	)
	r.StartupAt("/startup", gin.NamedProbe("bootstrap", func(c *gin.Context) error { return nil }))

	t.Run("liveness", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/livez", nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp gin.ProbeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode liveness: %v", err)
		}
		if resp.Status != "alive" {
			t.Fatalf("unexpected liveness status: %s", resp.Status)
		}
	})

	t.Run("readiness", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", w.Code)
		}

		var resp gin.ProbeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode readiness: %v", err)
		}
		if resp.Status != "not_ready" {
			t.Fatalf("unexpected readiness status: %s", resp.Status)
		}
		if len(resp.Checks) != 2 {
			t.Fatalf("expected 2 checks, got %d", len(resp.Checks))
		}
	})

	t.Run("startup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/startup", nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp gin.ProbeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode startup: %v", err)
		}
		if resp.Status != "started" {
			t.Fatalf("unexpected startup status: %s", resp.Status)
		}
	})
}
