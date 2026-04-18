package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	engine "github.com/darkit/gin"
)

func TestVersionCreatesGroup(t *testing.T) {
	e := engine.New()
	r := e.Router()

	v1 := Version(r, "1")
	v1.GET("/users", func(c *engine.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestVersionDefaultsAndPrefix(t *testing.T) {
	e := engine.New()
	r := e.Router()

	vDefault := Version(r, "")
	vDefault.GET("/ping", func(c *engine.Context) {
		c.String(http.StatusOK, "pong")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	v2 := Version(r, "v2")
	v2.GET("/check", func(c *engine.Context) {
		c.String(http.StatusOK, "ok")
	})

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v2/check", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestVersionedAPI(t *testing.T) {
	e := engine.New()
	r := e.Router()

	VersionedAPI(r, "3", func(v *engine.Router) {
		v.GET("/status", func(c *engine.Context) {
			c.String(http.StatusOK, "ok")
		})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v3/status", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestVersionNilRouter(t *testing.T) {
	if Version(nil, "1") != nil {
		t.Fatalf("expected nil router")
	}
	VersionedAPI(nil, "1", func(v *engine.Router) {})
	VersionedAPI(nil, "1", nil)
}
