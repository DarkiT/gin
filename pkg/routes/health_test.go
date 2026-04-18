package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	engine "github.com/darkit/gin"
)

type healthResp struct {
	Status string `json:"status"`
}

func TestHealthCheckDefaultPath(t *testing.T) {
	e := engine.New()
	r := e.Router()
	HealthCheck(r)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp healthResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Status != "healthy" {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
}

func TestHealthCheckCustomPath(t *testing.T) {
	e := engine.New()
	r := e.Router()
	HealthCheck(r, "/ready")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHealthCheckNilRouter(t *testing.T) {
	HealthCheck(nil)
}
