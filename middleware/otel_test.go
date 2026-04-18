package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	engine "github.com/darkit/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestOTelMiddleware(t *testing.T) {
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()

	provider := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer func() {
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
		_ = provider.Shutdown(context.Background())
	}()

	e := engine.New()
	r := e.Router()
	r.Use(OTel("test-service"))
	r.GET("/trace", func(c *engine.Context) {
		c.JSON(http.StatusOK, engine.H{
			"trace_id": c.TraceID(),
			"span_id":  c.SpanID(),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/trace", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["trace_id"] == "" {
		t.Fatalf("expected trace_id to be populated")
	}
	if payload["span_id"] == "" {
		t.Fatalf("expected span_id to be populated")
	}
}
