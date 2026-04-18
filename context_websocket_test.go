package gin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/pkg/websocket"
	"github.com/gin-gonic/gin"
)

func TestUpgradeWebSocket_DefaultOrigin(t *testing.T) {
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/ws", nil)
	ctx := &engine.Context{Context: ginCtx}
	ctx.SetEngine(engine.New())

	if _, err := ctx.UpgradeWebSocket("", nil); err == nil {
		t.Fatalf("expected upgrade to fail in test context without websocket handshake")
	}
}

func TestUpgradeWebSocket_CheckOriginAllowed(t *testing.T) {
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/ws", nil)
	ginCtx.Request.Header.Set("Origin", "https://example.com")
	ctx := &engine.Context{Context: ginCtx}
	ctx.SetEngine(engine.New())

	_, err := ctx.UpgradeWebSocket("", websocket.WithWSCheckOrigin(func(r *http.Request) bool {
		return r.Header.Get("Origin") == "https://example.com"
	}))
	if err == nil {
		t.Fatalf("expected upgrade to fail in test context without websocket handshake")
	}
}
