package gin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darkit/gin/auth"
	gingonic "github.com/gin-gonic/gin"
)

func TestWithAuthDefersManagerCreationUntilRuntimeReady(t *testing.T) {
	e := New(WithAuth(auth.AuthConfig{
		Secret:     "test-secret",
		Expiry:     24 * time.Hour,
		TokenStyle: auth.TokenStyleJWT,
	}))

	if e.authManager != nil {
		t.Fatalf("expected auth manager to be nil before runtime start")
	}

	if err := e.ensureRuntimeReady(context.TODO()); err != nil {
		t.Fatalf("ensureRuntimeReady: %v", err)
	}

	if e.authManager == nil {
		t.Fatalf("expected auth manager to be initialized after runtime start")
	}
}

func TestAuthManagerStopsOnShutdown(t *testing.T) {
	e := New(WithAuth(auth.AuthConfig{
		Secret:     "test-secret",
		Expiry:     24 * time.Hour,
		TokenStyle: auth.TokenStyleJWT,
	}))

	if err := e.ensureRuntimeReady(context.TODO()); err != nil {
		t.Fatalf("ensureRuntimeReady: %v", err)
	}
	if e.authManager == nil {
		t.Fatalf("expected auth manager initialized")
	}

	if err := e.Shutdown(context.TODO()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if e.authManager != nil {
		t.Fatalf("expected auth manager cleared on shutdown")
	}
}

func TestServeHTTPLazilyInitializesAuthForRequests(t *testing.T) {
	e := New(WithAuth(auth.AuthConfig{
		Secret:     "test-secret",
		Expiry:     24 * time.Hour,
		TokenStyle: auth.TokenStyleJWT,
	}))

	e.GET("/login", func(c *Context) {
		token, err := c.Auth().Login("user-1", "web")
		if err != nil {
			c.InternalError(err.Error())
			return
		}
		c.Success(H{"token": token})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if e.authManager == nil {
		t.Fatalf("expected auth manager to be initialized by request path")
	}
}

func TestAuthContextWithoutRuntimeReadyReturnsNotConfigured(t *testing.T) {
	e := New(WithAuth(auth.AuthConfig{
		Secret:     "test-secret",
		Expiry:     24 * time.Hour,
		TokenStyle: auth.TokenStyleJWT,
	}))

	rawCtx, _ := gingonic.CreateTestContext(httptest.NewRecorder())
	rawCtx.Request = httptest.NewRequest(http.MethodGet, "/auth", nil)

	ctx := &Context{Context: rawCtx, engine: e}
	_, err := ctx.Auth().Login("user-1")
	if !errors.Is(err, auth.ErrAuthNotConfigured) {
		t.Fatalf("expected ErrAuthNotConfigured before runtime ready, got %v", err)
	}
}
