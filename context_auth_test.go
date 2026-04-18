package gin

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin/auth"
	gingonic "github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextAuthWithoutConfigSafe(t *testing.T) {
	gingonic.SetMode(gingonic.TestMode)
	w := httptest.NewRecorder()
	rawCtx, _ := gingonic.CreateTestContext(w)
	rawCtx.Request = httptest.NewRequest("GET", "/auth", nil)

	ctx := &Context{Context: rawCtx, engine: New()}

	require.NotPanics(t, func() {
		authCtx := ctx.Auth()
		require.NotNil(t, authCtx)
		assert.False(t, authCtx.IsLogin())
		_, err := authCtx.Login("user-1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrAuthNotConfigured))
	})
}
