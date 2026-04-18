package security_test

import (
	"testing"
	"time"

	"github.com/darkit/gin/auth/core/config"
	"github.com/darkit/gin/auth/core/manager"
	memory "github.com/darkit/gin/auth/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager() *manager.Manager {
	cfg := config.DefaultConfig()
	cfg.TokenStyle = config.TokenStyleUUID
	cfg.Timeout = int64((30 * time.Minute).Seconds())
	return manager.NewManager(memory.NewStorage(), cfg)
}

func TestRefreshTokenFlowKeepsNewAccessTokenValid(t *testing.T) {
	mgr := newTestManager()

	initial, err := mgr.LoginWithRefreshToken("user-refresh", "web")
	require.NoError(t, err)
	require.NotEmpty(t, initial.AccessToken)
	require.NotEmpty(t, initial.RefreshToken)
	assert.True(t, mgr.IsLogin(initial.AccessToken))

	refreshed, err := mgr.RefreshAccessToken(initial.RefreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, refreshed.AccessToken)
	assert.NotEqual(t, initial.AccessToken, refreshed.AccessToken)
	assert.True(t, mgr.IsLogin(refreshed.AccessToken))
}
