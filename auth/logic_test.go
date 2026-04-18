package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStpLogic_AuthAndPermissionFlow(t *testing.T) {
	mgr := setupTestManager()
	logic := NewStpLogic(mgr)

	token, err := logic.Login("logic-user", "web")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.True(t, logic.IsLogin(token))

	err = logic.SetPermissions("logic-user", []string{"user:read", "user:write"})
	require.NoError(t, err)
	assert.True(t, logic.HasPermission("logic-user", "user:read"))
	require.NoError(t, logic.CheckPermission(token, "user:write"))

	err = logic.SetRoles("logic-user", []string{"admin", "user"})
	require.NoError(t, err)
	assert.True(t, logic.HasRole("logic-user", "admin"))
	require.NoError(t, logic.CheckRole(token, "admin"))

	perms, err := logic.GetPermissionList(token)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user:read", "user:write"}, perms)

	roles, err := logic.GetRoleList(token)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "user"}, roles)
}

func TestGlobalLogicAliases(t *testing.T) {
	mgr := setupTestManager()
	SetGlobalManager(mgr)
	defer CloseGlobalManager()

	logic := GetStpLogic()
	require.NotNil(t, logic)
	assert.Same(t, mgr, GetGlobalManager())

	token, err := Login("global-logic-user", "pc")
	require.NoError(t, err)
	assert.True(t, logic.IsLogin(token))
}

func TestAuthContext_RefreshToken(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	info, err := mgr.LoginWithRefreshToken("refresh-auth-user", "web")
	require.NoError(t, err)
	require.NotNil(t, info)
	require.NotEmpty(t, info.AccessToken)
	require.NotEmpty(t, info.RefreshToken)

	newToken, err := authCtx.RefreshToken(info.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newToken)
	assert.NotEqual(t, info.AccessToken, newToken)
	assert.True(t, mgr.IsLogin(newToken))
}

func TestStpLogic_DisableCheck(t *testing.T) {
	mgr := setupTestManager()
	logic := NewStpLogic(mgr)

	token, err := logic.Login("disabled-user")
	require.NoError(t, err)
	require.NoError(t, logic.Disable("disabled-user", time.Minute))
	assert.Error(t, logic.CheckDisable(token))
}

func TestNewManager_Loaders(t *testing.T) {
	storage := NewMemoryStorage()
	cfg := DefaultAuthConfig()
	permissionCalls := 0
	roleCalls := 0
	cfg.PermissionLoader = func(loginID string) ([]string, error) {
		permissionCalls++
		return []string{"user:read", "user:write"}, nil
	}
	cfg.RoleLoader = func(loginID string) ([]string, error) {
		roleCalls++
		return []string{"admin"}, nil
	}

	mgr := NewManager(storage, &cfg)
	_, authCtx := setupTestContext(mgr)
	token, err := authCtx.Login("loader-user")
	require.NoError(t, err)
	authCtx.tokenValue = token

	perms, err := authCtx.GetPermissions("loader-user")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user:read", "user:write"}, perms)
	assert.True(t, authCtx.HasPermission("user:read"))

	roles, err := authCtx.GetRoles("loader-user")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin"}, roles)
	assert.True(t, authCtx.HasRole("admin"))

	assert.Equal(t, 1, permissionCalls)
	assert.Equal(t, 1, roleCalls)
}
