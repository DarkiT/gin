package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestManager 创建测试用的 Manager
func setupTestManager() *Manager {
	storage := NewMemoryStorage()
	cfg := DefaultAuthConfig()
	cfg.TokenStyle = TokenStyleUUID
	cfg.Expiry = 1 * time.Hour
	cfg.ReadFromCookie = true // 启用 Cookie 读取用于测试

	return NewManager(storage, &cfg)
}

// setupTestContext 创建测试用的 Gin Context 和 AuthContext
func setupTestContext(mgr *Manager) (*gin.Context, *AuthContext) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	ginCtx := NewGinRequestContext(c)
	authCtx := NewAuthContext(ginCtx, mgr)

	return c, authCtx
}

func TestAuthContext_Login(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 测试登录
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// 测试重复登录（共享 Token）
	token2, err := authCtx.Login("user123")
	require.NoError(t, err)
	assert.Equal(t, token, token2, "共享 Token 模式下应返回相同 Token")
}

func TestAuthContext_LoginWithDevice(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 不同设备登录
	tokenPC, err := authCtx.Login("user123", "PC")
	require.NoError(t, err)

	tokenMobile, err := authCtx.Login("user123", "Mobile")
	require.NoError(t, err)

	assert.NotEqual(t, tokenPC, tokenMobile, "不同设备应生成不同 Token")
}

func TestAuthContext_Logout(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 先登录
	token, err := authCtx.Login("user123")
	require.NoError(t, err)

	// 设置 Token 到请求上下文
	authCtx.tokenValue = token

	// 登出
	err = authCtx.Logout()
	require.NoError(t, err)

	// 验证已登出
	assert.False(t, mgr.IsLogin(token))
}

func TestAuthContext_IsLogin(t *testing.T) {
	mgr := setupTestManager()
	c, authCtx := setupTestContext(mgr)

	// 未登录
	assert.False(t, authCtx.IsLogin())

	// 登录
	token, err := authCtx.Login("user123")
	require.NoError(t, err)

	// 设置 Token 到 Header
	c.Request.Header.Set("satoken", token)

	// 重新创建 AuthContext（清除缓存）
	ginCtx := NewGinRequestContext(c)
	authCtx = NewAuthContext(ginCtx, mgr)

	// 已登录
	assert.True(t, authCtx.IsLogin())
}

func TestAuthContext_CheckLogin(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 未登录应返回错误
	err := authCtx.CheckLogin()
	assert.Error(t, err)

	// 登录后检查
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	err = authCtx.CheckLogin()
	assert.NoError(t, err)
}

func TestAuthContext_LoginID(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	// 获取登录 ID
	loginID, err := authCtx.LoginID()
	require.NoError(t, err)
	assert.Equal(t, "user123", loginID)
}

func TestAuthContext_MustLoginID(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 未登录应 panic
	assert.Panics(t, func() {
		authCtx.MustLoginID()
	})

	// 登录后正常返回
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	loginID := authCtx.MustLoginID()
	assert.Equal(t, "user123", loginID)
}

func TestAuthContext_UnconfiguredSafe(t *testing.T) {
	authCtx := NewAuthContext(nil, nil)

	assert.False(t, authCtx.IsLogin())
	_, err := authCtx.Login("user123")
	require.ErrorIs(t, err, ErrAuthNotConfigured)
	_, err = authCtx.LoginID()
	require.ErrorIs(t, err, ErrAuthNotConfigured)
	_, err = authCtx.RefreshToken("refresh-token")
	require.ErrorIs(t, err, ErrAuthNotConfigured)
	assert.Nil(t, authCtx.Session())
}

func TestAuthContext_Kickout(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录两个设备
	token1, err := authCtx.Login("user123", "PC")
	require.NoError(t, err)

	token2, err := authCtx.Login("user123", "Mobile")
	require.NoError(t, err)

	// 踢出 PC 设备
	err = authCtx.Kickout("user123", "PC")
	require.NoError(t, err)

	// PC Token 已失效
	assert.False(t, mgr.IsLogin(token1))

	// Mobile Token 仍有效
	assert.True(t, mgr.IsLogin(token2))
}

func TestAuthContext_HasPermission(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	// 设置权限
	err = authCtx.SetPermissions("user123", []string{"user:read", "user:write"})
	require.NoError(t, err)

	// 检查权限
	assert.True(t, authCtx.HasPermission("user:read"))
	assert.True(t, authCtx.HasPermission("user:write"))
	assert.False(t, authCtx.HasPermission("admin:delete"))
}

func TestAuthContext_HasPermissions(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录并设置权限
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	err = authCtx.SetPermissions("user123", []string{"user:read", "user:write"})
	require.NoError(t, err)

	// AND 逻辑：需要同时拥有所有权限
	assert.True(t, authCtx.HasPermissions("user:read", "user:write"))
	assert.False(t, authCtx.HasPermissions("user:read", "admin:delete"))
}

func TestAuthContext_HasAnyPermission(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录并设置权限
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	err = authCtx.SetPermissions("user123", []string{"user:read"})
	require.NoError(t, err)

	// OR 逻辑：拥有任意一个权限即可
	assert.True(t, authCtx.HasAnyPermission("user:read", "user:write"))
	assert.False(t, authCtx.HasAnyPermission("user:write", "admin:delete"))
}

func TestAuthContext_CheckPermission(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录并设置权限
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	err = authCtx.SetPermissions("user123", []string{"user:read"})
	require.NoError(t, err)

	// 有权限
	err = authCtx.CheckPermission("user:read")
	assert.NoError(t, err)

	// 无权限
	err = authCtx.CheckPermission("admin:delete")
	assert.Error(t, err)
}

func TestAuthContext_HasRole(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	// 设置角色
	err = authCtx.SetRoles("user123", []string{"admin", "user"})
	require.NoError(t, err)

	// 检查角色
	assert.True(t, authCtx.HasRole("admin"))
	assert.True(t, authCtx.HasRole("user"))
	assert.False(t, authCtx.HasRole("super"))
}

func TestAuthContext_HasRoles(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录并设置角色
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	err = authCtx.SetRoles("user123", []string{"admin", "user"})
	require.NoError(t, err)

	// AND 逻辑
	assert.True(t, authCtx.HasRoles("admin", "user"))
	assert.False(t, authCtx.HasRoles("admin", "super"))
}

func TestAuthContext_HasAnyRole(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录并设置角色
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	err = authCtx.SetRoles("user123", []string{"user"})
	require.NoError(t, err)

	// OR 逻辑
	assert.True(t, authCtx.HasAnyRole("admin", "user"))
	assert.False(t, authCtx.HasAnyRole("admin", "super"))
}

func TestAuthContext_CheckRole(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录并设置角色
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	err = authCtx.SetRoles("user123", []string{"user"})
	require.NoError(t, err)

	// 有角色
	err = authCtx.CheckRole("user")
	assert.NoError(t, err)

	// 无角色
	err = authCtx.CheckRole("admin")
	assert.Error(t, err)
}

func TestAuthContext_Disable(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 封禁账号
	err := authCtx.Disable("user123", 1*time.Hour)
	require.NoError(t, err)

	// 检查封禁状态
	assert.True(t, authCtx.IsDisabled("user123"))

	// 解封
	err = authCtx.Untie("user123")
	require.NoError(t, err)

	// 检查解封状态
	assert.False(t, authCtx.IsDisabled("user123"))
}

func TestAuthContext_CheckDisabled(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	// 未封禁时检查
	err = authCtx.CheckDisabled()
	assert.NoError(t, err)

	// 封禁账号
	err = authCtx.Disable("user123", 1*time.Hour)
	require.NoError(t, err)

	// 封禁时检查
	err = authCtx.CheckDisabled()
	assert.Error(t, err)
}

func TestAuthContext_Session(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 未登录时 Session 为 nil
	session := authCtx.Session()
	assert.Nil(t, session)

	// 登录后可获取 Session
	token, err := authCtx.Login("user123")
	require.NoError(t, err)
	authCtx.tokenValue = token

	session = authCtx.Session()
	require.NotNil(t, session)

	// Session 操作
	require.NoError(t, session.Set("key", "value"))
	val, ok := session.Get("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestAuthContext_GetSessionByID(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录
	_, err := authCtx.Login("user123")
	require.NoError(t, err)

	// 根据 loginID 获取 Session
	session, err := authCtx.GetSessionByID("user123")
	require.NoError(t, err)
	assert.NotNil(t, session)
}

func TestAuthContext_TokenInfo(t *testing.T) {
	mgr := setupTestManager()
	_, authCtx := setupTestContext(mgr)

	// 登录
	token, err := authCtx.Login("user123", "PC")
	require.NoError(t, err)
	authCtx.tokenValue = token

	// 获取 Token 信息
	info, err := authCtx.TokenInfo()
	require.NoError(t, err)
	assert.Equal(t, "user123", info.LoginID)
	assert.Equal(t, "PC", info.Device)
}

func TestAuthContext_ExtractToken(t *testing.T) {
	mgr := setupTestManager()

	tests := []struct {
		name     string
		setup    func(*gin.Context)
		expected string
	}{
		{
			name: "从 Header 读取",
			setup: func(c *gin.Context) {
				c.Request.Header.Set("satoken", "token-from-header")
			},
			expected: "token-from-header",
		},
		{
			name: "从 Authorization Bearer 读取",
			setup: func(c *gin.Context) {
				c.Request.Header.Set("Authorization", "Bearer token-from-bearer")
			},
			expected: "token-from-bearer",
		},
		{
			name: "从 Cookie 读取",
			setup: func(c *gin.Context) {
				c.Request.AddCookie(&http.Cookie{
					Name:  "satoken",
					Value: "token-from-cookie",
				})
			},
			expected: "token-from-cookie",
		},
		{
			name: "从 Query 读取",
			setup: func(c *gin.Context) {
				c.Request.URL.RawQuery = "satoken=token-from-query"
			},
			expected: "token-from-query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)

			tt.setup(c)

			ginCtx := NewGinRequestContext(c)
			authCtx := NewAuthContext(ginCtx, mgr)

			token := authCtx.Token()
			assert.Equal(t, tt.expected, token)
		})
	}
}

func TestGinRequestContext_Implementation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	ctx := NewGinRequestContext(c)

	// 验证实现了 adapter.RequestContext 接口
	_, ok := ctx.(*GinRequestContext)
	assert.True(t, ok)

	// 测试基本方法
	assert.Equal(t, "GET", ctx.GetMethod())
	assert.Equal(t, "/test", ctx.GetPath())

	// 测试上下文存储
	ctx.Set("key", "value")
	val, exists := ctx.Get("key")
	assert.True(t, exists)
	assert.Equal(t, "value", val)

	// 测试 Abort
	assert.False(t, ctx.IsAborted())
	ctx.Abort()
	assert.True(t, ctx.IsAborted())
}
