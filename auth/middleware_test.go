package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestEngine() (*gin.Engine, *Manager) {
	gin.SetMode(gin.TestMode)
	mgr := setupTestManager()

	r := gin.New()
	return r, mgr
}

func TestAuthRequired(t *testing.T) {
	r, mgr := setupTestEngine()

	// 添加 AuthRequired 中间件
	r.GET("/protected", AuthRequired(mgr), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	t.Run("未登录应返回 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/protected", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("已登录应通过", func(t *testing.T) {
		// 先登录获取 token
		token, err := mgr.Login("user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRoleRequired(t *testing.T) {
	r, mgr := setupTestEngine()

	// 添加 RoleRequired 中间件
	r.GET("/admin", RoleRequired(mgr, "admin"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "admin access"})
	})

	// 登录并设置角色
	token, err := mgr.Login("user123")
	require.NoError(t, err)

	t.Run("未登录应返回 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/admin", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("无角色应返回 403", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("有角色应通过", func(t *testing.T) {
		// 设置角色
		err := mgr.SetRoles("user123", []string{"admin"})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRoleRequiredAll(t *testing.T) {
	r, mgr := setupTestEngine()

	// 添加 RoleRequiredAll 中间件（需要同时拥有两个角色）
	r.GET("/super-admin", RoleRequiredAll(mgr, "admin", "super"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "super admin access"})
	})

	// 登录
	token, err := mgr.Login("user123")
	require.NoError(t, err)

	t.Run("只有一个角色应返回 403", func(t *testing.T) {
		err := mgr.SetRoles("user123", []string{"admin"})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/super-admin", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("拥有所有角色应通过", func(t *testing.T) {
		err := mgr.SetRoles("user123", []string{"admin", "super"})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/super-admin", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestPermRequired(t *testing.T) {
	r, mgr := setupTestEngine()

	// 添加 PermRequired 中间件（OR 逻辑）
	r.GET("/resource", PermRequired(mgr, "user:read", "user:write"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "access granted"})
	})

	// 登录
	token, err := mgr.Login("user123")
	require.NoError(t, err)

	t.Run("无权限应返回 403", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("有任一权限应通过", func(t *testing.T) {
		// 只设置一个权限
		err := mgr.SetPermissions("user123", []string{"user:read"})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestPermRequiredAll(t *testing.T) {
	r, mgr := setupTestEngine()

	// 添加 PermRequiredAll 中间件（AND 逻辑）
	r.GET("/resource", PermRequiredAll(mgr, "user:read", "user:write"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "full access granted"})
	})

	// 登录
	token, err := mgr.Login("user123")
	require.NoError(t, err)

	t.Run("只有一个权限应返回 403", func(t *testing.T) {
		err := mgr.SetPermissions("user123", []string{"user:read"})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("拥有所有权限应通过", func(t *testing.T) {
		err := mgr.SetPermissions("user123", []string{"user:read", "user:write"})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestDisableCheck(t *testing.T) {
	r, mgr := setupTestEngine()

	// 添加 DisableCheck 中间件
	r.GET("/api", DisableCheck(mgr), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "api success"})
	})

	// 登录
	token, err := mgr.Login("user123")
	require.NoError(t, err)

	t.Run("未封禁应通过", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("已封禁后旧 token 应返回 401", func(t *testing.T) {
		// 封禁账号
		err := mgr.Disable("user123", 1*60) // 1 分钟
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestMiddlewareChain(t *testing.T) {
	r, mgr := setupTestEngine()

	// 链式使用多个中间件
	r.GET(
		"/secure-resource",
		AuthRequired(mgr),
		RoleRequired(mgr, "admin"),
		PermRequired(mgr, "resource:access"),
		DisableCheck(mgr),
		func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "secure resource accessed"})
		},
	)

	// 登录并设置权限和角色
	token, err := mgr.Login("user123")
	require.NoError(t, err)

	err = mgr.SetRoles("user123", []string{"admin"})
	require.NoError(t, err)

	err = mgr.SetPermissions("user123", []string{"resource:access"})
	require.NoError(t, err)

	t.Run("所有条件满足应通过", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/secure-resource", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("缺少角色应返回 403", func(t *testing.T) {
		// 移除角色
		err := mgr.SetRoles("user123", []string{})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/secure-resource", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestMiddlewareBuilder(t *testing.T) {
	mgr := setupTestManager()
	builder := NewMiddlewareBuilder(mgr)

	r := gin.New()

	// 使用 Builder 创建中间件
	r.GET("/auth", builder.AuthRequired(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "authenticated"})
	})

	r.GET("/admin", builder.RoleRequired("admin"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "admin only"})
	})

	// 登录
	token, err := mgr.Login("user123")
	require.NoError(t, err)

	t.Run("AuthRequired 中间件", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/auth", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RoleRequired 中间件", func(t *testing.T) {
		// 设置角色
		err := mgr.SetRoles("user123", []string{"admin"})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Header.Set("satoken", token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
