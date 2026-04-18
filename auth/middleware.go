package auth

import (
	"net/http"

	"github.com/darkit/gin/auth/core/manager"
	"github.com/gin-gonic/gin"
)

// MiddlewareBuilder 中间件构建器
// 用于创建认证授权中间件
type MiddlewareBuilder struct {
	mgr *manager.Manager
}

// NewMiddlewareBuilder 创建中间件构建器
func NewMiddlewareBuilder(mgr *manager.Manager) *MiddlewareBuilder {
	return &MiddlewareBuilder{mgr: mgr}
}

// AuthRequired 登录必需中间件
// 未登录返回 401 Unauthorized
//
// 使用示例:
//
//	e.Use(AuthRequired(authManager))
//	// 或通过 Engine 提供的便捷方法
//	e.Use(e.AuthRequired())
func AuthRequired(mgr *manager.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinRequestContext(c)
		authCtx := NewAuthContext(ctx, mgr)

		// 检查登录
		if err := authCtx.CheckLogin(); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "请先登录",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RoleRequired 角色必需中间件（OR 逻辑）
// 至少拥有其中一个角色才允许访问
// 无角色返回 403 Forbidden
//
// 使用示例:
//
//	e.Use(RoleRequired(authManager, "admin", "moderator"))
func RoleRequired(mgr *manager.Manager, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinRequestContext(c)
		authCtx := NewAuthContext(ctx, mgr)

		// 检查登录
		if err := authCtx.CheckLogin(); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "请先登录",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		// 检查角色（OR 逻辑）
		if err := authCtx.CheckAnyRole(roles...); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "权限不足",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RoleRequiredAll 角色必需中间件（AND 逻辑）
// 必须同时拥有所有角色才允许访问
// 无角色返回 403 Forbidden
//
// 使用示例:
//
//	e.Use(RoleRequiredAll(authManager, "admin", "super"))
func RoleRequiredAll(mgr *manager.Manager, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinRequestContext(c)
		authCtx := NewAuthContext(ctx, mgr)

		// 检查登录
		if err := authCtx.CheckLogin(); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "请先登录",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		// 检查角色（AND 逻辑）
		if err := authCtx.CheckRoles(roles...); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "权限不足",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// PermRequired 权限必需中间件（OR 逻辑）
// 至少拥有其中一个权限才允许访问
// 无权限返回 403 Forbidden
//
// 使用示例:
//
//	e.Use(PermRequired(authManager, "user:read", "user:write"))
func PermRequired(mgr *manager.Manager, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinRequestContext(c)
		authCtx := NewAuthContext(ctx, mgr)

		// 检查登录
		if err := authCtx.CheckLogin(); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "请先登录",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		// 检查权限（OR 逻辑）
		if err := authCtx.CheckAnyPermission(permissions...); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "权限不足",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// PermRequiredAll 权限必需中间件（AND 逻辑）
// 必须同时拥有所有权限才允许访问
// 无权限返回 403 Forbidden
//
// 使用示例:
//
//	e.Use(PermRequiredAll(authManager, "user:read", "user:write"))
func PermRequiredAll(mgr *manager.Manager, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinRequestContext(c)
		authCtx := NewAuthContext(ctx, mgr)

		// 检查登录
		if err := authCtx.CheckLogin(); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "请先登录",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		// 检查权限（AND 逻辑）
		if err := authCtx.CheckPermissions(permissions...); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "权限不足",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// DisableCheck 封禁检查中间件
// 检查当前登录用户是否被封禁
// 当请求仍携带有效登录态时，已封禁返回 403 Forbidden；若封禁已使 token 失效，则会先返回 401 Unauthorized
//
// 使用示例:
//
//	e.Use(DisableCheck(authManager))
func DisableCheck(mgr *manager.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinRequestContext(c)
		authCtx := NewAuthContext(ctx, mgr)

		// 检查登录
		if err := authCtx.CheckLogin(); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "请先登录",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		// 检查封禁
		if err := authCtx.CheckDisabled(); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "账号已被封禁",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ============ 中间件构建器方法 ============

// AuthRequired 登录必需中间件
func (b *MiddlewareBuilder) AuthRequired() gin.HandlerFunc {
	return AuthRequired(b.mgr)
}

// RoleRequired 角色必需中间件（OR 逻辑）
func (b *MiddlewareBuilder) RoleRequired(roles ...string) gin.HandlerFunc {
	return RoleRequired(b.mgr, roles...)
}

// RoleRequiredAll 角色必需中间件（AND 逻辑）
func (b *MiddlewareBuilder) RoleRequiredAll(roles ...string) gin.HandlerFunc {
	return RoleRequiredAll(b.mgr, roles...)
}

// PermRequired 权限必需中间件（OR 逻辑）
func (b *MiddlewareBuilder) PermRequired(permissions ...string) gin.HandlerFunc {
	return PermRequired(b.mgr, permissions...)
}

// PermRequiredAll 权限必需中间件（AND 逻辑）
func (b *MiddlewareBuilder) PermRequiredAll(permissions ...string) gin.HandlerFunc {
	return PermRequiredAll(b.mgr, permissions...)
}

// DisableCheck 封禁检查中间件
func (b *MiddlewareBuilder) DisableCheck() gin.HandlerFunc {
	return DisableCheck(b.mgr)
}
