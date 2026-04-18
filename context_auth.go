// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"github.com/darkit/gin/auth"
)

// Auth 获取认证授权上下文，封装底层 Manager 的复杂性。
// 使用示例:
//
//	// 登录
//	token, err := c.Auth().Login("user123")
//
//	// 检查登录
//	if c.Auth().IsLogin() {
//	    userID, _ := c.Auth().LoginID()
//	}
//
//	// 权限检查
//	if c.Auth().HasPermission("user:write") {
//	    // 允许操作
//	}
//
// 注意: 需要先通过 WithAuth() 配置认证模块。
func (c *Context) Auth() *auth.AuthContext {
	// 创建 Gin 请求上下文适配器
	ginCtx := auth.NewGinRequestContext(c.Context)

	// 返回认证上下文
	if c.engine == nil {
		return auth.NewAuthContext(ginCtx, nil)
	}
	return auth.NewAuthContext(ginCtx, c.engine.authManager)
}
