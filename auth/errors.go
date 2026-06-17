package auth

import (
	"errors"
	"fmt"
)

// 预定义错误
var (
	// ErrAuthNotConfigured 认证模块未配置
	ErrAuthNotConfigured = errors.New("认证模块未配置，请使用 WithAuth() 配置认证")

	// ErrInvalidTokenStyle 无效的 Token 风格
	ErrInvalidTokenStyle = errors.New("无效的 Token 风格")

	// ErrJWTSecretRequired JWT 风格需要提供 Secret
	ErrJWTSecretRequired = errors.New("TokenStyle 为 JWT 时必须提供 Secret")

	// ErrInvalidExpiry 无效的过期时间
	ErrInvalidExpiry = errors.New("Token 过期时间不能为负")

	// ErrPermissionDenied 权限不足
	ErrPermissionDenied = errors.New("权限不足")

	// ErrRoleDenied 角色不足
	ErrRoleDenied = errors.New("角色不足")

	// ErrAccountDisabled 账号已被封禁
	ErrAccountDisabled = errors.New("账号已被封禁")

	// ErrNotLogin 未登录
	ErrNotLogin = errors.New("未登录")
)

// AuthError 认证错误
type AuthError struct {
	Code    int    // 错误码
	Message string // 错误消息
	Err     error  // 原始错误
}

// Error 实现 error 接口
func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap 支持错误链
func (e *AuthError) Unwrap() error {
	return e.Err
}

// 错误码定义
const (
	CodeNotLogin         = 401  // 未登录
	CodePermissionDenied = 403  // 权限不足
	CodeRoleDenied       = 403  // 角色不足
	CodeAccountDisabled  = 403  // 账号封禁
	CodeTokenInvalid     = 1001 // Token 无效
	CodeTokenExpired     = 1002 // Token 过期
)

// NewPermissionDeniedError 创建权限不足错误
func NewPermissionDeniedError(permission string) *AuthError {
	return &AuthError{
		Code:    CodePermissionDenied,
		Message: fmt.Sprintf("权限不足，需要权限: %s", permission),
		Err:     ErrPermissionDenied,
	}
}

// NewRoleDeniedError 创建角色不足错误
func NewRoleDeniedError(role string) *AuthError {
	return &AuthError{
		Code:    CodeRoleDenied,
		Message: fmt.Sprintf("角色不足，需要角色: %s", role),
		Err:     ErrRoleDenied,
	}
}

// NewAccountDisabledError 创建账号封禁错误
func NewAccountDisabledError(loginID string) *AuthError {
	return &AuthError{
		Code:    CodeAccountDisabled,
		Message: fmt.Sprintf("账号已被封禁: %s", loginID),
		Err:     ErrAccountDisabled,
	}
}

// NewNotLoginError 创建未登录错误
func NewNotLoginError() *AuthError {
	return &AuthError{
		Code:    CodeNotLogin,
		Message: "未登录，请先登录",
		Err:     ErrNotLogin,
	}
}

// NewTokenInvalidError 创建 Token 无效错误
func NewTokenInvalidError(reason string) *AuthError {
	return &AuthError{
		Code:    CodeTokenInvalid,
		Message: fmt.Sprintf("Token 无效: %s", reason),
	}
}

// NewTokenExpiredError 创建 Token 过期错误
func NewTokenExpiredError() *AuthError {
	return &AuthError{
		Code:    CodeTokenExpired,
		Message: "Token 已过期",
	}
}
