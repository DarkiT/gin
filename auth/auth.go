package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/core/manager"
	"github.com/darkit/gin/auth/core/security"
	"github.com/darkit/gin/auth/core/session"
)

// AuthContext 认证上下文
// 提供简化的认证授权 API，封装底层 Manager 的复杂性
type AuthContext struct {
	ctx        adapter.RequestContext // 请求上下文适配器
	mgr        *manager.Manager       // 认证管理器
	tokenValue string                 // 缓存的 token 值
	initErr    error
}

// NewAuthContext 创建认证上下文
func NewAuthContext(ctx adapter.RequestContext, mgr *manager.Manager) *AuthContext {
	authCtx := &AuthContext{
		ctx: ctx,
		mgr: mgr,
	}
	if mgr == nil {
		authCtx.initErr = ErrAuthNotConfigured
	}
	return authCtx
}

// ============ 登录认证 ============

// Login 用户登录，返回 Token
//
// 参数:
//   - loginID: 登录 ID（用户 ID、用户名等），会被转换为字符串
//   - device: 可选的设备标识，用于区分不同设备登录
//
// 返回:
//   - token: 生成的 Token 字符串
//   - error: 错误信息
//
// 示例:
//
//	token, err := c.Auth().Login("user123")
//	token, err := c.Auth().Login("user123", "mobile")
func (a *AuthContext) Login(loginID any, device ...string) (string, error) {
	if err := a.authError(); err != nil {
		return "", err
	}
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return a.mgr.Login(toString(loginID), dev)
}

// LoginWithRefreshToken 使用 Access Token + Refresh Token 方案登录。
func (a *AuthContext) LoginWithRefreshToken(loginID any, device ...string) (*security.RefreshTokenInfo, error) {
	if err := a.authError(); err != nil {
		return nil, err
	}
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return a.mgr.LoginWithRefreshToken(toString(loginID), dev)
}

// Logout 当前用户登出
// 登出当前请求携带的 Token
func (a *AuthContext) Logout() error {
	if err := a.authError(); err != nil {
		return err
	}
	token := a.Token()
	if token == "" {
		return NewNotLoginError()
	}
	return a.mgr.LogoutByToken(token)
}

// LogoutByID 指定用户登出
// 登出指定用户的所有登录或指定设备的登录
func (a *AuthContext) LogoutByID(loginID any, device ...string) error {
	if err := a.authError(); err != nil {
		return err
	}
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return a.mgr.Logout(toString(loginID), dev)
}

// Kickout 踢人下线
// 强制下线指定用户的所有登录或指定设备的登录
func (a *AuthContext) Kickout(loginID any, device ...string) error {
	if err := a.authError(); err != nil {
		return err
	}
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return a.mgr.Kickout(toString(loginID), dev)
}

// ============ Token 验证 ============

// Token 获取当前请求的 Token
// 从 Header、Cookie、Query 等位置读取 Token（根据配置）
func (a *AuthContext) Token() string {
	if a == nil || a.mgr == nil || a.ctx == nil {
		return ""
	}
	if a.tokenValue != "" {
		return a.tokenValue
	}
	a.tokenValue = a.extractToken()
	return a.tokenValue
}

// IsLogin 检查是否已登录
// 返回 true 表示已登录，false 表示未登录
func (a *AuthContext) IsLogin() bool {
	if err := a.authError(); err != nil {
		return false
	}
	return a.mgr.IsLogin(a.Token())
}

// CheckLogin 检查登录（未登录返回错误）
// 如果未登录，返回 ErrNotLogin 错误
func (a *AuthContext) CheckLogin() error {
	if !a.IsLogin() {
		return NewNotLoginError()
	}
	return nil
}

// LoginID 获取当前登录用户 ID
// 如果未登录，返回错误
func (a *AuthContext) LoginID() (string, error) {
	if err := a.authError(); err != nil {
		return "", err
	}
	token := a.Token()
	if token == "" {
		return "", NewNotLoginError()
	}
	return a.mgr.GetLoginID(token)
}

// MustLoginID 获取登录 ID（panic if not logged in）
// 如果未登录会 panic，仅在确定已登录的场景使用
func (a *AuthContext) MustLoginID() string {
	id, err := a.LoginID()
	if err != nil {
		panic(err)
	}
	return id
}

// TokenInfo 获取 Token 信息
// 返回 Token 的详细信息（登录 ID、设备、创建时间等）
func (a *AuthContext) TokenInfo() (*TokenInfo, error) {
	if err := a.authError(); err != nil {
		return nil, err
	}
	token := a.Token()
	if token == "" {
		return nil, NewNotLoginError()
	}
	return a.mgr.GetTokenInfo(token)
}

// ============ 权限检查 ============

// HasPermission 检查是否有权限
// 返回 true 表示有权限，false 表示无权限
func (a *AuthContext) HasPermission(permission string) bool {
	id, err := a.LoginID()
	if err != nil {
		return false
	}
	return a.mgr.HasPermission(id, permission)
}

// HasPermissions 检查是否有多个权限（AND 逻辑）
// 需要同时拥有所有权限才返回 true
func (a *AuthContext) HasPermissions(permissions ...string) bool {
	id, err := a.LoginID()
	if err != nil {
		return false
	}
	return a.mgr.HasPermissionsAnd(id, permissions)
}

// HasAnyPermission 检查是否有任意权限（OR 逻辑）
// 拥有任意一个权限即返回 true
func (a *AuthContext) HasAnyPermission(permissions ...string) bool {
	id, err := a.LoginID()
	if err != nil {
		return false
	}
	return a.mgr.HasPermissionsOr(id, permissions)
}

// CheckPermission 权限检查（无权限返回错误）
// 如果没有权限，返回 ErrPermissionDenied 错误
func (a *AuthContext) CheckPermission(permission string) error {
	if !a.HasPermission(permission) {
		return NewPermissionDeniedError(permission)
	}
	return nil
}

// CheckPermissions 检查多个权限（AND 逻辑，无权限返回错误）
// 需要同时拥有所有权限，否则返回错误
func (a *AuthContext) CheckPermissions(permissions ...string) error {
	if !a.HasPermissions(permissions...) {
		return NewPermissionDeniedError(strings.Join(permissions, ","))
	}
	return nil
}

// CheckAnyPermission 检查任意权限（OR 逻辑，无权限返回错误）
// 需要至少拥有一个权限，否则返回错误
func (a *AuthContext) CheckAnyPermission(permissions ...string) error {
	if !a.HasAnyPermission(permissions...) {
		return NewPermissionDeniedError(strings.Join(permissions, ","))
	}
	return nil
}

// ============ 角色检查 ============

// HasRole 检查是否有角色
// 返回 true 表示有角色，false 表示无角色
func (a *AuthContext) HasRole(role string) bool {
	id, err := a.LoginID()
	if err != nil {
		return false
	}
	return a.mgr.HasRole(id, role)
}

// HasRoles 检查是否有多个角色（AND 逻辑）
// 需要同时拥有所有角色才返回 true
func (a *AuthContext) HasRoles(roles ...string) bool {
	id, err := a.LoginID()
	if err != nil {
		return false
	}
	return a.mgr.HasRolesAnd(id, roles)
}

// HasAnyRole 检查是否有任意角色（OR 逻辑）
// 拥有任意一个角色即返回 true
func (a *AuthContext) HasAnyRole(roles ...string) bool {
	id, err := a.LoginID()
	if err != nil {
		return false
	}
	return a.mgr.HasRolesOr(id, roles)
}

// CheckRole 角色检查（无角色返回错误）
// 如果没有角色，返回 ErrRoleDenied 错误
func (a *AuthContext) CheckRole(role string) error {
	if !a.HasRole(role) {
		return NewRoleDeniedError(role)
	}
	return nil
}

// CheckRoles 检查多个角色（AND 逻辑，无角色返回错误）
// 需要同时拥有所有角色，否则返回错误
func (a *AuthContext) CheckRoles(roles ...string) error {
	if !a.HasRoles(roles...) {
		return NewRoleDeniedError(strings.Join(roles, ","))
	}
	return nil
}

// CheckAnyRole 检查任意角色（OR 逻辑，无角色返回错误）
// 需要至少拥有一个角色，否则返回错误
func (a *AuthContext) CheckAnyRole(roles ...string) error {
	if !a.HasAnyRole(roles...) {
		return NewRoleDeniedError(strings.Join(roles, ","))
	}
	return nil
}

// ============ 账号封禁 ============

// Disable 封禁账号
// 在指定时间内禁止用户登录
//
// 参数:
//   - loginID: 登录 ID
//   - duration: 封禁时长，0 或负数表示永久封禁
func (a *AuthContext) Disable(loginID any, duration time.Duration) error {
	if err := a.authError(); err != nil {
		return err
	}
	return a.mgr.Disable(toString(loginID), duration)
}

// Untie 解封账号
// 解除用户的封禁状态
func (a *AuthContext) Untie(loginID any) error {
	if err := a.authError(); err != nil {
		return err
	}
	return a.mgr.Untie(toString(loginID))
}

// IsDisabled 检查账号是否被封禁
// 返回 true 表示已封禁，false 表示未封禁
func (a *AuthContext) IsDisabled(loginID any) bool {
	if err := a.authError(); err != nil {
		return false
	}
	return a.mgr.IsDisable(toString(loginID))
}

// CheckDisabled 检查当前用户是否被封禁
// 如果已封禁，返回错误
func (a *AuthContext) CheckDisabled() error {
	id, err := a.LoginID()
	if err != nil {
		return err
	}
	if a.IsDisabled(id) {
		return NewAccountDisabledError(id)
	}
	return nil
}

// ============ Session 管理 ============

// Session 获取当前用户 Session
// 如果未登录，返回 nil
func (a *AuthContext) Session() *session.Session {
	if err := a.authError(); err != nil {
		return nil
	}
	id, err := a.LoginID()
	if err != nil {
		return nil
	}
	sess, _ := a.mgr.GetSession(id)
	return sess
}

// GetSessionByID 获取指定用户的 Session
func (a *AuthContext) GetSessionByID(loginID any) (*session.Session, error) {
	if err := a.authError(); err != nil {
		return nil, err
	}
	return a.mgr.GetSession(toString(loginID))
}

// SetPermissions 设置用户权限
// 会覆盖用户的所有权限
func (a *AuthContext) SetPermissions(loginID any, permissions []string) error {
	if err := a.authError(); err != nil {
		return err
	}
	return a.mgr.SetPermissions(toString(loginID), permissions)
}

// SetRoles 设置用户角色
// 会覆盖用户的所有角色
func (a *AuthContext) SetRoles(loginID any, roles []string) error {
	if err := a.authError(); err != nil {
		return err
	}
	return a.mgr.SetRoles(toString(loginID), roles)
}

// GetPermissions 获取用户权限列表
func (a *AuthContext) GetPermissions(loginID any) ([]string, error) {
	if err := a.authError(); err != nil {
		return nil, err
	}
	return a.mgr.GetPermissions(toString(loginID))
}

// GetRoles 获取用户角色列表
func (a *AuthContext) GetRoles(loginID any) ([]string, error) {
	if err := a.authError(); err != nil {
		return nil, err
	}
	return a.mgr.GetRoles(toString(loginID))
}

// ============ Token 刷新 ============

// RefreshToken 刷新 Token
// 使用 Refresh Token 换取新的 Access Token
// 注意：需要在配置中启用 Refresh Token 功能
func (a *AuthContext) RefreshToken(refreshToken string) (string, error) {
	if err := a.authError(); err != nil {
		return "", err
	}
	info, err := a.RefreshTokenInfo(refreshToken)
	if err != nil {
		return "", err
	}
	if info == nil || info.AccessToken == "" {
		return "", fmt.Errorf("refresh token 刷新失败：未返回新的 access token")
	}
	return info.AccessToken, nil
}

// RefreshTokenInfo 使用 Refresh Token 刷新并返回完整 Token 信息。
func (a *AuthContext) RefreshTokenInfo(refreshToken string) (*security.RefreshTokenInfo, error) {
	if err := a.authError(); err != nil {
		return nil, err
	}
	return a.mgr.RefreshAccessToken(refreshToken)
}

// RevokeRefreshToken 撤销 Refresh Token。
func (a *AuthContext) RevokeRefreshToken(refreshToken string) error {
	if err := a.authError(); err != nil {
		return err
	}
	return a.mgr.RevokeRefreshToken(refreshToken)
}

// ============ 内部方法 ============

// extractToken 从请求中提取 Token
func (a *AuthContext) extractToken() string {
	if a == nil || a.ctx == nil || a.mgr == nil {
		return ""
	}
	cfg := a.mgr.GetConfig()

	// 1. 从 Header 读取
	if cfg.IsReadHeader {
		if token := a.ctx.GetHeader(cfg.TokenName); token != "" {
			return token
		}
		// 支持 Bearer Token
		if auth := a.ctx.GetHeader("Authorization"); auth != "" {
			if strings.HasPrefix(auth, "Bearer ") {
				return strings.TrimPrefix(auth, "Bearer ")
			}
		}
	}

	// 2. 从 Cookie 读取
	if cfg.IsReadCookie {
		if token := a.ctx.GetCookie(cfg.TokenName); token != "" {
			return token
		}
	}

	// 3. 从 Query 读取
	if token := a.ctx.GetQuery(cfg.TokenName); token != "" {
		return token
	}

	// 4. 从 Body 读取（如果配置了）
	if cfg.IsReadBody {
		if token := a.ctx.GetPostForm(cfg.TokenName); token != "" {
			return token
		}
	}

	return ""
}

func (a *AuthContext) authError() error {
	if a == nil {
		return ErrAuthNotConfigured
	}
	if a.initErr != nil {
		return a.initErr
	}
	if a.mgr == nil {
		return ErrAuthNotConfigured
	}
	return nil
}

// toString 将任意类型转换为字符串
func toString(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case uint:
		return fmt.Sprintf("%d", val)
	case uint64:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
