package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/darkit/gin/auth/core/manager"
	"github.com/darkit/gin/auth/core/oauth2"
	"github.com/darkit/gin/auth/core/security"
	"github.com/darkit/gin/auth/core/session"
)

// ============ 全局 Manager 管理 ============
//
// 全局静态方法封装，适用于不使用 Engine 集成方式的场景
// 使用前必须调用 SetGlobalManager 初始化

var (
	globalManager *manager.Manager
	globalLogic   *StpLogic
	globalMu      sync.RWMutex
)

// SetGlobalManager 设置全局 Manager
// 使用全局静态方法前必须先调用此函数初始化
//
// 使用示例:
//
//	storage := auth.NewMemoryStorage()
//	cfg := auth.DefaultAuthConfig()
//	mgr := auth.NewManager(storage, &cfg)
//	auth.SetGlobalManager(mgr)
func SetGlobalManager(mgr *Manager) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalManager = mgr
	if globalLogic == nil {
		globalLogic = NewStpLogic(mgr)
		return
	}
	globalLogic.SetManager(mgr)
}

// GetGlobalManager 获取全局 Manager
// 如果未初始化会 panic
func GetGlobalManager() *Manager {
	globalMu.RLock()
	mgr := globalManager
	logic := globalLogic
	globalMu.RUnlock()
	if mgr != nil {
		return mgr
	}
	if logic != nil {
		return logic.GetManager()
	}
	panic("auth: 全局 Manager 未初始化，请先调用 SetGlobalManager()")
}

// CloseGlobalManager 关闭全局 Manager 并释放资源
func CloseGlobalManager() {
	globalMu.Lock()
	mgr := globalManager
	logic := globalLogic
	globalManager = nil
	globalLogic = nil
	globalMu.Unlock()

	if logic != nil {
		logic.CloseManager()
		logic.SetManager(nil)
		return
	}
	if mgr != nil {
		mgr.CloseManager()
	}
}

// SetStpLogic 设置全局 StpLogic 实例。
func SetStpLogic(logic *StpLogic) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogic = logic
	if logic == nil {
		globalManager = nil
		return
	}
	globalManager = logic.GetManager()
}

// GetStpLogic 获取全局 StpLogic 实例。
func GetStpLogic() *StpLogic {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogic
}

// ============ 登录认证 ============

// Login 用户登录（全局方法）
//
// 参数:
//   - loginID: 登录 ID（用户 ID、用户名等）
//   - device: 可选的设备标识
//
// 返回:
//   - token: 生成的 Token 字符串
//   - error: 错误信息
func Login(loginID any, device ...string) (string, error) {
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return GetGlobalManager().Login(toString(loginID), dev)
}

// LoginByToken 使用指定 Token 登录
func LoginByToken(loginID any, tokenValue string, device ...string) error {
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return GetGlobalManager().LoginByToken(toString(loginID), tokenValue, dev)
}

// Logout 用户登出
func Logout(loginID any, device ...string) error {
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return GetGlobalManager().Logout(toString(loginID), dev)
}

// LogoutByToken 根据 Token 登出
func LogoutByToken(tokenValue string) error {
	return GetGlobalManager().LogoutByToken(tokenValue)
}

// IsLogin 检查是否已登录
func IsLogin(tokenValue string) bool {
	return GetGlobalManager().IsLogin(tokenValue)
}

// CheckLogin 检查登录状态（未登录返回错误）
func CheckLogin(tokenValue string) error {
	return GetGlobalManager().CheckLogin(tokenValue)
}

// GetLoginID 从 Token 获取登录 ID
func GetLoginID(tokenValue string) (string, error) {
	return GetGlobalManager().GetLoginID(tokenValue)
}

// GetLoginIDNotCheck 获取登录 ID（不检查有效性）
func GetLoginIDNotCheck(tokenValue string) (string, error) {
	return GetGlobalManager().GetLoginIDNotCheck(tokenValue)
}

// GetTokenValue 获取登录 ID 对应的 Token 值
func GetTokenValue(loginID any, device ...string) (string, error) {
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return GetGlobalManager().GetTokenValue(toString(loginID), dev)
}

// GetTokenInfo 获取 Token 信息
func GetTokenInfo(tokenValue string) (*TokenInfo, error) {
	return GetGlobalManager().GetTokenInfo(tokenValue)
}

// ============ 踢人下线 ============

// Kickout 踢人下线
func Kickout(loginID any, device ...string) error {
	dev := ""
	if len(device) > 0 {
		dev = device[0]
	}
	return GetGlobalManager().Kickout(toString(loginID), dev)
}

// ============ 账号封禁 ============

// Disable 封禁账号
func Disable(loginID any, duration time.Duration) error {
	return GetGlobalManager().Disable(toString(loginID), duration)
}

// Untie 解封账号
func Untie(loginID any) error {
	return GetGlobalManager().Untie(toString(loginID))
}

// IsDisable 检查账号是否被封禁
func IsDisable(loginID any) bool {
	return GetGlobalManager().IsDisable(toString(loginID))
}

// GetDisableTime 获取剩余封禁时间（秒）
func GetDisableTime(loginID any) (int64, error) {
	return GetGlobalManager().GetDisableTime(toString(loginID))
}

// ============ Session 管理 ============

// GetSession 根据登录 ID 获取 Session
func GetSession(loginID any) (*session.Session, error) {
	return GetGlobalManager().GetSession(toString(loginID))
}

// GetSessionByToken 根据 Token 获取 Session
func GetSessionByToken(tokenValue string) (*session.Session, error) {
	return GetGlobalManager().GetSessionByToken(tokenValue)
}

// DeleteSession 删除 Session
func DeleteSession(loginID any) error {
	return GetGlobalManager().DeleteSession(toString(loginID))
}

// ============ 权限验证 ============

// SetPermissions 设置用户权限
func SetPermissions(loginID any, permissions []string) error {
	return GetGlobalManager().SetPermissions(toString(loginID), permissions)
}

// GetPermissions 获取权限列表
func GetPermissions(loginID any) ([]string, error) {
	return GetGlobalManager().GetPermissions(toString(loginID))
}

// HasPermission 检查是否拥有指定权限
func HasPermission(loginID any, permission string) bool {
	return GetGlobalManager().HasPermission(toString(loginID), permission)
}

// HasPermissionsAnd 检查是否拥有所有权限（AND 逻辑）
func HasPermissionsAnd(loginID any, permissions []string) bool {
	return GetGlobalManager().HasPermissionsAnd(toString(loginID), permissions)
}

// HasPermissionsOr 检查是否拥有任一权限（OR 逻辑）
func HasPermissionsOr(loginID any, permissions []string) bool {
	return GetGlobalManager().HasPermissionsOr(toString(loginID), permissions)
}

// ============ 角色管理 ============

// SetRoles 设置用户角色
func SetRoles(loginID any, roles []string) error {
	return GetGlobalManager().SetRoles(toString(loginID), roles)
}

// GetRoles 获取角色列表
func GetRoles(loginID any) ([]string, error) {
	return GetGlobalManager().GetRoles(toString(loginID))
}

// HasRole 检查是否拥有指定角色
func HasRole(loginID any, role string) bool {
	return GetGlobalManager().HasRole(toString(loginID), role)
}

// HasRolesAnd 检查是否拥有所有角色（AND 逻辑）
func HasRolesAnd(loginID any, roles []string) bool {
	return GetGlobalManager().HasRolesAnd(toString(loginID), roles)
}

// HasRolesOr 检查是否拥有任一角色（OR 逻辑）
func HasRolesOr(loginID any, roles []string) bool {
	return GetGlobalManager().HasRolesOr(toString(loginID), roles)
}

// ============ Token 标签 ============

// SetTokenTag 设置 Token 标签
func SetTokenTag(tokenValue, tag string) error {
	return GetGlobalManager().SetTokenTag(tokenValue, tag)
}

// GetTokenTag 获取 Token 标签
func GetTokenTag(tokenValue string) (string, error) {
	return GetGlobalManager().GetTokenTag(tokenValue)
}

// ============ 会话查询 ============

// GetTokenValueList 获取指定账号的所有 Token
func GetTokenValueList(loginID any) ([]string, error) {
	return GetGlobalManager().GetTokenValueListByLoginID(toString(loginID))
}

// GetSessionCount 获取指定账号的 Session 数量
func GetSessionCount(loginID any) (int, error) {
	return GetGlobalManager().GetSessionCountByLoginID(toString(loginID))
}

// ============ 安全功能 ============

// GenerateNonce 生成一次性随机令牌
func GenerateNonce() (string, error) {
	return GetGlobalManager().GenerateNonce()
}

// VerifyNonce 验证一次性随机令牌
func VerifyNonce(nonce string) bool {
	return GetGlobalManager().VerifyNonce(nonce)
}

// LoginWithRefreshToken 使用 Refresh Token 登录
func LoginWithRefreshToken(loginID any, device ...string) (*security.RefreshTokenInfo, error) {
	deviceType := "default"
	if len(device) > 0 {
		deviceType = device[0]
	}
	return GetGlobalManager().LoginWithRefreshToken(fmt.Sprintf("%v", loginID), deviceType)
}

// RefreshAccessToken 刷新 Access Token
func RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error) {
	return GetGlobalManager().RefreshAccessToken(refreshToken)
}

// RevokeRefreshToken 撤销 Refresh Token
func RevokeRefreshToken(refreshToken string) error {
	return GetGlobalManager().RevokeRefreshToken(refreshToken)
}

// GetOAuth2Server 获取 OAuth2 服务器实例
func GetOAuth2Server() *oauth2.OAuth2Server {
	return GetGlobalManager().GetOAuth2Server()
}

// ============ 基于 Token 的检查函数 ============

// CheckDisable 检查 Token 对应账号是否被封禁
func CheckDisable(tokenValue string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if IsDisable(loginID) {
		return NewAccountDisabledError(loginID)
	}
	return nil
}

// CheckPermission 检查 Token 是否拥有指定权限
func CheckPermission(tokenValue string, permission string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasPermission(loginID, permission) {
		return NewPermissionDeniedError(permission)
	}
	return nil
}

// CheckPermissionAnd 检查 Token 是否拥有所有指定权限
func CheckPermissionAnd(tokenValue string, permissions []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasPermissionsAnd(loginID, permissions) {
		return NewPermissionDeniedError(fmt.Sprintf("%v", permissions))
	}
	return nil
}

// CheckPermissionOr 检查 Token 是否拥有任一指定权限
func CheckPermissionOr(tokenValue string, permissions []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasPermissionsOr(loginID, permissions) {
		return NewPermissionDeniedError(fmt.Sprintf("%v", permissions))
	}
	return nil
}

// GetPermissionList 获取 Token 对应的权限列表
func GetPermissionList(tokenValue string) ([]string, error) {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return GetPermissions(loginID)
}

// CheckRole 检查 Token 是否拥有指定角色
func CheckRole(tokenValue string, role string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasRole(loginID, role) {
		return NewRoleDeniedError(role)
	}
	return nil
}

// CheckRoleAnd 检查 Token 是否拥有所有指定角色
func CheckRoleAnd(tokenValue string, roles []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasRolesAnd(loginID, roles) {
		return NewRoleDeniedError(fmt.Sprintf("%v", roles))
	}
	return nil
}

// CheckRoleOr 检查 Token 是否拥有任一指定角色
func CheckRoleOr(tokenValue string, roles []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasRolesOr(loginID, roles) {
		return NewRoleDeniedError(fmt.Sprintf("%v", roles))
	}
	return nil
}

// GetRoleList 获取 Token 对应的角色列表
func GetRoleList(tokenValue string) ([]string, error) {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return GetRoles(loginID)
}

// GetTokenSession 获取 Token 对应的 Session
func GetTokenSession(tokenValue string) (*session.Session, error) {
	return GetSessionByToken(tokenValue)
}
