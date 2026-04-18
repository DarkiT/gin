package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/darkit/gin/auth/core/oauth2"
	"github.com/darkit/gin/auth/core/security"
	"github.com/darkit/gin/auth/core/session"
)

var (
	TokenValueKey  = "stplogic:tokenvalue"
	LoginIdKey     = "stplogic:loginid"
	PermissionsKey = "stplogic:permissions"
	RolesKey       = "stplogic:roles"
)

// StpLogic 提供与上游 stputil 对齐的多认证逻辑封装。
// 它基于独立 Manager 实例工作，适合多套认证域并存的场景。
type StpLogic struct {
	manager *Manager
	mu      sync.RWMutex
}

// NewStpLogic 创建 StpLogic 实例。
func NewStpLogic(mgr *Manager) *StpLogic {
	return &StpLogic{manager: mgr}
}

// GetManager 获取当前绑定的 Manager。
func (s *StpLogic) GetManager() *Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.manager == nil {
		panic("auth: StpLogic 未初始化，请先绑定 Manager")
	}
	return s.manager
}

// SetManager 绑定 Manager。
func (s *StpLogic) SetManager(mgr *Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manager = mgr
}

// Login 用户登录。
func (s *StpLogic) Login(loginID any, device ...string) (string, error) {
	return s.GetManager().Login(toString(loginID), device...)
}

// LoginByToken 使用指定 Token 登录。
func (s *StpLogic) LoginByToken(loginID any, tokenValue string, device ...string) error {
	return s.GetManager().LoginByToken(toString(loginID), tokenValue, device...)
}

// Logout 用户登出。
func (s *StpLogic) Logout(loginID any, device ...string) error {
	return s.GetManager().Logout(toString(loginID), device...)
}

// LogoutByToken 根据 Token 登出。
func (s *StpLogic) LogoutByToken(tokenValue string) error {
	return s.GetManager().LogoutByToken(tokenValue)
}

// IsLogin 检查是否已登录。
func (s *StpLogic) IsLogin(tokenValue string) bool {
	return s.GetManager().IsLogin(tokenValue)
}

// CheckLogin 检查登录状态。
func (s *StpLogic) CheckLogin(tokenValue string) error {
	return s.GetManager().CheckLogin(tokenValue)
}

// GetLoginID 获取登录 ID。
func (s *StpLogic) GetLoginID(tokenValue string) (string, error) {
	return s.GetManager().GetLoginID(tokenValue)
}

// GetLoginIDNotCheck 获取登录 ID（不校验）。
func (s *StpLogic) GetLoginIDNotCheck(tokenValue string) (string, error) {
	return s.GetManager().GetLoginIDNotCheck(tokenValue)
}

// GetTokenValue 获取账号当前 Token。
func (s *StpLogic) GetTokenValue(loginID any, device ...string) (string, error) {
	return s.GetManager().GetTokenValue(toString(loginID), device...)
}

// GetTokenInfo 获取 Token 信息。
func (s *StpLogic) GetTokenInfo(tokenValue string) (*TokenInfo, error) {
	return s.GetManager().GetTokenInfo(tokenValue)
}

// Kickout 踢人下线。
func (s *StpLogic) Kickout(loginID any, device ...string) error {
	return s.GetManager().Kickout(toString(loginID), device...)
}

// Disable 封禁账号。
func (s *StpLogic) Disable(loginID any, duration time.Duration) error {
	return s.GetManager().Disable(toString(loginID), duration)
}

// Untie 解封账号。
func (s *StpLogic) Untie(loginID any) error {
	return s.GetManager().Untie(toString(loginID))
}

// IsDisable 检查账号是否被封禁。
func (s *StpLogic) IsDisable(loginID any) bool {
	return s.GetManager().IsDisable(toString(loginID))
}

// GetDisableTime 获取剩余封禁时间。
func (s *StpLogic) GetDisableTime(loginID any) (int64, error) {
	return s.GetManager().GetDisableTime(toString(loginID))
}

// GetSession 获取 Session。
func (s *StpLogic) GetSession(loginID any) (*session.Session, error) {
	return s.GetManager().GetSession(toString(loginID))
}

// GetSessionByToken 根据 Token 获取 Session。
func (s *StpLogic) GetSessionByToken(tokenValue string) (*session.Session, error) {
	return s.GetManager().GetSessionByToken(tokenValue)
}

// DeleteSession 删除 Session。
func (s *StpLogic) DeleteSession(loginID any) error {
	return s.GetManager().DeleteSession(toString(loginID))
}

// SetPermissions 设置权限。
func (s *StpLogic) SetPermissions(loginID any, permissions []string) error {
	return s.GetManager().SetPermissions(toString(loginID), permissions)
}

// GetPermissions 获取权限列表。
func (s *StpLogic) GetPermissions(loginID any) ([]string, error) {
	return s.GetManager().GetPermissions(toString(loginID))
}

// HasPermission 检查单个权限。
func (s *StpLogic) HasPermission(loginID any, permission string) bool {
	return s.GetManager().HasPermission(toString(loginID), permission)
}

// HasPermissionsAnd 检查是否拥有全部权限。
func (s *StpLogic) HasPermissionsAnd(loginID any, permissions []string) bool {
	return s.GetManager().HasPermissionsAnd(toString(loginID), permissions)
}

// HasPermissionsOr 检查是否拥有任一权限。
func (s *StpLogic) HasPermissionsOr(loginID any, permissions []string) bool {
	return s.GetManager().HasPermissionsOr(toString(loginID), permissions)
}

// SetRoles 设置角色。
func (s *StpLogic) SetRoles(loginID any, roles []string) error {
	return s.GetManager().SetRoles(toString(loginID), roles)
}

// GetRoles 获取角色列表。
func (s *StpLogic) GetRoles(loginID any) ([]string, error) {
	return s.GetManager().GetRoles(toString(loginID))
}

// HasRole 检查单个角色。
func (s *StpLogic) HasRole(loginID any, role string) bool {
	return s.GetManager().HasRole(toString(loginID), role)
}

// HasRolesAnd 检查是否拥有全部角色。
func (s *StpLogic) HasRolesAnd(loginID any, roles []string) bool {
	return s.GetManager().HasRolesAnd(toString(loginID), roles)
}

// HasRolesOr 检查是否拥有任一角色。
func (s *StpLogic) HasRolesOr(loginID any, roles []string) bool {
	return s.GetManager().HasRolesOr(toString(loginID), roles)
}

// SetTokenTag 设置 Token 标签。
func (s *StpLogic) SetTokenTag(tokenValue, tag string) error {
	return s.GetManager().SetTokenTag(tokenValue, tag)
}

// GetTokenTag 获取 Token 标签。
func (s *StpLogic) GetTokenTag(tokenValue string) (string, error) {
	return s.GetManager().GetTokenTag(tokenValue)
}

// GetTokenValueList 获取账号全部 Token。
func (s *StpLogic) GetTokenValueList(loginID any) ([]string, error) {
	return s.GetManager().GetTokenValueListByLoginID(toString(loginID))
}

// GetSessionCount 获取 Session 数量。
func (s *StpLogic) GetSessionCount(loginID any) (int, error) {
	return s.GetManager().GetSessionCountByLoginID(toString(loginID))
}

// GenerateNonce 生成一次性随机串。
func (s *StpLogic) GenerateNonce() (string, error) {
	return s.GetManager().GenerateNonce()
}

// VerifyNonce 验证一次性随机串。
func (s *StpLogic) VerifyNonce(nonce string) bool {
	return s.GetManager().VerifyNonce(nonce)
}

// LoginWithRefreshToken 使用 Refresh Token 方案登录。
func (s *StpLogic) LoginWithRefreshToken(loginID any, device ...string) (*security.RefreshTokenInfo, error) {
	dev := "default"
	if len(device) > 0 && device[0] != "" {
		dev = device[0]
	}
	return s.GetManager().LoginWithRefreshToken(toString(loginID), dev)
}

// RefreshAccessToken 刷新 Access Token。
func (s *StpLogic) RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error) {
	return s.GetManager().RefreshAccessToken(refreshToken)
}

// RevokeRefreshToken 撤销 Refresh Token。
func (s *StpLogic) RevokeRefreshToken(refreshToken string) error {
	return s.GetManager().RevokeRefreshToken(refreshToken)
}

// GetOAuth2Server 获取 OAuth2 Server。
func (s *StpLogic) GetOAuth2Server() *oauth2.OAuth2Server {
	return s.GetManager().GetOAuth2Server()
}

// CheckDisable 检查 Token 对应账号是否被封禁。
func (s *StpLogic) CheckDisable(tokenValue string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if s.IsDisable(loginID) {
		return NewAccountDisabledError(loginID)
	}
	return nil
}

// CheckPermission 检查 Token 是否拥有指定权限。
func (s *StpLogic) CheckPermission(tokenValue string, permission string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermission(loginID, permission) {
		return NewPermissionDeniedError(permission)
	}
	return nil
}

// CheckPermissionAnd 检查 Token 是否拥有所有权限。
func (s *StpLogic) CheckPermissionAnd(tokenValue string, permissions []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermissionsAnd(loginID, permissions) {
		return NewPermissionDeniedError(fmt.Sprintf("%v", permissions))
	}
	return nil
}

// CheckPermissionOr 检查 Token 是否拥有任一权限。
func (s *StpLogic) CheckPermissionOr(tokenValue string, permissions []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermissionsOr(loginID, permissions) {
		return NewPermissionDeniedError(fmt.Sprintf("%v", permissions))
	}
	return nil
}

// GetPermissionList 获取 Token 对应权限列表。
func (s *StpLogic) GetPermissionList(tokenValue string) ([]string, error) {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return s.GetPermissions(loginID)
}

// CheckRole 检查 Token 是否拥有指定角色。
func (s *StpLogic) CheckRole(tokenValue string, role string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRole(loginID, role) {
		return NewRoleDeniedError(role)
	}
	return nil
}

// CheckRoleAnd 检查 Token 是否拥有所有角色。
func (s *StpLogic) CheckRoleAnd(tokenValue string, roles []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRolesAnd(loginID, roles) {
		return NewRoleDeniedError(fmt.Sprintf("%v", roles))
	}
	return nil
}

// CheckRoleOr 检查 Token 是否拥有任一角色。
func (s *StpLogic) CheckRoleOr(tokenValue string, roles []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRolesOr(loginID, roles) {
		return NewRoleDeniedError(fmt.Sprintf("%v", roles))
	}
	return nil
}

// GetRoleList 获取 Token 对应角色列表。
func (s *StpLogic) GetRoleList(tokenValue string) ([]string, error) {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return s.GetRoles(loginID)
}

// GetTokenSession 获取 Token 对应 Session。
func (s *StpLogic) GetTokenSession(tokenValue string) (*session.Session, error) {
	return s.GetSessionByToken(tokenValue)
}

// CloseManager 关闭绑定的 Manager。
func (s *StpLogic) CloseManager() {
	mgr := s.GetManager()
	mgr.CloseManager()
}
