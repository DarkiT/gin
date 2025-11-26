package gin

import (
	"fmt"
	"time"
)

// TokenResponse OAuth令牌响应结构
type TokenResponse struct {
	AccessToken  string `json:"access_token"`    // 访问令牌
	RefreshToken string `json:"refresh_token"`   // 刷新令牌
	TokenType    string `json:"token_type"`      // 令牌类型，通常为"Bearer"
	ExpiresIn    int64  `json:"expires_in"`      // 访问令牌过期时间（秒）
	Scope        string `json:"scope,omitempty"` // 权限范围
	JTI          string `json:"jti,omitempty"`   // JWT ID
}

// RefreshRequest 刷新令牌请求结构
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"` // 刷新令牌
	Scope        string `json:"scope,omitempty"`                  // 可选的权限范围
}

// UserClaims 用户声明结构
type UserClaims struct {
	UserID   string   `json:"user_id"`         // 用户ID
	Username string   `json:"username"`        // 用户名
	Email    string   `json:"email,omitempty"` // 邮箱
	Roles    []string `json:"roles,omitempty"` // 角色列表
	Scope    string   `json:"scope,omitempty"` // 权限范围
}

// OAuthConfig OAuth配置
type OAuthConfig struct {
	AccessTokenTTL  time.Duration // 访问令牌过期时间，默认15分钟
	RefreshTokenTTL time.Duration // 刷新令牌过期时间，默认7天
	Issuer          string        // 签发者
	DefaultScope    string        // 默认权限范围
}

// DefaultOAuthConfig 默认OAuth配置
func DefaultOAuthConfig() *OAuthConfig {
	return &OAuthConfig{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "gin-oauth-server",
		DefaultScope:    "read",
	}
}

// GenerateTokens 生成OAuth令牌对
func (c *Context) GenerateTokens(userClaims UserClaims, config ...*OAuthConfig) (*TokenResponse, error) {
	// 获取JWT适配器
	jwtAdapter := c.getJWTAdapter()
	if jwtAdapter == nil {
		return nil, fmt.Errorf("JWT适配器未初始化")
	}

	// 使用配置或默认配置
	cfg := DefaultOAuthConfig()
	if len(config) > 0 && config[0] != nil {
		cfg = config[0]
	}

	now := time.Now()
	jti := c.GenerateRequestID() // 使用UUID v5作为JTI

	// 创建访问令牌载荷
	accessPayload := JWTPayload{
		ClaimIss:  cfg.Issuer,
		ClaimSub:  userClaims.UserID,
		ClaimAud:  "api",
		ClaimIat:  now.Unix(),
		ClaimExp:  now.Add(cfg.AccessTokenTTL).Unix(),
		ClaimJti:  jti,
		ClaimType: TokenTypeAccess,

		// 自定义用户声明
		"user_id":  userClaims.UserID,
		"username": userClaims.Username,
		"email":    userClaims.Email,
		"roles":    userClaims.Roles,
		"scope":    getScope(userClaims.Scope, cfg.DefaultScope),
	}

	// 创建刷新令牌载荷
	refreshPayload := JWTPayload{
		ClaimIss:  cfg.Issuer,
		ClaimSub:  userClaims.UserID,
		ClaimAud:  "refresh",
		ClaimIat:  now.Unix(),
		ClaimExp:  now.Add(cfg.RefreshTokenTTL).Unix(),
		ClaimJti:  jti + "-refresh",
		ClaimType: TokenTypeRefresh,

		// 刷新令牌只包含必要信息
		"user_id": userClaims.UserID,
		"scope":   getScope(userClaims.Scope, cfg.DefaultScope),
	}

	// 生成令牌
	accessToken, err := jwtAdapter.GenerateToken(accessPayload)
	if err != nil {
		return nil, fmt.Errorf("生成访问令牌失败: %v", err)
	}

	refreshToken, err := jwtAdapter.GenerateToken(refreshPayload)
	if err != nil {
		return nil, fmt.Errorf("生成刷新令牌失败: %v", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(cfg.AccessTokenTTL.Seconds()),
		Scope:        getScope(userClaims.Scope, cfg.DefaultScope),
		JTI:          jti,
	}, nil
}

// RefreshTokens 刷新令牌
func (c *Context) RefreshTokens(refreshToken string, config ...*OAuthConfig) (*TokenResponse, error) {
	// 获取JWT适配器
	jwtAdapter := c.getJWTAdapter()
	if jwtAdapter == nil {
		return nil, fmt.Errorf("JWT适配器未初始化")
	}

	// 验证刷新令牌
	payload, err := jwtAdapter.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("刷新令牌无效: %v", err)
	}

	// 检查令牌类型
	tokenType, _ := payload.GetClaim(ClaimType)
	tokenTypeStr, _ := tokenType.(string)
	if tokenTypeStr != TokenTypeRefresh {
		return nil, fmt.Errorf("令牌类型错误，期望refresh，实际%s", tokenTypeStr)
	}

	// 提取用户信息
	userID, _ := payload.GetClaim("user_id")
	userIDStr, _ := userID.(string)
	scope, _ := payload.GetClaim("scope")
	scopeStr, _ := scope.(string)

	if userIDStr == "" {
		return nil, fmt.Errorf("刷新令牌中缺少用户ID")
	}

	// 从 refresh token 无法获取完整资料，这里使用最小化安全信息；业务方可在生成时附加更多字段。
	userClaims := UserClaims{
		UserID:   userIDStr,
		Username: userIDStr,
		Scope:    scopeStr,
	}

	// 生成新的令牌对
	return c.GenerateTokens(userClaims, config...)
}

// getScope 获取权限范围，优先使用用户指定的，否则使用默认的
func getScope(userScope, defaultScope string) string {
	if userScope != "" {
		return userScope
	}
	return defaultScope
}
