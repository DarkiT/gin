package auth

import (
	"time"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/core/config"
)

// AuthConfig 认证授权配置
// 对外暴露的简化配置，提供更友好的 API
type AuthConfig struct {
	// ============ 基础配置 ============

	// Secret JWT 密钥（TokenStyle 为 JWT 时必需）
	Secret string

	// Expiry Token 过期时间
	// 默认: 30 天
	Expiry time.Duration

	// RefreshExpiry Refresh Token 过期时间。
	// 默认: 30 天。
	RefreshExpiry time.Duration

	// TokenName Token 名称（Header/Cookie/Query 参数名）
	// 默认: "satoken"
	TokenName string

	// TokenStyle Token 生成风格
	// 可选: UUID, JWT, Simple, Random32/64/128, Hash, Timestamp, Tik
	// 默认: TokenStyleUUID
	TokenStyle TokenStyle

	// KeyPrefix 存储键前缀
	// 默认: "satoken:"
	KeyPrefix string

	// ============ 读取配置 ============

	// ReadFromHeader 从 HTTP Header 读取 Token
	// 默认: true
	ReadFromHeader bool

	// ReadFromCookie 从 Cookie 读取 Token
	// 默认: false
	ReadFromCookie bool

	// ReadFromQuery 从 URL Query 参数读取 Token
	// 默认: false
	ReadFromQuery bool

	// ReadFromBody 从请求体读取 Token
	// 默认: false
	ReadFromBody bool

	// ============ 并发登录配置 ============

	// AllowConcurrent 允许并发登录
	// true: 允许同一账号多处登录
	// false: 新登录会踢出旧登录
	// 默认: true
	AllowConcurrent bool

	// ShareToken 共享 Token
	// true: 多处登录共用一个 Token
	// false: 每次登录生成新 Token
	// 默认: true
	ShareToken bool

	// MaxLoginCount 最大并发登录数
	// -1: 不限制
	// >0: 限制最大登录数，超出时踢出最早的登录
	// 默认: 12
	MaxLoginCount int

	// ============ 自动续期配置 ============

	// AutoRenew 自动续期
	// true: Token 访问时自动续期
	// false: Token 到期后需要重新登录
	// 默认: true
	AutoRenew bool

	// RenewInterval 续期间隔
	// 同一 Token 在此时间内只会续期一次，避免频繁续期
	// 0 或负数: 不限制续期频率
	// 默认: 0（不限制）
	RenewInterval time.Duration

	// MaxRefresh 续期触发阈值
	// 当 Token 剩余有效期低于此值时触发续期
	// 0: 使用 Expiry/2 作为阈值
	// 默认: 0（自动计算）
	MaxRefresh time.Duration

	// ActiveTimeout 最低活跃频率
	// Token 超过此时间未访问会被冻结
	// 0 或负数: 永不冻结
	// 默认: 0（永不冻结）
	ActiveTimeout time.Duration

	// ============ Cookie 配置 ============

	// CookieConfig Cookie 相关配置
	// 仅在 ReadFromCookie=true 时生效
	CookieConfig *CookieConfig

	// ============ 存储配置 ============

	// Storage 自定义存储实现
	// 不设置时使用内存存储
	// 生产环境建议使用 Redis 存储
	Storage adapter.Storage

	// ============ 权限加载器 ============

	// PermissionLoader 权限加载器
	// 用于从数据库加载用户权限列表
	PermissionLoader func(loginID string) ([]string, error)

	// RoleLoader 角色加载器
	// 用于从数据库加载用户角色列表
	RoleLoader func(loginID string) ([]string, error)
}

// CookieConfig Cookie 配置
type CookieConfig struct {
	// Path Cookie 路径
	// 默认: "/"
	Path string

	// Domain Cookie 域名
	// 默认: ""（当前域名）
	Domain string

	// Secure 仅 HTTPS
	// 默认: false
	Secure bool

	// HttpOnly 禁止 JavaScript 访问
	// 默认: true
	HttpOnly bool

	// SameSite SameSite 属性
	// 可选: Strict, Lax, None
	// 默认: Lax
	SameSite SameSiteMode
}

// DefaultAuthConfig 返回默认配置
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		Expiry:          30 * 24 * time.Hour, // 30 天
		RefreshExpiry:   30 * 24 * time.Hour, // 30 天
		TokenName:       config.DefaultTokenName,
		TokenStyle:      TokenStyleUUID,
		KeyPrefix:       "satoken:",
		ReadFromHeader:  true,
		ReadFromCookie:  false,
		ReadFromQuery:   false,
		ReadFromBody:    false,
		AllowConcurrent: true,
		ShareToken:      true,
		MaxLoginCount:   config.DefaultMaxLoginCount,
		AutoRenew:       true,
		RenewInterval:   0,
		MaxRefresh:      0,
		ActiveTimeout:   0,
		CookieConfig: &CookieConfig{
			Path:     config.DefaultCookiePath,
			Domain:   "",
			Secure:   false,
			HttpOnly: true,
			SameSite: SameSiteLax,
		},
	}
}

// toInternalConfig 转换为内部配置
// 将用户友好的配置转换为 core 层使用的配置
func (c *AuthConfig) toInternalConfig() *config.Config {
	cfg := config.DefaultConfig()

	// 基础配置
	if c.TokenName != "" {
		cfg.TokenName = c.TokenName
	}
	if c.Expiry > 0 {
		cfg.Timeout = int64(c.Expiry.Seconds())
	}
	if c.RefreshExpiry > 0 {
		cfg.RefreshTimeout = int64(c.RefreshExpiry.Seconds())
	}
	cfg.TokenStyle = config.TokenStyle(c.TokenStyle)
	if c.KeyPrefix != "" {
		cfg.KeyPrefix = c.KeyPrefix
	}

	// JWT 配置
	if c.Secret != "" {
		cfg.JwtSecretKey = c.Secret
	}

	// 读取配置
	cfg.IsReadHeader = c.ReadFromHeader
	cfg.IsReadCookie = c.ReadFromCookie
	cfg.IsReadBody = c.ReadFromBody

	// 并发登录配置
	cfg.IsConcurrent = c.AllowConcurrent
	cfg.IsShare = c.ShareToken
	cfg.MaxLoginCount = c.MaxLoginCount

	// 自动续期配置
	cfg.AutoRenew = c.AutoRenew
	if c.RenewInterval > 0 {
		cfg.RenewInterval = int64(c.RenewInterval.Seconds())
	}
	if c.MaxRefresh > 0 {
		cfg.MaxRefresh = int64(c.MaxRefresh.Seconds())
	}
	if c.ActiveTimeout > 0 {
		cfg.ActiveTimeout = int64(c.ActiveTimeout.Seconds())
	}

	// Cookie 配置
	if c.CookieConfig != nil {
		if cfg.CookieConfig == nil {
			cfg.CookieConfig = &config.CookieConfig{}
		}
		cfg.CookieConfig.Path = c.CookieConfig.Path
		cfg.CookieConfig.Domain = c.CookieConfig.Domain
		cfg.CookieConfig.Secure = c.CookieConfig.Secure
		cfg.CookieConfig.HttpOnly = c.CookieConfig.HttpOnly
		cfg.CookieConfig.SameSite = config.SameSiteMode(c.CookieConfig.SameSite)
	}

	return cfg
}

// Validate 验证配置
func (c *AuthConfig) Validate() error {
	// 验证 Token 风格
	if !TokenStyle(c.TokenStyle).IsValid() {
		return ErrInvalidTokenStyle
	}

	// JWT 风格必须提供 Secret
	if c.TokenStyle == TokenStyleJWT && c.Secret == "" {
		return ErrJWTSecretRequired
	}

	// Token 过期时间必须大于 0
	if c.Expiry <= 0 {
		return ErrInvalidExpiry
	}
	if c.RefreshExpiry <= 0 {
		return ErrInvalidExpiry
	}

	return nil
}
