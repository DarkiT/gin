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

func (c AuthConfig) withDefaults() AuthConfig {
	defaults := DefaultAuthConfig()
	defaultBased := c.appearsDefaultBased()

	if c.Secret != "" {
		defaults.Secret = c.Secret
	}
	if c.Expiry > 0 {
		defaults.Expiry = c.Expiry
	}
	if c.RefreshExpiry > 0 {
		defaults.RefreshExpiry = c.RefreshExpiry
	}
	if c.TokenName != "" {
		defaults.TokenName = c.TokenName
	}
	if c.TokenStyle != "" {
		defaults.TokenStyle = c.TokenStyle
	}
	if c.KeyPrefix != "" {
		defaults.KeyPrefix = c.KeyPrefix
	}

	if c.ReadFromHeader || c.ReadFromCookie || c.ReadFromQuery || c.ReadFromBody || defaultBased {
		defaults.ReadFromHeader = c.ReadFromHeader
		defaults.ReadFromCookie = c.ReadFromCookie
		defaults.ReadFromQuery = c.ReadFromQuery
		defaults.ReadFromBody = c.ReadFromBody
	}

	if c.AllowConcurrent || c.ShareToken || c.MaxLoginCount != 0 {
		defaults.AllowConcurrent = c.AllowConcurrent
		defaults.ShareToken = c.ShareToken
		defaults.MaxLoginCount = c.MaxLoginCount
	}
	if c.AutoRenew || c.RenewInterval != 0 || c.MaxRefresh != 0 || c.ActiveTimeout != 0 || defaultBased {
		defaults.AutoRenew = c.AutoRenew
		defaults.RenewInterval = c.RenewInterval
		defaults.MaxRefresh = c.MaxRefresh
		defaults.ActiveTimeout = c.ActiveTimeout
	}

	if c.CookieConfig != nil {
		defaults.CookieConfig = c.CookieConfig
	}
	if c.Storage != nil {
		defaults.Storage = c.Storage
	}
	if c.PermissionLoader != nil {
		defaults.PermissionLoader = c.PermissionLoader
	}
	if c.RoleLoader != nil {
		defaults.RoleLoader = c.RoleLoader
	}

	return defaults
}

func (c AuthConfig) appearsDefaultBased() bool {
	return c.CookieConfig != nil && c.MaxLoginCount == config.DefaultMaxLoginCount
}

// toInternalConfig 转换为内部配置
// 将用户友好的配置转换为 core 层使用的配置
func (c *AuthConfig) toInternalConfig() *config.Config {
	normalized := c.withDefaults()
	cfg := config.DefaultConfig()

	// 基础配置
	if normalized.TokenName != "" {
		cfg.TokenName = normalized.TokenName
	}
	if normalized.Expiry > 0 {
		cfg.Timeout = int64(normalized.Expiry.Seconds())
	}
	if normalized.RefreshExpiry > 0 {
		cfg.RefreshTimeout = int64(normalized.RefreshExpiry.Seconds())
	}
	cfg.TokenStyle = config.TokenStyle(normalized.TokenStyle)
	if normalized.KeyPrefix != "" {
		cfg.KeyPrefix = normalized.KeyPrefix
	}

	// JWT 配置
	if normalized.Secret != "" {
		cfg.JwtSecretKey = normalized.Secret
	}

	// 读取配置
	cfg.IsReadHeader = normalized.ReadFromHeader
	cfg.IsReadCookie = normalized.ReadFromCookie
	cfg.IsReadQuery = normalized.ReadFromQuery
	cfg.IsReadBody = normalized.ReadFromBody

	// 并发登录配置
	cfg.IsConcurrent = normalized.AllowConcurrent
	cfg.IsShare = normalized.ShareToken
	cfg.MaxLoginCount = normalized.MaxLoginCount

	// 自动续期配置
	cfg.AutoRenew = normalized.AutoRenew
	if normalized.RenewInterval > 0 {
		cfg.RenewInterval = int64(normalized.RenewInterval.Seconds())
	}
	if normalized.MaxRefresh > 0 {
		cfg.MaxRefresh = int64(normalized.MaxRefresh.Seconds())
	}
	if normalized.ActiveTimeout > 0 {
		cfg.ActiveTimeout = int64(normalized.ActiveTimeout.Seconds())
	}

	// Cookie 配置
	if normalized.CookieConfig != nil {
		if cfg.CookieConfig == nil {
			cfg.CookieConfig = &config.CookieConfig{}
		}
		cfg.CookieConfig.Path = normalized.CookieConfig.Path
		cfg.CookieConfig.Domain = normalized.CookieConfig.Domain
		cfg.CookieConfig.Secure = normalized.CookieConfig.Secure
		cfg.CookieConfig.HttpOnly = normalized.CookieConfig.HttpOnly
		cfg.CookieConfig.SameSite = config.SameSiteMode(normalized.CookieConfig.SameSite)
	}

	return cfg
}

// Validate 验证配置
func (c *AuthConfig) Validate() error {
	normalized := c.withDefaults()
	// 验证 Token 风格
	if !TokenStyle(normalized.TokenStyle).IsValid() {
		return ErrInvalidTokenStyle
	}

	// JWT 风格必须提供 Secret
	if normalized.TokenStyle == TokenStyleJWT && normalized.Secret == "" {
		return ErrJWTSecretRequired
	}

	// Token 过期时间不能为负，0 表示使用默认值。
	if c.Expiry < 0 {
		return ErrInvalidExpiry
	}
	if c.RefreshExpiry < 0 {
		return ErrInvalidExpiry
	}

	return nil
}
