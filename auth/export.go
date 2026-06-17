package auth

import (
	"github.com/darkit/gin/auth/core/adapter"
	"github.com/darkit/gin/auth/core/config"
	"github.com/darkit/gin/auth/core/listener"
	"github.com/darkit/gin/auth/core/manager"
	"github.com/darkit/gin/auth/core/oauth2"
	"github.com/darkit/gin/auth/core/security"
	"github.com/darkit/gin/auth/core/session"
	"github.com/darkit/gin/auth/core/token"
	"github.com/darkit/gin/auth/storage/kv"
	"github.com/darkit/gin/auth/storage/memory"
	"github.com/darkit/gin/auth/storage/redis"
	"github.com/darkit/gin/pkg/storage"
)

// ============ 核心类型导出 ============

// Manager 认证管理器
type Manager = manager.Manager

// Session 会话
type Session = session.Session

// TokenInfo Token 信息
type TokenInfo = manager.TokenInfo

// Storage 存储接口
type Storage = adapter.Storage

// RequestContext 请求上下文接口
type RequestContext = adapter.RequestContext

// ============ Token 相关 ============

// TokenStyle Token 生成风格
type TokenStyle = config.TokenStyle

// Token 风格常量
const (
	// TokenStyleUUID UUID 风格
	TokenStyleUUID TokenStyle = config.TokenStyleUUID
	// TokenStyleSimple 简单随机字符串
	TokenStyleSimple TokenStyle = config.TokenStyleSimple
	// TokenStyleRandom32 32 位随机字符串
	TokenStyleRandom32 TokenStyle = config.TokenStyleRandom32
	// TokenStyleRandom64 64 位随机字符串
	TokenStyleRandom64 TokenStyle = config.TokenStyleRandom64
	// TokenStyleRandom128 128 位随机字符串
	TokenStyleRandom128 TokenStyle = config.TokenStyleRandom128
	// TokenStyleJWT JWT 风格
	TokenStyleJWT TokenStyle = config.TokenStyleJWT
	// TokenStyleHash SHA256 哈希风格
	TokenStyleHash TokenStyle = config.TokenStyleHash
	// TokenStyleTimestamp 时间戳风格
	TokenStyleTimestamp TokenStyle = config.TokenStyleTimestamp
	// TokenStyleTik Tik 风格短 ID
	TokenStyleTik TokenStyle = config.TokenStyleTik
)

// TokenGenerator Token 生成器
type TokenGenerator = token.Generator

// ============ Cookie 相关 ============

// SameSiteMode Cookie SameSite 属性
type SameSiteMode = config.SameSiteMode

// SameSite 模式常量
const (
	// SameSiteStrict 严格模式
	SameSiteStrict SameSiteMode = config.SameSiteStrict
	// SameSiteLax 宽松模式
	SameSiteLax SameSiteMode = config.SameSiteLax
	// SameSiteNone 无限制模式
	SameSiteNone SameSiteMode = config.SameSiteNone
)

// CookieOptions Cookie 选项
type CookieOptions = adapter.CookieOptions

// ============ 事件相关 ============

// Event 事件类型
type Event = listener.Event

// 事件常量
const (
	// EventLogin 登录事件
	EventLogin Event = listener.EventLogin
	// EventLogout 登出事件
	EventLogout Event = listener.EventLogout
	// EventKickout 踢人事件
	EventKickout Event = listener.EventKickout
	// EventDisable 封禁事件
	EventDisable Event = listener.EventDisable
	// EventUntie 解封事件
	EventUntie Event = listener.EventUntie
	// EventRenew Token 续期事件
	EventRenew Event = listener.EventRenew
	// EventCreateSession 创建 Session 事件
	EventCreateSession Event = listener.EventCreateSession
	// EventDestroySession 销毁 Session 事件
	EventDestroySession Event = listener.EventDestroySession
)

// EventData 事件数据
type EventData = listener.EventData

// EventListener 事件监听器接口
type EventListener = listener.Listener

// EventManager 事件管理器
type EventManager = listener.Manager

// ============ OAuth2 相关 ============

// OAuth2Server OAuth2 服务器
type OAuth2Server = oauth2.OAuth2Server

// ============ 安全相关 ============

// NonceManager Nonce 管理器
type NonceManager = security.NonceManager

// RefreshTokenManager Refresh Token 管理器
type RefreshTokenManager = security.RefreshTokenManager

// RefreshTokenInfo Refresh Token 信息
type RefreshTokenInfo = security.RefreshTokenInfo

// ============ 存储实现 ============

// NewMemoryStorage 创建内存存储
func NewMemoryStorage() Storage {
	return memory.NewStorage()
}

// NewRedisStorage 创建 Redis 存储
// redisURL 格式: redis://[:password@]host:port[/database]
// 例如: redis://localhost:6379/0 或 redis://:password@localhost:6379/1
func NewRedisStorage(redisURL string) (Storage, error) {
	return redis.NewStorage(redisURL)
}

// NewKVStorage 创建严格模式的通用 KV 认证存储。
//
// 底层 store 必须支持 storage.TTLStore 与 storage.KeyScanner；不满足时返回错误，避免把基础 KV 后端误用于完整 auth/session 主链。
func NewKVStorage(store storage.Store) (Storage, error) {
	return kv.NewStrict(store)
}

// NewRelaxedKVStorage 创建宽松模式的通用 KV 认证存储。
//
// 宽松模式只要求底层实现 storage.Store；调用 TTL、Keys、Expire、SetKeepTTL 等增强能力时，
// 若后端不支持会返回 kv.ErrUnsupportedOperation。生产认证主链优先使用 NewKVStorage。
func NewRelaxedKVStorage(store storage.Store) Storage {
	return kv.NewRelaxed(store)
}

// NewAtomicKVStorage 创建带原子 SetNX 能力的通用 KV 认证存储。
//
// 该入口适合需要 OAuth2 操作锁走后端原子 SetNX 的场景；底层必须实现 kv.AtomicStore。
func NewAtomicKVStorage(store kv.AtomicStore) Storage {
	return kv.NewAtomic(store)
}

// ============ 工厂函数 ============

// NewManager 创建认证管理器
func NewManager(storage Storage, cfg *AuthConfig) *Manager {
	if cfg == nil {
		defaultCfg := DefaultAuthConfig()
		cfg = &defaultCfg
	}
	if storage == nil {
		storage = NewMemoryStorage()
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	// 转换配置
	internalCfg := cfg.toInternalConfig()

	// 创建管理器
	mgr := manager.NewManager(storage, internalCfg)

	// 设置权限/角色加载器
	if cfg.PermissionLoader != nil || cfg.RoleLoader != nil {
		mgr.SetLoaders(cfg.PermissionLoader, cfg.RoleLoader)
	}

	return mgr
}
