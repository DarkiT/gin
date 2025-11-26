package gin

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// SecurityHeadersMiddleware 安全HTTP头中间件
func SecurityHeadersMiddleware() HandlerFunc {
	return func(c *Context) {
		// 防止点击劫持攻击
		c.Header("X-Frame-Options", "DENY")

		// 防止MIME类型嗅探攻击
		c.Header("X-Content-Type-Options", "nosniff")

		// XSS保护
		c.Header("X-XSS-Protection", "1; mode=block")

		// 强制HTTPS
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// 减少信息泄露
		c.Header("X-Powered-By", "")
		c.Header("Server", "")

		// 引用者策略
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// 权限策略（新版本的Feature Policy）
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// 默认的内容安全策略（可以被具体路由覆盖）
		if c.GetHeader("Content-Security-Policy") == "" {
			csp := "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
				"style-src 'self' 'unsafe-inline'; " +
				"img-src 'self' data: https:; " +
				"font-src 'self' data:; " +
				"connect-src 'self'; " +
				"frame-ancestors 'none';"
			c.Header("Content-Security-Policy", csp)
		}

		c.Next()
	}
}

// CustomSecurityHeadersMiddleware 可定制的安全HTTP头中间件
func CustomSecurityHeadersMiddleware(config SecurityHeadersConfig) HandlerFunc {
	return func(c *Context) {
		// X-Frame-Options
		if config.XFrameOptions != "" {
			c.Header("X-Frame-Options", config.XFrameOptions)
		}

		// X-Content-Type-Options
		if config.XContentTypeOptions {
			c.Header("X-Content-Type-Options", "nosniff")
		}

		// X-XSS-Protection
		if config.XXSSProtection != "" {
			c.Header("X-XSS-Protection", config.XXSSProtection)
		}

		// Strict-Transport-Security
		if config.StrictTransportSecurity != "" {
			c.Header("Strict-Transport-Security", config.StrictTransportSecurity)
		}

		// Content-Security-Policy
		if config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		// Referrer-Policy
		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		// Permissions-Policy
		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
		}

		// 隐藏服务器信息
		if config.HideServerInfo {
			c.Header("X-Powered-By", "")
			c.Header("Server", "")
		}

		c.Next()
	}
}

// SecurityHeadersConfig 安全头配置
type SecurityHeadersConfig struct {
	XFrameOptions           string // DENY, SAMEORIGIN, ALLOW-FROM uri
	XContentTypeOptions     bool   // 是否启用 nosniff
	XXSSProtection          string // 1; mode=block
	StrictTransportSecurity string // max-age=31536000; includeSubDomains; preload
	ContentSecurityPolicy   string // CSP策略字符串
	ReferrerPolicy          string // 引用者策略
	PermissionsPolicy       string // 权限策略
	HideServerInfo          bool   // 是否隐藏服务器信息
}

// DefaultSecurityHeadersConfig 返回默认安全头配置
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		XFrameOptions:           "DENY",
		XContentTypeOptions:     true,
		XXSSProtection:          "1; mode=block",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"font-src 'self' data:; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none';",
		ReferrerPolicy:    "strict-origin-when-cross-origin",
		PermissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=()",
		HideServerInfo:    true,
	}
}

// StrictCSPConfig 严格的CSP配置
func StrictCSPConfig() string {
	return "default-src 'none'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'; " +
		"object-src 'none'; " +
		"upgrade-insecure-requests"
}

// DevelopmentCSPConfig 开发环境CSP配置（较为宽松）
func DevelopmentCSPConfig() string {
	return "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: https: http:; " +
		"font-src 'self' data: https:; " +
		"connect-src 'self' ws: wss: https: http:; " +
		"frame-ancestors 'none';"
}

// RateLimitMiddleware 增强版限流中间件
func RateLimitMiddleware(config RateLimitConfig) HandlerFunc {
	limiter := NewRateLimiter(config)

	return func(c *Context) {
		key := getRateLimitKey(c, config.KeyFunc)

		allowed, resetTime := limiter.Allow(key)
		if !allowed {
			// 设置限流响应头
			c.Header("X-RateLimit-Limit", strconv.Itoa(config.RequestsPerWindow))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
			c.Header("Retry-After", strconv.Itoa(int(time.Until(resetTime).Seconds())))

			c.JSON(http.StatusTooManyRequests, H{
				"error":       "rate limit exceeded",
				"message":     fmt.Sprintf("请求过于频繁，请在 %v 后重试", time.Until(resetTime).Round(time.Second)),
				"retry_after": int(time.Until(resetTime).Seconds()),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	RequestsPerWindow int                   // 时间窗口内允许的请求数
	WindowSize        time.Duration         // 时间窗口大小
	KeyFunc           func(*Context) string // 获取限流键的函数
}

// getRateLimitKey 获取限流键
func getRateLimitKey(c *Context, keyFunc func(*Context) string) string {
	if keyFunc != nil {
		return keyFunc(c)
	}
	// 默认使用客户端IP作为键
	return c.GetIP()
}

// DefaultRateLimitKeyFunc 默认的限流键生成函数（基于IP）
func DefaultRateLimitKeyFunc(c *Context) string {
	return c.GetIP()
}

// UserBasedRateLimitKeyFunc 基于用户的限流键生成函数
func UserBasedRateLimitKeyFunc(c *Context) string {
	// 尝试从JWT中获取用户ID
	if payload := c.GetJWTPayload(); payload != nil {
		if userID, ok := payload["user_id"].(string); ok {
			return "user:" + userID
		}
	}
	// 回退到IP限流
	return "ip:" + c.GetIP()
}

// EndpointBasedRateLimitKeyFunc 基于端点的限流键生成函数
func EndpointBasedRateLimitKeyFunc(c *Context) string {
	return c.GetIP() + ":" + c.Request.Method + ":" + c.Request.URL.Path
}

// RateLimiter 限流器接口
type RateLimiter interface {
	Allow(key string) (allowed bool, resetTime time.Time)
	Reset(key string)
	Stats(key string) (requests int, resetTime time.Time)
}

// MemoryRateLimiter 内存限流器
type MemoryRateLimiter struct {
	config  RateLimitConfig
	windows sync.Map // map[string]*rateLimitWindow
}

type rateLimitWindow struct {
	requests  int
	startTime time.Time
	mutex     sync.Mutex
}

// NewRateLimiter 创建新的限流器
func NewRateLimiter(config RateLimitConfig) RateLimiter {
	limiter := &MemoryRateLimiter{
		config: config,
	}

	// 启动清理goroutine
	go limiter.cleanup()

	return limiter
}

// Allow 检查是否允许请求
func (rl *MemoryRateLimiter) Allow(key string) (bool, time.Time) {
	now := time.Now()
	value, loaded := rl.windows.LoadOrStore(key, &rateLimitWindow{
		startTime: now,
	})

	window := value.(*rateLimitWindow)
	window.mutex.Lock()
	defer window.mutex.Unlock()

	if !loaded {
		window.requests = 1
		window.startTime = now
		return true, now.Add(rl.config.WindowSize)
	}

	if now.Sub(window.startTime) >= rl.config.WindowSize {
		window.requests = 1
		window.startTime = now
		return true, now.Add(rl.config.WindowSize)
	}

	if window.requests >= rl.config.RequestsPerWindow {
		return false, window.startTime.Add(rl.config.WindowSize)
	}

	window.requests++
	return true, window.startTime.Add(rl.config.WindowSize)
}

// Reset 重置指定键的限流状态
func (rl *MemoryRateLimiter) Reset(key string) {
	rl.windows.Delete(key)
}

// Stats 获取限流统计信息
func (rl *MemoryRateLimiter) Stats(key string) (int, time.Time) {
	value, ok := rl.windows.Load(key)
	if !ok {
		return 0, time.Now().Add(rl.config.WindowSize)
	}

	window := value.(*rateLimitWindow)
	window.mutex.Lock()
	defer window.mutex.Unlock()

	return window.requests, window.startTime.Add(rl.config.WindowSize)
}

// cleanup 清理过期的限流窗口
func (rl *MemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.WindowSize)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		rl.windows.Range(func(key, value interface{}) bool {
			window, ok := value.(*rateLimitWindow)
			if !ok {
				return true
			}

			window.mutex.Lock()
			expired := now.Sub(window.startTime) >= rl.config.WindowSize*2 // 给予额外缓冲时间
			window.mutex.Unlock()

			if expired {
				rl.windows.Delete(key)
			}
			return true
		})
	}
}

// WithSecurityHeaders 添加安全头中间件的路由选项
func WithSecurityHeaders(config ...SecurityHeadersConfig) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		var secConfig SecurityHeadersConfig
		if len(config) > 0 {
			secConfig = config[0]
		} else {
			secConfig = DefaultSecurityHeadersConfig()
		}

		engine.Use(func(ctx *gin.Context) {
			// 创建增强上下文
			enhancedCtx := newContext(ctx)

			// 确保Context在函数结束时被释放回对象池
			defer releaseContext(enhancedCtx)

			// 应用安全头中间件
			CustomSecurityHeadersMiddleware(secConfig)(enhancedCtx)
		})
	}
}

// WithRateLimit 添加限流中间件的路由选项
func WithRateLimitEnhanced(requestsPerMinute int, keyFunc ...func(*Context) string) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		config := RateLimitConfig{
			RequestsPerWindow: requestsPerMinute,
			WindowSize:        time.Minute,
		}

		if len(keyFunc) > 0 {
			config.KeyFunc = keyFunc[0]
		} else {
			config.KeyFunc = DefaultRateLimitKeyFunc
		}

		middleware := RateLimitMiddleware(config)

		engine.Use(func(ctx *gin.Context) {
			// 创建增强上下文
			enhancedCtx := newContext(ctx)

			// 确保Context在函数结束时被释放回对象池
			defer releaseContext(enhancedCtx)

			// 应用限流中间件
			middleware(enhancedCtx)
		})
	}
}
