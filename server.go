package gin

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkit/gin/cache"
	"github.com/darkit/gin/pkg/errors"
	"github.com/darkit/gin/pkg/sse"
	"github.com/darkit/gin/types"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

const (
	EnvGinMode = "GIN_MODE"

	DebugMode   = "debug"
	ReleaseMode = "release"
	TestMode    = "test"
)

// ServerConfig 服务器配置选项
type ServerConfig struct {
	Host            string        // 主机地址
	Port            string        // 端口
	ReadTimeout     time.Duration // 读取超时
	WriteTimeout    time.Duration // 写入超时
	MaxHeaderBytes  int           // 最大头部字节
	CertFile        string        // TLS证书文件
	KeyFile         string        // TLS密钥文件
	EnableHTTP2     bool          // 启用HTTP/2
	GracefulTimeout time.Duration // 优雅关闭超时
}

// Config 框架配置
type Config struct {
	// 缓存配置
	CacheEnabled bool          `json:"cache_enabled"`
	CacheConfig  *cache.Config `json:"cache_config,omitempty"`

	// JWT配置通过SecurityConfig管理

	// 安全配置
	SecurityConfig *SecurityConfig `json:"security_config,omitempty"`

	// SSE配置
	SSEEnabled bool        `json:"sse_enabled"`
	SSEConfig  *sse.Config `json:"sse_config,omitempty"`

	// OpenAPI配置
	OpenAPIEnabled bool     `json:"openapi_enabled"`
	OpenAPI        *OpenAPI `json:"openapi_config,omitempty"`

	// 错误处理配置
	ErrorHandlerEnabled bool `json:"error_handler_enabled"`
	SensitiveFilter     bool `json:"sensitive_filter"`

	// 日志配置
	LoggerConfig *LoggerConfig `json:"logger_config,omitempty"`
}

// DefaultConfig 返回默认框架配置
func DefaultConfig() *Config {
	securityConfig, _ := LoadSecurityConfig() // 忽略错误，使用默认值
	if securityConfig == nil {
		securityConfig = DefaultSecurityConfig()
	}

	return &Config{
		CacheEnabled: false,
		CacheConfig: &cache.Config{
			TTL:             time.Hour,
			CleanupInterval: 10 * time.Minute,
		},
		// 安全配置
		SecurityConfig:      securityConfig,
		SSEEnabled:          false,
		OpenAPIEnabled:      false,
		ErrorHandlerEnabled: true,
		SensitiveFilter:     true,
		// 日志配置
		LoggerConfig: DefaultLoggerConfig(),
	}
}

// DefaultServerConfig 返回默认服务器配置
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Host:            "",
		Port:            "8080",
		ReadTimeout:     time.Second * 60,
		WriteTimeout:    time.Second * 60,
		MaxHeaderBytes:  1 << 20, // 1MB
		EnableHTTP2:     true,
		GracefulTimeout: time.Second * 30, // 增加到30秒，给SSE连接和定时任务足够的清理时间
	}
}

func init() {
	mode := os.Getenv(EnvGinMode)
	if mode == "" {
		if os.Getenv("GO_ENV") == "development" {
			mode = DebugMode
		} else {
			mode = ReleaseMode
		}
	}
	SetMode(mode)
}

// SetMode 根据输入字符串设置 gin 模式。
func SetMode(value string) {
	gin.SetMode(value)
}

// DisableBindValidation 关闭默认的验证器。
func DisableBindValidation() {
	binding.Validator = nil
}

// EnableJsonDecoderUseNumber 设置 binding.EnableDecoderUseNumber 为 true，以调用 JSON 解码器实例的 UseNumber 方法。
func EnableJsonDecoderUseNumber() {
	binding.EnableDecoderUseNumber = true
}

// EnableJsonDecoderDisallowUnknownFields 设置 binding.EnableDecoderDisallowUnknownFields 为 true，以调用 JSON 解码器实例的 DisallowUnknownFields 方法。
func EnableJsonDecoderDisallowUnknownFields() {
	binding.EnableDecoderDisallowUnknownFields = true
}

// New 创建新的路由管理器，支持可选的框架配置
func New(config ...*Config) *Router {
	r := &Router{
		engine:      gin.New(),
		groups:      make(map[string]*RouterGroup),
		routes:      make(map[string]bool),
		middlewares: make([]HandlerFunc, 0),
	}

	// 如果提供了配置，则初始化高级功能
	if len(config) > 0 && config[0] != nil {
		r.config = config[0]
	} else {
		r.config = DefaultConfig()
	}

	// 初始化日志器
	if r.config.LoggerConfig != nil {
		r.logger = r.config.LoggerConfig.GetLogger("GIN-SERVER")
	} else {
		r.logger = NewGinCompatLogger("GIN-SERVER")
	}

	// 初始化各个组件
	_ = r.initializeComponents()

	// 设置增强中间件
	r.setupMiddleware()

	return r
}

// Default 创建默认的路由管理器（包含 Logger、Recovery），支持可选的框架配置
func Default(config ...*Config) *Router {
	r := New(config...) // 传递配置

	// 包装 gin 的默认中间件
	r.UseGin(gin.Logger(), gin.Recovery())
	return r
}

// initializeComponents 初始化Router的各个组件
func (r *Router) initializeComponents() error {
	// 初始化缓存
	r.logger.Debug("开始初始化缓存组件...")
	if r.config.CacheConfig != nil {
		r.cache = cache.New[string, any](*r.config.CacheConfig)
		r.logger.Info("缓存组件初始化完成 (TTL: %v, 清理间隔: %v)",
			r.config.CacheConfig.TTL, r.config.CacheConfig.CleanupInterval)
	} else {
		// 默认缓存 (2小时过期，10分钟清理)
		r.cache = cache.NewCache[string, any](time.Hour*2, time.Minute*10)
		r.logger.Info("缓存组件初始化完成 (TTL: 2h0m0s, 清理间隔: 10m0s) - 使用默认配置")
	}

	// 初始化错误处理器
	if r.config.ErrorHandlerEnabled {
		r.logger.Debug("开始初始化错误处理器...")
		handler := &DefaultErrorHandler{
			SensitiveFilter: r.config.SensitiveFilter,
		}
		r.errorHandler = handler
		filterStatus := "禁用"
		if r.config.SensitiveFilter {
			filterStatus = "启用"
		}
		r.logger.Info("错误处理器初始化完成 (敏感信息过滤: %s)", filterStatus)
	} else {
		r.logger.Debug("错误处理器未启用")
	}

	// 初始化JWT适配器
	if r.config.SecurityConfig != nil && len(r.config.SecurityConfig.JWTSecretKey) > 0 {
		r.logger.Debug("开始初始化JWT组件...")

		// 验证安全配置
		if err := r.config.SecurityConfig.Validate(); err != nil {
			r.logger.Error("安全配置验证失败: %v", err)
			return err
		}

		adapter, err := r.config.SecurityConfig.BuildJWTAdapter()
		if err != nil {
			r.logger.Error("JWT适配器初始化失败: %v", err)
			r.logger.Error("建议检查JWT密钥配置和算法设置")
			return err
		}
		r.jwtAdapter = adapter
		r.logger.Info("JWT组件初始化完成 (过期时间: %v)", r.config.SecurityConfig.JWTExpiration)
	} else {
		r.logger.Debug("JWT组件未启用")
	}

	// 初始化SSE中心
	if r.config.SSEEnabled {
		r.logger.Debug("开始初始化SSE组件...")
		config := r.config.SSEConfig
		if config == nil {
			config = &sse.Config{
				HistorySize:  50,
				PingInterval: 10 * time.Second,
				PingTimeout:  30 * time.Second,
			}
			r.logger.Debug("使用默认SSE配置")
		}
		r.sseHub = sse.NewHub(config)
		r.logger.Info("SSE组件初始化完成 (历史大小: %d, Ping间隔: %v, Ping超时: %v)",
			config.HistorySize, config.PingInterval, config.PingTimeout)
	} else {
		r.logger.Debug("SSE组件未启用")
	}

	return nil
}

// setupMiddleware 设置增强中间件
func (r *Router) setupMiddleware() {
	// 添加增强Context中间件
	r.UseGin(r.contextMiddleware())

	// 添加安全头中间件
	if r.config.SecurityConfig != nil && r.config.SecurityConfig.SecurityHeadersEnabled {
		r.UseGin(r.securityHeadersMiddleware())
		r.logger.Info("安全HTTP头中间件已启用")
	}

	// 添加错误处理中间件
	if r.config.ErrorHandlerEnabled {
		r.UseGin(r.errorHandlingMiddleware())
	}

	// 添加限流中间件
	if r.config.SecurityConfig != nil && r.config.SecurityConfig.RateLimitEnabled {
		r.UseGin(r.rateLimitMiddleware())
		r.logger.Info("限流中间件已启用 (每分钟%d请求)", r.config.SecurityConfig.RateLimitRequestsPerMinute)
	}

	// 添加缓存注入中间件
	r.Use(r.injectCacheMiddleware())
}

// contextMiddleware 增强Context中间件
func (r *Router) contextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := newContext(c)

		// 读锁保护组件引用，避免与动态变更（如 NewSSEHub）竞争
		r.mu.RLock()
		cache := r.cache
		errHandler := r.errorHandler
		jwtAdapter := r.jwtAdapter
		sseHub := r.sseHub
		r.mu.RUnlock()

		if cache != nil {
			ctx.SetCache(cache)
		}
		if errHandler != nil {
			ctx.SetErrorHandler(errHandler)
		}
		if jwtAdapter != nil {
			ctx.SetJWTAdapter(jwtAdapter)
		}
		if sseHub != nil {
			ctx.SetSSEHub(sseHub)
		}

		// 将增强的Context存储到gin.Context中
		c.Set("enhanced_context", ctx)

		// 调用后续处理函数
		c.Next()

		// 请求处理完成后，释放Context回对象池
		releaseContext(ctx)
	}
}

// errorHandlingMiddleware 错误处理中间件
func (r *Router) errorHandlingMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if ctx, exists := c.Get("enhanced_context"); exists {
			if enhancedCtx, ok := ctx.(*Context); ok {
				switch v := recovered.(type) {
				case string:
					enhancedCtx.ErrorWithCode(errors.New(errors.ErrCodeInternal).WithMessage(v))
				case error:
					enhancedCtx.ErrorWithCode(v)
				default:
					enhancedCtx.ErrorWithCode(errors.New(errors.ErrCodeInternal).WithMessage("Internal server error"))
				}
			}
		}

		// 如果之前尚未写出响应，则返回 500；否则只终止后续处理中避免重复写
		if !c.Writer.Written() {
			c.AbortWithStatus(http.StatusInternalServerError)
		} else {
			c.Abort()
		}
	})
}

// securityHeadersMiddleware 安全HTTP头中间件
func (r *Router) securityHeadersMiddleware() gin.HandlerFunc {
	config := DefaultSecurityHeadersConfig()

	return func(c *gin.Context) {
		// 防止点击劫持攻击
		c.Header("X-Frame-Options", config.XFrameOptions)

		// 防止MIME类型嗅探攻击
		if config.XContentTypeOptions {
			c.Header("X-Content-Type-Options", "nosniff")
		}

		// XSS保护
		if config.XXSSProtection != "" {
			c.Header("X-XSS-Protection", config.XXSSProtection)
		}

		// 强制HTTPS
		if config.StrictTransportSecurity != "" {
			c.Header("Strict-Transport-Security", config.StrictTransportSecurity)
		}

		// 减少信息泄露
		if config.HideServerInfo {
			c.Header("X-Powered-By", "")
			c.Header("Server", "")
		}

		// 引用者策略
		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		// 权限策略
		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
		}

		// 内容安全策略
		if c.GetHeader("Content-Security-Policy") == "" && config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		c.Next()
	}
}

// rateLimitMiddleware 限流中间件
func (r *Router) rateLimitMiddleware() gin.HandlerFunc {
	config := RateLimitConfig{
		RequestsPerWindow: r.config.SecurityConfig.RateLimitRequestsPerMinute,
		WindowSize:        time.Minute,
	}
	limiter := NewRateLimiter(config)

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		allowed, reset := limiter.Allow(clientIP)
		requests, nextReset := limiter.Stats(clientIP)
		remaining := config.RequestsPerWindow - requests
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(config.RequestsPerWindow))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(nextReset.Unix(), 10))
		if !allowed {
			retry := int(time.Until(reset).Seconds())
			if retry < 0 {
				retry = 0
			}
			c.Header("Retry-After", strconv.Itoa(retry))
			c.JSON(http.StatusTooManyRequests, H{
				"error":       "rate limit exceeded",
				"message":     "请求过于频繁，请稍后再试",
				"retry_after": retry,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// DefaultErrorHandler 默认错误处理器
type DefaultErrorHandler struct {
	SensitiveFilter bool
}

// HandleError 处理错误
func (h *DefaultErrorHandler) HandleError(ctx types.RequestContext, err error) {
	if appErr, ok := err.(*errors.Error); ok {
		// 如果启用敏感信息过滤
		if h.SensitiveFilter {
			appErr = h.filterSensitiveInfo(appErr)
		}

		ctx.JSON(appErr.GetStatus(), types.Response{
			Code: appErr.Code,
			Msg:  appErr.Message,
			Data: appErr.Data,
		})
	} else {
		ctx.JSON(500, types.Response{
			Code: errors.ErrCodeInternal,
			Msg:  "Internal server error",
		})
	}
}

// filterSensitiveInfo 过滤敏感信息
func (h *DefaultErrorHandler) filterSensitiveInfo(err *errors.Error) *errors.Error {
	// 对于内部错误，不显示详细信息
	if err.Code >= errors.ErrCodeInternal {
		return errors.New(err.Code).WithMessage("Internal server error")
	}
	return err
}

// GetJWTAdapter 获取JWT适配器
func (r *Router) GetJWTAdapter() *JWTAdapter {
	return r.jwtAdapter
}

// GetErrorHandler 获取错误处理器
func (r *Router) GetErrorHandler() errors.ErrorHandler {
	return r.errorHandler
}

// StartSSE 启动SSE服务
func (r *Router) StartSSE() error {
	// 如果SSE Hub不存在，先创建一个默认的
	if r.sseHub == nil {
		r.sseHub = sse.NewHub(nil) // 使用默认配置
	}

	// 在后台启动SSE服务
	go r.sseHub.Run(context.Background())

	return nil
}

// JWTMiddleware 创建JWT中间件（手动添加到需要认证的路由）
func (r *Router) JWTMiddleware() gin.HandlerFunc {
	if r.jwtAdapter == nil {
		panic("JWT未启用或未正确配置")
	}

	return func(c *gin.Context) {
		if ctx, exists := c.Get("enhanced_context"); exists {
			if enhancedCtx, ok := ctx.(*Context); ok {
				if _, valid := enhancedCtx.RequireJWT(); !valid {
					return
				}
			}
		}
		c.Next()
	}
}

// WrapHandler 包装处理函数，自动转换Context类型
func WrapHandler(handler HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ctx, exists := c.Get("enhanced_context"); exists {
			if enhancedCtx, ok := ctx.(*Context); ok {
				handler(enhancedCtx)
			}
		} else {
			// 如果没有增强Context，创建一个临时的
			ctx := newContext(c)

			// 确保临时Context在函数结束时被释放回对象池
			defer releaseContext(ctx)

			handler(ctx)
		}
	}
}

// GetCache 获取路由器的全局缓存实例
func (r *Router) GetCache() *cache.Cache[string, any] {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cache
}

// injectCacheMiddleware 注入缓存到请求上下文的中间件
func (r *Router) injectCacheMiddleware() HandlerFunc {
	return func(c *Context) {
		r.mu.RLock()
		cache := r.cache
		r.mu.RUnlock()
		if cache != nil {
			// 设置上下文缓存为路由器的全局缓存
			c.setGlobalCache(cache)
		}
		c.Next()
	}
}

// RunTLS 使用TLS运行服务器，支持优雅停机
func (r *Router) RunTLS(addr, certFile, keyFile string) error {
	config := DefaultServerConfig()
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		config.Host = parts[0]
		config.Port = parts[1]
	} else {
		config.Port = addr
	}
	config.CertFile = certFile
	config.KeyFile = keyFile

	return r.RunWithGracefulShutdown(config)
}

// 服务器实例，用于停机和重启
type serverInstance struct {
	server *http.Server
	config ServerConfig
	active bool
}

// 全局服务器实例
var (
	activeServer     *serverInstance
	activeServerLock sync.Mutex
)

// RunWithGracefulShutdown 启动服务器并支持优雅停机
func (r *Router) RunWithGracefulShutdown(config ServerConfig) error {
	// 创建一个基于信号的上下文
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return r.RunWithContext(ctx, config)
}

// RunWithContextString 使用给定的上下文和地址字符串启动服务器
func (r *Router) RunWithContextString(ctx context.Context, addr string) error {
	config := DefaultServerConfig()
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		config.Host = parts[0]
		config.Port = parts[1]
	} else {
		config.Port = addr
	}

	return r.RunWithContext(ctx, config)
}

// RunWithContext 使用指定的上下文启动服务器
// 当上下文被取消时，服务器将优雅地关闭
func (r *Router) RunWithContext(ctx context.Context, config ...ServerConfig) error {
	// 应用配置，如果没有提供则使用默认配置
	serverConfig := DefaultServerConfig()
	if len(config) > 0 {
		serverConfig = config[0]
	}

	addr := serverConfig.Host + ":" + serverConfig.Port

	// 设置TLS配置
	var tlsConfig *tls.Config
	if serverConfig.CertFile != "" && serverConfig.KeyFile != "" {
		r.logger.Debug("加载TLS证书: %s, %s", serverConfig.CertFile, serverConfig.KeyFile)
		cert, err := tls.LoadX509KeyPair(serverConfig.CertFile, serverConfig.KeyFile)
		if err != nil {
			r.logger.Error("TLS证书加载失败: %v", err)
			return err
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		if serverConfig.EnableHTTP2 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
			r.logger.Debug("启用HTTP/2支持")
		}

		r.logger.Info("TLS配置加载成功 (最小版本: TLS 1.2)")
	}

	// 创建HTTP服务器
	server := &http.Server{
		Addr:           addr,
		Handler:        r.engine,
		ReadTimeout:    serverConfig.ReadTimeout,
		WriteTimeout:   serverConfig.WriteTimeout,
		MaxHeaderBytes: serverConfig.MaxHeaderBytes,
		TLSConfig:      tlsConfig,
	}

	// 保存当前服务器实例
	activeServerLock.Lock()
	activeServer = &serverInstance{
		server: server,
		config: serverConfig,
		active: true,
	}
	activeServerLock.Unlock()

	// 创建一个通道，用于接收来自关闭处理程序的信号
	idleConnsClosed := make(chan struct{})

	// 在单独的goroutine中监听上下文取消事件
	go func() {
		// 等待上下文取消信号
		<-ctx.Done()

		r.logger.Info("收到停机信号，开始优雅停机...")

		// 首先关闭Router资源（SSE Hub、缓存等）
		if err := r.Close(); err != nil {
			r.logger.Error("关闭Router资源时出错: %v", err)
		} else {
			r.logger.Debug("Router资源已成功关闭")
		}

		// 使用超时上下文创建关闭超时
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serverConfig.GracefulTimeout)
		defer cancel()

		r.logger.Debug("开始关闭HTTP服务器 (超时: %v)", serverConfig.GracefulTimeout)

		// 关闭服务器，不再接受新的连接
		if err := server.Shutdown(shutdownCtx); err != nil {
			r.logger.Error("服务器关闭出错: %v", err)
		} else {
			r.logger.Debug("HTTP服务器已停止接受新连接")
		}

		// 更新服务器状态
		activeServerLock.Lock()
		if activeServer != nil && activeServer.server == server {
			activeServer.active = false
		}
		activeServerLock.Unlock()

		r.logger.Info("服务器已成功关闭")

		// 发送关闭信号
		close(idleConnsClosed)
	}()

	// 输出服务器启动信息
	if tlsConfig != nil {
		r.logger.Info("服务器正在启动 (HTTPS), 监听地址: %s", addr)
	} else {
		r.logger.Info("服务器正在启动 (HTTP), 监听地址: %s", addr)
	}

	// 在调试模式下输出详细配置信息
	r.logger.Debug("服务器配置 - 读取超时: %v, 写入超时: %v, 最大头部字节: %d",
		serverConfig.ReadTimeout, serverConfig.WriteTimeout, serverConfig.MaxHeaderBytes)

	// 启动服务器
	var err error
	if tlsConfig != nil {
		err = server.ListenAndServeTLS("", "") // 证书已在TLS配置中设置
	} else {
		err = server.ListenAndServe()
	}

	// 如果服务器因为Shutdown而关闭，err将是ErrServerClosed
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	// 等待关闭信号
	<-idleConnsClosed

	return nil
}

// GracefulShutdown 优雅地关闭服务器
func (r *Router) GracefulShutdown(timeout time.Duration) error {
	activeServerLock.Lock()
	defer activeServerLock.Unlock()

	if activeServer == nil || !activeServer.active {
		r.logger.Warn("尝试关闭服务器，但没有活跃的服务器实例")
		return fmt.Errorf("没有活跃的服务器实例")
	}

	r.logger.Info("开始优雅停机流程... (超时: %v)", timeout)

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 获取当前服务器的引用
	server := activeServer.server

	// 关闭服务器，不再接受新的连接，但会等待现有连接处理完成
	if err := server.Shutdown(ctx); err != nil {
		r.logger.Error("服务器关闭失败: %v", err)
		return fmt.Errorf("服务器关闭失败: %v", err)
	}

	// 标记服务器为非活跃
	activeServer.active = false

	r.logger.Info("服务器已成功关闭")
	return nil
}

// Restart 重启服务器
func (r *Router) Restart() error {
	activeServerLock.Lock()
	if activeServer == nil {
		activeServerLock.Unlock()
		r.logger.Warn("尝试重启服务器，但没有可重启的服务器实例")
		return fmt.Errorf("没有可重启的服务器实例")
	}

	// 获取当前配置
	config := activeServer.config
	activeServerLock.Unlock()

	r.logger.Info("开始重启服务器...")

	// 优雅关闭当前服务器
	if err := r.GracefulShutdown(config.GracefulTimeout); err != nil {
		r.logger.Error("重启时关闭服务器失败: %v", err)
		return fmt.Errorf("重启时关闭服务器失败: %v", err)
	}

	r.logger.Debug("旧服务器已关闭，准备启动新服务器")

	// 启动新的服务器
	go func() {
		if err := r.RunWithGracefulShutdown(config); err != nil && err != http.ErrServerClosed {
			r.logger.Error("重启服务器失败: %v", err)
		}
	}()

	// 等待一小段时间确保服务器启动
	time.Sleep(500 * time.Millisecond)

	r.logger.Info("服务器已重启")
	return nil
}

// IsRunning 检查服务器是否正在运行
func (r *Router) IsRunning() bool {
	activeServerLock.Lock()
	defer activeServerLock.Unlock()
	return activeServer != nil && activeServer.active
}
