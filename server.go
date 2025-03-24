package gin

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/darkit/gin/cache"
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

// DefaultServerConfig 返回默认服务器配置
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Host:            "",
		Port:            "8080",
		ReadTimeout:     time.Second * 60,
		WriteTimeout:    time.Second * 60,
		MaxHeaderBytes:  1 << 20, // 1MB
		EnableHTTP2:     true,
		GracefulTimeout: time.Second * 5,
	}
}

type H map[string]any

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

// New 创建新的路由管理器
func New() *Router {
	r := &Router{
		engine: gin.New(),
		groups: make(map[string]*RouterGroup),
	}

	// 初始化默认缓存 (2小时过期，10分钟清理)
	r.cache = cache.NewCache[string, any](time.Hour*2, time.Minute*10)

	// 添加缓存注入中间件
	r.Use(r.injectCacheMiddleware())

	return r
}

// Default 创建默认的路由管理器（包含 Logger、Recovery 和缓存中间件）
func Default() *Router {
	r := New() // 已包含缓存初始化

	// 包装 gin 的默认中间件
	r.UseGin(gin.Logger(), gin.Recovery())
	return r
}

// GetCache 获取路由器的全局缓存实例
func (r *Router) GetCache() *cache.Cache[string, any] {
	return r.cache
}

// SetCacheConfig 配置路由器的缓存
func (r *Router) SetCacheConfig(defaultExpiration, cleanupInterval time.Duration) {
	// 如果已有缓存，先关闭它
	if r.cache != nil {
		r.cache.Close()
	}

	// 创建新缓存
	r.cache = cache.NewCache[string, any](defaultExpiration, cleanupInterval)
}

// EnablePersistCache 开启持久化缓存
func (r *Router) EnablePersistCache(persistPath string, autoPersistInterval time.Duration) error {
	if r.cache == nil {
		return fmt.Errorf("缓存未初始化")
	}

	r.cache = r.cache.WithPersistence(persistPath, autoPersistInterval)
	r.cache.EnableAutoPersist()
	return nil
}

// injectCacheMiddleware 注入缓存到请求上下文的中间件
func (r *Router) injectCacheMiddleware() HandlerFunc {
	return func(c *Context) {
		if r.cache != nil {
			// 设置上下文缓存为路由器的全局缓存
			c.setGlobalCache(r.cache)
		}
		c.Next()
	}
}

// RunWithConfig 使用配置运行服务器
func (r *Router) RunWithConfig(config ServerConfig) error {
	addr := config.Host + ":" + config.Port

	// 设置TLS配置
	var tlsConfig *tls.Config
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return err
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		if config.EnableHTTP2 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		}
	}

	server := &http.Server{
		Addr:           addr,
		Handler:        r.engine,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
		TLSConfig:      tlsConfig,
	}

	if tlsConfig != nil {
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
}

// RunTLS 使用TLS运行服务器
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

	return r.RunWithConfig(config)
}
