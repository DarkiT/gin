// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"time"

	"github.com/darkit/gin/auth"
	"github.com/darkit/gin/pkg/cache"
	"github.com/darkit/gin/pkg/logger"
	"github.com/darkit/gin/pkg/mail"
	"github.com/darkit/gin/pkg/sms"
	"github.com/darkit/gin/pkg/swagger"
)

// OptionFunc 定义 Engine 配置选项函数。
type OptionFunc func(*Engine)

// WithAddr 设置服务监听地址。
func WithAddr(addr string) OptionFunc {
	return func(e *Engine) {
		e.config.Addr = addr
	}
}

// WithReadTimeout 设置读超时。
func WithReadTimeout(d time.Duration) OptionFunc {
	return func(e *Engine) {
		e.config.ReadTimeout = d
	}
}

// WithWriteTimeout 设置写超时。
func WithWriteTimeout(d time.Duration) OptionFunc {
	return func(e *Engine) {
		e.config.WriteTimeout = d
	}
}

// WithTrustedProxies 设置受信任的代理列表。
func WithTrustedProxies(proxies []string) OptionFunc {
	return func(e *Engine) {
		if err := e.Engine.SetTrustedProxies(proxies); err != nil {
			panic(err)
		}
	}
}

// WithGracefulShutdown 设置优雅关闭超时。
func WithGracefulShutdown(timeout time.Duration) OptionFunc {
	return func(e *Engine) {
		e.lifecycle.SetShutdownTimeout(timeout)
	}
}

// WithLogger 设置日志器。
func WithLogger(l logger.Logger) OptionFunc {
	return func(e *Engine) {
		e.logger = l
	}
}

// WithCache 设置缓存实现。
func WithCache(c cache.Cache) OptionFunc {
	return func(e *Engine) {
		e.cache = c
	}
}

// Development 应用开发环境的默认配置。
func Development() OptionFunc {
	return func(e *Engine) {
		WithReadTimeout(30 * time.Second)(e)
	}
}

// Production 应用生产环境的默认配置。
func Production() OptionFunc {
	return func(e *Engine) {
		WithReadTimeout(10 * time.Second)(e)
		WithWriteTimeout(10 * time.Second)(e)
		WithGracefulShutdown(30 * time.Second)(e)
	}
}

// WithUploadDir 设置上传目录。
func WithUploadDir(dir string) OptionFunc {
	return func(e *Engine) {
		e.uploadConfig.UploadDir = dir
	}
}

// WithMaxFileSize 设置单文件大小上限。
func WithMaxFileSize(size int64) OptionFunc {
	return func(e *Engine) {
		e.uploadConfig.MaxFileSize = size
	}
}

// WithMaxMultipartMemory 设置 multipart 内存阈值。
func WithMaxMultipartMemory(size int64) OptionFunc {
	return func(e *Engine) {
		e.uploadConfig.MaxMultipartMemory = size
		if size > 0 {
			e.MaxMultipartMemory = size
		}
	}
}

// WithAllowedExts 设置允许的文件扩展名。
func WithAllowedExts(exts ...string) OptionFunc {
	return func(e *Engine) {
		e.uploadConfig.AllowedExts = exts
	}
}

// WithUploadConfig 设置完整上传配置。
func WithUploadConfig(cfg *UploadConfig) OptionFunc {
	return func(e *Engine) {
		if cfg == nil {
			return
		}
		e.uploadConfig = cfg
		if cfg.MaxMultipartMemory > 0 {
			e.MaxMultipartMemory = cfg.MaxMultipartMemory
		}
	}
}

// WithMail 设置邮件配置并初始化默认发送器。
func WithMail(cfg mail.MailConfig) OptionFunc {
	return func(e *Engine) {
		e.mailConfig = cfg
		if err := mail.InitDefaultMailer(cfg); err != nil {
			panic(err)
		}
	}
}

// WithSMS 设置短信配置并初始化默认提供者。
func WithSMS(cfg sms.SMSConfig) OptionFunc {
	return func(e *Engine) {
		e.smsConfig = cfg
		if err := sms.InitDefaultProvider(cfg); err != nil {
			panic(err)
		}
	}
}

// EnableSwagger 启用 Swagger 文档生成并注册路由。
func EnableSwagger(cfg swagger.SwaggerConfig) OptionFunc {
	return func(e *Engine) {
		e.swaggerEnabled = true
		e.swaggerConfig = &cfg
		// 注册 Swagger 路由
		e.registerSwaggerRoutes()
	}
}

// WithAuth 配置认证授权模块并初始化管理器。
// 启用后可通过 c.Auth() 访问认证功能
//
// 使用示例:
//
//	e := gin.New(
//	    gin.WithAuth(auth.AuthConfig{
//	        Secret:     "your-jwt-secret",
//	        Expiry:     24 * time.Hour,
//	        TokenStyle: auth.TokenStyleJWT,
//	    }),
//	)
func WithAuth(cfg auth.AuthConfig) OptionFunc {
	return func(e *Engine) {
		// 验证配置
		if err := cfg.Validate(); err != nil {
			panic(err)
		}

		// 保存配置
		e.authConfig = &cfg

		// 创建存储
		storage := cfg.Storage
		if storage == nil {
			// 默认使用内存存储
			storage = auth.NewMemoryStorage()
		}

		// 创建认证管理器
		e.authManager = auth.NewManager(storage, &cfg)
	}
}
