package gin

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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
	return &Router{
		engine: gin.New(),
		groups: make(map[string]*RouterGroup),
	}
}

// Default 创建默认的路由管理器（包含 Logger 和 Recovery 中间件）
func Default() *Router {
	r := New()
	// 包装 gin 的默认中间件
	r.UseGin(gin.Logger(), gin.Recovery())
	return r
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

	// 启动服务器
	log.Printf("Server is running on %s\n", addr)

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
