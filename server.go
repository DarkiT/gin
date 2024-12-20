package gin

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"os"
)

const (
	EnvGinMode = "GIN_MODE"

	DebugMode   = "debug"
	ReleaseMode = "release"
	TestMode    = "test"
)

type H map[string]any

func init() {
	mode := os.Getenv(EnvGinMode)
	if mode == "" {
		mode = ReleaseMode
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

// New 创建一个新的 gin 实例以启动服务器。
func New() *gin.Engine {
	return gin.New()
}

// Default 返回一个带有 Logger 和 Recovery 中间件的 Engine 实例。
func Default() *gin.Engine {
	engine := New()
	engine.Use(gin.Logger(), gin.Recovery())
	return engine
}
