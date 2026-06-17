// Package gin 提供对上游 gin 公开面的兼容导出。
package gin

import (
	"context"
	"io"
	"net/http"
	"sync"

	original "github.com/gin-gonic/gin"
)

// ---- 基础类型与路由接口 ----
type (
	Accounts           = original.Accounts
	ErrorType          = original.ErrorType
	Error              = original.Error
	H                  = original.H
	Param              = original.Param
	Params             = original.Params
	ResponseWriter     = original.ResponseWriter
	Negotiate          = original.Negotiate
	ContextKeyType     = original.ContextKeyType
	OnlyFilesFS        = original.OnlyFilesFS
	RouteInfo          = original.RouteInfo
	RoutesInfo         = original.RoutesInfo
	LogFormatter       = original.LogFormatter
	LogFormatterParams = original.LogFormatterParams
)

// RecoveryFunc 与上游保持同名，但绑定本项目的增强 Context。
type RecoveryFunc func(*Context, any)

// Skipper 与上游保持同名，但绑定本项目的增强 Context。
type Skipper func(*Context) bool

// LoggerConfig 与上游保持相同字段形状，但 Skip 绑定增强 Context。
type LoggerConfig struct {
	Formatter       LogFormatter
	Output          io.Writer
	SkipPaths       []string
	SkipQueryString bool
	Skip            Skipper
}

// HandlersChain 定义处理器链。
type HandlersChain []HandlerFunc

// Last 返回链中的最后一个处理器。
func (c HandlersChain) Last() HandlerFunc {
	if n := len(c); n > 0 {
		return c[n-1]
	}
	return nil
}

// RouterGroup 兼容暴露上游同名类型；在本项目中由增强 Router 承担职责。
type RouterGroup = Router

// IRoutes 定义与上游一致的路由注册接口。
type IRoutes interface {
	Use(...HandlerFunc) IRoutes

	Handle(string, string, ...HandlerFunc) IRoutes
	Any(string, ...HandlerFunc) IRoutes
	GET(string, ...HandlerFunc) IRoutes
	POST(string, ...HandlerFunc) IRoutes
	DELETE(string, ...HandlerFunc) IRoutes
	PATCH(string, ...HandlerFunc) IRoutes
	PUT(string, ...HandlerFunc) IRoutes
	OPTIONS(string, ...HandlerFunc) IRoutes
	HEAD(string, ...HandlerFunc) IRoutes
	Match([]string, string, ...HandlerFunc) IRoutes

	StaticFile(string, string) IRoutes
	StaticFileFS(string, string, http.FileSystem) IRoutes
	Static(string, string) IRoutes
	StaticFS(string, http.FileSystem) IRoutes
}

// IRouter 定义与上游一致的路由分组接口。
type IRouter interface {
	IRoutes
	Group(string, ...HandlerFunc) *RouterGroup
}

// GinHandlerFunc 原始 gin 处理器类型别名，仅在显式需要原始类型时使用。
type GinHandlerFunc = original.HandlerFunc

// GinContext 原始 gin 请求上下文类型别名，仅在兼容层显式需要原始上下文时使用。
type GinContext = original.Context

// GinEngine 原始 gin 引擎类型别名，仅在兼容层显式需要原始引擎时使用。
type GinEngine = original.Engine

// HTTPMiddleware 标准 http 中间件类型（Chi 风格）。
type HTTPMiddleware = func(http.Handler) http.Handler

// ---- 模式与平台常量 ----
const (
	EnvGinMode = original.EnvGinMode

	DebugMode   = original.DebugMode
	ReleaseMode = original.ReleaseMode
	TestMode    = original.TestMode

	PlatformGoogleAppEngine = original.PlatformGoogleAppEngine
	PlatformCloudflare      = original.PlatformCloudflare
	PlatformFlyIO           = original.PlatformFlyIO
)

// ---- MIME 常量 ----
const (
	MIMEJSON              = original.MIMEJSON
	MIMEHTML              = original.MIMEHTML
	MIMEXML               = original.MIMEXML
	MIMEXML2              = original.MIMEXML2
	MIMEPlain             = original.MIMEPlain
	MIMEPOSTForm          = original.MIMEPOSTForm
	MIMEMultipartPOSTForm = original.MIMEMultipartPOSTForm
	MIMEYAML              = original.MIMEYAML
	MIMEYAML2             = original.MIMEYAML2
	MIMETOML              = original.MIMETOML
	MIMEPROTOBUF          = original.MIMEPROTOBUF
	MIMEBSON              = original.MIMEBSON
)

// ---- 其它常量 ----
const (
	AuthUserKey      = original.AuthUserKey
	AuthProxyUserKey = original.AuthProxyUserKey

	BindKey      = original.BindKey
	BodyBytesKey = original.BodyBytesKey
	ContextKey   = original.ContextKey

	Version = original.Version
)

const (
	ErrorTypeBind    = original.ErrorTypeBind
	ErrorTypeRender  = original.ErrorTypeRender
	ErrorTypePrivate = original.ErrorTypePrivate
	ErrorTypePublic  = original.ErrorTypePublic
	ErrorTypeAny     = original.ErrorTypeAny
)

const (
	ContextRequestKey = original.ContextRequestKey
)

// ---- 全局变量 ----
var (
	DebugPrintRouteFunc = original.DebugPrintRouteFunc
	DebugPrintFunc      = original.DebugPrintFunc

	DefaultWriter      = original.DefaultWriter
	DefaultErrorWriter = original.DefaultErrorWriter

	ginGlobalsMu sync.Mutex
)

func syncGinGlobalsLocked() {
	original.DebugPrintRouteFunc = DebugPrintRouteFunc
	original.DebugPrintFunc = DebugPrintFunc
	original.DefaultWriter = DefaultWriter
	original.DefaultErrorWriter = DefaultErrorWriter
}

func withGinGlobals(fn func() original.HandlerFunc) original.HandlerFunc {
	ginGlobalsMu.Lock()
	defer ginGlobalsMu.Unlock()
	syncGinGlobalsLocked()
	return fn()
}

// Bind 返回绑定中间件。
func Bind(val any) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.Bind(val) }))
}

// WrapF 将标准库 http.HandlerFunc 包装为本项目 HandlerFunc。
func WrapF(f http.HandlerFunc) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.WrapF(f) }))
}

// WrapH 将标准库 http.Handler 包装为本项目 HandlerFunc。
func WrapH(h http.Handler) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.WrapH(h) }))
}

// BasicAuthForRealm 返回 BasicAuth 中间件。
func BasicAuthForRealm(accounts Accounts, realm string) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
		return original.BasicAuthForRealm(accounts, realm)
	}))
}

// BasicAuth 返回 BasicAuth 中间件。
func BasicAuth(accounts Accounts) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.BasicAuth(accounts) }))
}

// BasicAuthForProxy 返回代理场景的 BasicAuth 中间件。
func BasicAuthForProxy(accounts Accounts, realm string) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
		return original.BasicAuthForProxy(accounts, realm)
	}))
}

// SetMode 设置运行模式。
func SetMode(value string) {
	original.SetMode(value)
}

// Mode 返回当前运行模式。
func Mode() string {
	return original.Mode()
}

// IsDebugging 返回是否处于调试模式。
func IsDebugging() bool {
	return original.IsDebugging()
}

// DisableBindValidation 禁用绑定校验。
func DisableBindValidation() {
	original.DisableBindValidation()
}

// EnableJsonDecoderUseNumber 启用 decoder.UseNumber。
func EnableJsonDecoderUseNumber() {
	original.EnableJsonDecoderUseNumber()
}

// EnableJsonDecoderDisallowUnknownFields 启用未知字段校验。
func EnableJsonDecoderDisallowUnknownFields() {
	original.EnableJsonDecoderDisallowUnknownFields()
}

// DisableConsoleColor 禁用控制台颜色。
func DisableConsoleColor() {
	original.DisableConsoleColor()
}

// ForceConsoleColor 强制控制台颜色输出。
func ForceConsoleColor() {
	original.ForceConsoleColor()
}

// Logger 返回默认日志中间件。
func Logger() HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.Logger() }))
}

// LoggerWithFormatter 返回自定义格式的日志中间件。
func LoggerWithFormatter(f LogFormatter) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.LoggerWithFormatter(f) }))
}

// LoggerWithWriter 返回写入指定目标的日志中间件。
func LoggerWithWriter(out io.Writer, notlogged ...string) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
		return original.LoggerWithWriter(out, notlogged...)
	}))
}

// LoggerWithConfig 返回自定义配置的日志中间件。
func LoggerWithConfig(conf LoggerConfig) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
		return original.LoggerWithConfig(toOriginalLoggerConfig(conf))
	}))
}

// ErrorLogger 返回任意错误类型的错误日志中间件。
func ErrorLogger() HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.ErrorLogger() }))
}

// ErrorLoggerT 返回指定错误类型的错误日志中间件。
func ErrorLoggerT(typ ErrorType) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.ErrorLoggerT(typ) }))
}

// Recovery 返回默认恢复中间件。
func Recovery() HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc { return original.Recovery() }))
}

// CustomRecovery 返回自定义恢复中间件。
func CustomRecovery(handle RecoveryFunc) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
		return original.CustomRecovery(wrapOriginalRecoveryFunc(handle))
	}))
}

// RecoveryWithWriter 返回写入指定输出的恢复中间件。
func RecoveryWithWriter(out io.Writer, recovery ...RecoveryFunc) HandlerFunc {
	if len(recovery) > 0 {
		return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
			return original.RecoveryWithWriter(out, wrapOriginalRecoveryFunc(recovery[0]))
		}))
	}
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
		return original.RecoveryWithWriter(out)
	}))
}

// CustomRecoveryWithWriter 返回自定义恢复中间件。
func CustomRecoveryWithWriter(out io.Writer, handle RecoveryFunc) HandlerFunc {
	return WrapMiddleware(withGinGlobals(func() original.HandlerFunc {
		return original.CustomRecoveryWithWriter(out, wrapOriginalRecoveryFunc(handle))
	}))
}

// Dir 返回静态文件系统。
func Dir(root string, listDirectory bool) http.FileSystem {
	return original.Dir(root, listDirectory)
}

// CreateTestContext 创建测试上下文与测试引擎。
func CreateTestContext(w http.ResponseWriter) (c *Context, r *Engine) {
	r = New()
	return CreateTestContextOnly(w, r), r
}

// CreateTestContextOnly 在给定引擎上创建测试上下文。
func CreateTestContextOnly(w http.ResponseWriter, r *Engine) (c *Context) {
	if r == nil {
		r = New()
	}
	raw := original.CreateTestContextOnly(w, r.Engine)
	return r.acquireContext(raw)
}

func wrapOriginalRecoveryFunc(fn RecoveryFunc) original.RecoveryFunc {
	if fn == nil {
		return nil
	}
	return func(c *original.Context, err any) {
		requestContext := context.Background()
		if c != nil && c.Request != nil {
			requestContext = c.Request.Context()
		}
		fn(&Context{
			Context:        c,
			requestContext: requestContext,
		}, err)
	}
}

func toOriginalLoggerConfig(conf LoggerConfig) original.LoggerConfig {
	result := original.LoggerConfig{
		Formatter:       conf.Formatter,
		Output:          conf.Output,
		SkipPaths:       conf.SkipPaths,
		SkipQueryString: conf.SkipQueryString,
	}
	if conf.Skip != nil {
		result.Skip = func(c *original.Context) bool {
			requestContext := context.Background()
			if c != nil && c.Request != nil {
				requestContext = c.Request.Context()
			}
			return conf.Skip(&Context{
				Context:        c,
				requestContext: requestContext,
			})
		}
	}
	return result
}
