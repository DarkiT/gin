// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/darkit/gin/auth"
	"github.com/darkit/gin/pkg/cache"
	"github.com/darkit/gin/pkg/lifecycle"
	"github.com/darkit/gin/pkg/logger"
	"github.com/darkit/gin/pkg/mail"
	"github.com/darkit/gin/pkg/sms"
	"github.com/darkit/gin/pkg/swagger"
	"github.com/gin-gonic/gin"
)

// Config 定义服务运行参数。
type Config struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Engine 封装 gin.Engine 并聚合各类扩展能力。
type Engine struct {
	*gin.Engine
	config               *Config
	logger               logger.Logger
	cache                cache.Cache
	lifecycle            *lifecycle.Manager
	middleware           *middlewareRegistry
	uploadConfig         *UploadConfig
	mailConfig           mail.MailConfig
	smsConfig            sms.SMSConfig
	authManager          *auth.Manager          // 认证管理器
	authConfig           *auth.AuthConfig       // 认证配置
	regexRouter          *RegexRouter           // 正则路由器,通过 NoRoute 集成
	staticMounts         []*staticMount         // 受控静态资源挂载
	userNoRouteHandlers  []gin.HandlerFunc      // 用户自定义的 NoRoute 处理器
	userNoMethodHandlers []gin.HandlerFunc      // 用户自定义的 NoMethod 处理器
	swaggerEnabled       bool                   // 是否启用 Swagger
	swaggerConfig        *swagger.SwaggerConfig // Swagger 配置
	swaggerRoutes        []*SwaggerRouteInfo    // Swagger 路由信息
	contextPool          sync.Pool              // Context 对象池
}

// New 创建带默认配置的 Engine，可通过 opts 覆盖。
func New(opts ...OptionFunc) *Engine {
	base := gin.New()
	e := &Engine{
		Engine: base,
		config: &Config{
			Addr: ":8080",
		},
		logger:       logger.NewNoop(),
		cache:        cache.NewMemoryCache(),
		lifecycle:    lifecycle.NewManager(),
		middleware:   newMiddlewareRegistry(),
		uploadConfig: DefaultUploadConfig(),
		mailConfig:   mail.MailConfig{},
		smsConfig:    sms.SMSConfig{},
		contextPool: sync.Pool{
			New: func() any {
				return &Context{}
			},
		},
	}
	e.ContextWithFallback = true
	e.MaxMultipartMemory = e.uploadConfig.MaxMultipartMemory
	for _, opt := range opts {
		opt(e)
	}

	return e
}

// With 按顺序应用配置选项并返回当前引擎。
func (e *Engine) With(opts ...OptionFunc) *Engine {
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
}

func (e *Engine) acquireContext(c *gin.Context) *Context {
	requestCtx := context.Background()
	if c != nil && c.Request != nil {
		requestCtx = c.Request.Context()
	}

	return &Context{
		Context:        c,
		engine:         e,
		requestContext: requestCtx,
	}
}

func (e *Engine) releaseContext(_ *Context) {
	// 增强 Context 可能作为 context.Context 继续被数据库层持有，
	// 这里不再回收到对象池，避免请求结束后对象被复用导致数据竞争或 panic。
}

// Default 创建默认 Engine，并注册常用中间件。
func Default(opts ...OptionFunc) *Engine {
	e := New(opts...)
	e.Use(requestIDMiddleware(), Recovery(), Logger())
	return e
}

// Use 添加全局中间件，并返回 IRoutes 以保持与上游一致。
func (e *Engine) Use(handlers ...HandlerFunc) IRoutes {
	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		e.Engine.Use(wrapHandler(handler, e))
	}
	return e
}

// UseAny 接受任意可适配的中间件类型。
func (e *Engine) UseAny(handlers ...any) IRoutes {
	adapted := make([]HandlerFunc, 0, len(handlers))
	for _, h := range handlers {
		handler, ok := adaptMiddlewareToHandlerFunc(h)
		if !ok {
			panic(fmt.Sprintf("gin: unsupported middleware type: %T, expected HandlerFunc, gin.HandlerFunc, or func(http.Handler) http.Handler", h))
		}
		adapted = append(adapted, handler)
	}
	return e.Use(adapted...)
}

// Run 启动 HTTP 服务，addr 为空时使用默认地址。
func (e *Engine) Run(addr ...string) error {
	address := e.config.Addr
	if len(addr) > 0 {
		address = addr[0]
	}

	server := &http.Server{
		Addr:         address,
		Handler:      e.Engine,
		ReadTimeout:  e.config.ReadTimeout,
		WriteTimeout: e.config.WriteTimeout,
	}

	return e.lifecycle.Run(server, e.Engine)
}

// Shutdown 触发优雅关闭。
func (e *Engine) Shutdown(ctx context.Context) error {
	return e.lifecycle.Shutdown(ctx)
}

// OnStart 注册服务启动前回调。
func (e *Engine) OnStart(hooks ...lifecycle.Hook) *Engine {
	if e != nil && e.lifecycle != nil {
		e.lifecycle.OnStart(hooks...)
	}
	return e
}

// OnShutdown 注册服务关闭阶段回调。
func (e *Engine) OnShutdown(hooks ...lifecycle.Hook) *Engine {
	if e != nil && e.lifecycle != nil {
		e.lifecycle.OnShutdown(hooks...)
	}
	return e
}

// OnStopped 注册服务完全停止后的回调。
func (e *Engine) OnStopped(hooks ...lifecycle.Hook) *Engine {
	if e != nil && e.lifecycle != nil {
		e.lifecycle.OnStopped(hooks...)
	}
	return e
}

// Router 返回增强路由器。
func (e *Engine) Router() *Router {
	return newRouter(e)
}

// WithLogger 设置日志器并返回 Engine。
func (e *Engine) WithLogger(l logger.Logger) *Engine {
	e.logger = l
	return e
}

// WithCache 设置缓存实现并返回 Engine。
func (e *Engine) WithCache(c cache.Cache) *Engine {
	e.cache = c
	return e
}

func (e *Engine) wrapHandlers(handlers []HandlerFunc) gin.HandlersChain {
	return wrapHandlersChain(handlers, e)
}

// Handle 注册指定方法与路径的处理器。
func (e *Engine) Handle(method, path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return e
	}
	if IsRegexPattern(path) {
		e.RegexRouter().Handle(method, path, handlers...)
		return e
	}
	e.Engine.Handle(method, path, e.wrapHandlers(handlers)...)
	return e
}

// GET 注册 GET 路由。
func (e *Engine) GET(path string, handlers ...HandlerFunc) IRoutes {
	return e.Handle(http.MethodGet, path, handlers...)
}

// POST 注册 POST 路由。
func (e *Engine) POST(path string, handlers ...HandlerFunc) IRoutes {
	return e.Handle(http.MethodPost, path, handlers...)
}

// PUT 注册 PUT 路由。
func (e *Engine) PUT(path string, handlers ...HandlerFunc) IRoutes {
	return e.Handle(http.MethodPut, path, handlers...)
}

// PATCH 注册 PATCH 路由。
func (e *Engine) PATCH(path string, handlers ...HandlerFunc) IRoutes {
	return e.Handle(http.MethodPatch, path, handlers...)
}

// DELETE 注册 DELETE 路由。
func (e *Engine) DELETE(path string, handlers ...HandlerFunc) IRoutes {
	return e.Handle(http.MethodDelete, path, handlers...)
}

// HEAD 注册 HEAD 路由。
func (e *Engine) HEAD(path string, handlers ...HandlerFunc) IRoutes {
	return e.Handle(http.MethodHead, path, handlers...)
}

// OPTIONS 注册 OPTIONS 路由。
func (e *Engine) OPTIONS(path string, handlers ...HandlerFunc) IRoutes {
	return e.Handle(http.MethodOptions, path, handlers...)
}

// Any 注册所有 HTTP 方法的路由。
func (e *Engine) Any(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return e
	}
	if IsRegexPattern(path) {
		e.RegexRouter().Any(path, handlers...)
		return e
	}
	e.Engine.Any(path, e.wrapHandlers(handlers)...)
	return e
}

// Match 注册匹配指定多个 HTTP 方法的路由。
// 避免为相同处理器重复注册多个方法。
//
// 使用示例：
//
//	// 同时支持 GET 和 POST
//	e.Match([]string{"GET", "POST"}, "/user", handlers...)
func (e *Engine) Match(methods []string, relativePath string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return e
	}
	if IsRegexPattern(relativePath) {
		target := e.RegexRouter()
		for _, method := range methods {
			target.Handle(method, relativePath, handlers...)
		}
		return e
	}
	e.Engine.Match(methods, relativePath, e.wrapHandlers(handlers)...)
	return e
}

// Group 创建路由分组，path 为分组前缀。
func (e *Engine) Group(path string, handlers ...HandlerFunc) *RouterGroup {
	group := &Router{
		RouterGroup:      e.Engine.Group(path, e.wrapHandlers(handlers)...),
		engine:           e,
		regexMiddlewares: append([]HandlerFunc{}, handlers...),
	}
	return group
}

// RegexRouter 返回高级正则路由器（懒加载）。
// 正则路由器通过 NoRoute 与 Gin 集成，作为标准路由的 fallback。
//
// 默认情况下，业务代码应优先直接使用 Engine/Router 的 GET、POST、Match、Any
// 等常规方法注册 chi 风格 pattern；只有在需要 Match、NotFound、Handler、
// 纯 regex Group/Use 等高级控制能力时，才应显式使用本方法。
//
// 请求流程：
//  1. Gin 标准路由尝试匹配（优先级最高）。
//  2. 如果不匹配，NoRoute 调度到正则路由器。
//  3. 正则路由器尝试匹配 Chi 风格正则路由。
//  4. 如果仍不匹配，执行真正的 404 处理器。
//
// 使用示例：
//
//	rx := engine.RegexRouter()
//	rx.GET("/users/{id:[0-9]+}", func(c *gin.Context) {
//	    id := c.Param("id")
//	    c.Success(gin.H{"user_id": id})
//	})
//	rx.NotFound(func(c *gin.Context) {
//	    c.JSON(404, gin.H{"error": "page not found"})
//	})
//
// 调用顺序无关：
//
//	e.NoRoute(custom404)
//	rx := e.RegexRouter()  // 顺序A
//
//	rx := e.RegexRouter()
//	e.NoRoute(custom404)  // 顺序B
//
// 两种顺序效果完全一致。
func (e *Engine) RegexRouter() *RegexRouter {
	if e.regexRouter == nil {
		e.regexRouter = NewRegexRouter()
		e.regexRouter.engine = e

		// 注册 NoRoute 入口，先匹配正则路由再回退用户处理器
		e.registerNoRouteIfUnset()
	}
	return e.regexRouter
}

// registerNoRouteIfUnset 尝试注册 NoRoute 入口，避免覆盖用户已设置的 gin.NoRoute。
func (e *Engine) registerNoRouteIfUnset() {
	// 始终安装统一入口，避免覆盖用户已设置的 gin.NoRoute
	e.Engine.NoRoute(e.noRouteHandler())
}

// NoRoute 设置 404 处理器，兼容正则路由。
//
// 调用顺序无关：
//
//	e.NoRoute(custom404)
//	rx := e.RegexRouter()  // 顺序A
//
//	rx := e.RegexRouter()
//	e.NoRoute(custom404)  // 顺序B
//
// 两种顺序效果完全一致。
func (e *Engine) NoRoute(handlers ...gin.HandlerFunc) {
	e.userNoRouteHandlers = handlers // 存储用户处理器

	// 未启用受控兜底能力：直接设置到 gin.NoRoute
	if !e.needsManagedNoRoute() {
		e.Engine.NoRoute(handlers...)
		return
	}

	// 已启用正则路由器：更新 NoRoute 入口并保留最新用户处理器
	e.registerNoRouteIfUnset()
}

// NoMethod 设置处理不支持 HTTP 方法的处理器（405 Method Not Allowed）。
// 需要先设置 Engine.HandleMethodNotAllowed = true 才能生效。
//
// 使用示例：
//
//	e := gin.New()
//	e.Engine.HandleMethodNotAllowed = true
//	e.GET("/users", getUsers)
//	e.NoMethod(func(c *gin.Context) {
//	    c.JSON(405, gin.H{"error": "method not allowed"})
//	})
func (e *Engine) NoMethod(handlers ...gin.HandlerFunc) {
	e.userNoMethodHandlers = handlers
	e.Engine.NoMethod(handlers...)
}

// Static 设置静态文件目录服务。
// 提供本地文件系统目录的静态文件访问。
//
// 使用示例：
//
//	e.Static("/assets", "./public")
func (e *Engine) Static(relativePath, root string) IRoutes {
	e.Engine.Static(relativePath, root)
	return e
}

// StaticFS 设置基于 http.FileSystem 的静态文件服务。
// 支持自定义文件系统实现（embed.FS, zip.FS 等）。
//
// 使用示例：
//
//	e.StaticFS("/static", http.Dir("./public"))
func (e *Engine) StaticFS(relativePath string, fs http.FileSystem) IRoutes {
	e.Engine.StaticFS(relativePath, fs)
	return e
}

// StaticFile 设置单个静态文件路由。
// 将 URL 路径映射到文件系统中的具体文件。
//
// 使用示例：
//
//	e.StaticFile("/favicon.ico", "./assets/favicon.ico")
func (e *Engine) StaticFile(relativePath, filepath string) IRoutes {
	e.Engine.StaticFile(relativePath, filepath)
	return e
}

// StaticFileFS 设置单个静态文件路由，并使用自定义文件系统。
func (e *Engine) StaticFileFS(relativePath, filepath string, fs http.FileSystem) IRoutes {
	e.Engine.StaticFileFS(relativePath, filepath, fs)
	return e
}

// Routes 返回所有注册的路由信息。
// 用于路由调试、文档生成和诊断。
//
// 使用示例：
//
//	routes := e.Routes()
//	for _, route := range routes {
//	    fmt.Printf("%s %s\n", route.Method, route.Path)
//	}
func (e *Engine) Routes() RoutesInfo {
	routes := append(RoutesInfo{}, e.Engine.Routes()...)
	if e.regexRouter != nil {
		routes = append(routes, e.regexRouter.routesInfo()...)
	}
	return routes
}

// SetTrustedProxies 设置可信代理 IP 列表。
// 用于反向代理部署时的安全配置。
//
// 使用示例：
//
//	// 信任本地代理
//	e.SetTrustedProxies([]string{"127.0.0.1"})
//
//	// 信任私有网络
//	e.SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"})
//
//	// 不信任任何代理
//	e.SetTrustedProxies(nil)
func (e *Engine) SetTrustedProxies(trustedProxies []string) error {
	return e.Engine.SetTrustedProxies(trustedProxies)
}

// noRouteHandler 构建 NoRoute 入口，优先匹配正则路由，再处理受控静态挂载。
func (e *Engine) noRouteHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := &Context{Context: c, engine: e}

		if e.regexRouter != nil {
			match := e.regexRouter.lookup(c.Request.Method, requestLookupPath(c.Request))
			if match.found {
				injectRegexMatch(ctx, match)
				defer e.regexRouter.paramsPool.Put(match.params)
				match.handler(ctx)
				return
			}
			if match.methodNotAllowed && e.HandleMethodNotAllowed {
				writeAllowHeader(ctx, match.methodsAllowed)
				if len(e.userNoMethodHandlers) > 0 {
					c.Status(http.StatusMethodNotAllowed)
					executeGinHandlerChain(c, cloneGinHandlers(e.userNoMethodHandlers), "")
					return
				}
				c.Status(http.StatusMethodNotAllowed)
				return
			}
		}

		if e.tryServeStaticMounts(c) {
			return
		}

		if len(e.userNoRouteHandlers) > 0 {
			executeGinHandlerChain(c, cloneGinHandlers(e.userNoRouteHandlers), "")
			return
		}

		if e.regexRouter != nil && e.regexRouter.notFound != nil {
			e.regexRouter.notFound(ctx)
			return
		}

		c.Status(http.StatusNotFound)
	}
}

// addSwaggerRoute 添加 Swagger 路由信息。
func (e *Engine) addSwaggerRoute(route *SwaggerRouteInfo) {
	if e.swaggerRoutes == nil {
		e.swaggerRoutes = make([]*SwaggerRouteInfo, 0)
	}
	e.swaggerRoutes = append(e.swaggerRoutes, route)
}

// registerSwaggerRoutes 注册 Swagger UI 和文档路由。
func (e *Engine) registerSwaggerRoutes() {
	if e.swaggerConfig == nil {
		return
	}

	// 注册 Swagger UI 路由
	e.Engine.GET("/swagger", func(c *gin.Context) {
		// 动态生成文档
		generator := e.buildSwaggerGenerator()
		uiHandler := swagger.NewUIHandler(generator)
		uiHandler.ServeUI(c.Writer, c.Request)
	})

	// 注册文档 JSON 路由
	e.Engine.GET("/swagger/doc.json", func(c *gin.Context) {
		// 动态生成文档
		generator := e.buildSwaggerGenerator()
		uiHandler := swagger.NewUIHandler(generator)
		uiHandler.ServeDoc(c.Writer, c.Request)
	})
}

// buildSwaggerGenerator 构建 Swagger 生成器。
func (e *Engine) buildSwaggerGenerator() *swagger.Generator {
	generator := swagger.NewGenerator(*e.swaggerConfig)
	documented := make(map[string]struct{}, len(e.swaggerRoutes))

	// 添加已收集的路由信息
	for _, route := range e.swaggerRoutes {
		swaggerRoute := &swagger.RouteInfo{
			Path:        route.path,
			Method:      route.method,
			Summary:     route.summary,
			Description: route.description,
			OperationID: route.operationID,
			Params:      route.params,
			Responses:   route.responses,
			Tags:        route.tags,
			Deprecated:  route.deprecated,
			Security:    route.security,
		}
		generator.AddRoute(swaggerRoute)
		documented[observableRouteKey(route.method, route.path)] = struct{}{}
	}

	for _, route := range e.Routes() {
		if strings.HasPrefix(route.Path, "/swagger") {
			continue
		}
		key := observableRouteKey(route.Method, route.Path)
		if _, exists := documented[key]; exists {
			continue
		}
		generator.AddRoute(&swagger.RouteInfo{
			Path:   route.Path,
			Method: route.Method,
		})
	}

	return generator
}
