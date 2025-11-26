package gin

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkit/gin/cache"
	"github.com/darkit/gin/pkg/errors"
	"github.com/darkit/gin/pkg/sse"
	"github.com/darkit/gin/types"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var startTime = time.Now() // 服务器启动时间

// HandlerFunc 定义处理函数类型
type HandlerFunc func(*Context)

// ErrorHandler 错误处理器类型别名
type ErrorHandler = errors.ErrorHandler

// 路由相关错误码
const (
	ErrCodeRouteConflict     = 4001 // 路由冲突
	ErrCodeInvalidPath       = 4002 // 无效路径
	ErrCodeInvalidMethod     = 4003 // 无效方法
	ErrCodeMiddlewareTimeout = 4004 // 中间件超时
	ErrCodeRegistrationFail  = 4005 // 注册失败
	ErrCodePatternInvalid    = 4006 // 模式无效
	ErrCodeMetadataInvalid   = 4007 // 元数据无效
)

// RouterConfig 路由器配置
type RouterConfig struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

// DefaultRouterConfig 默认路由器配置
func DefaultRouterConfig() *RouterConfig {
	return &RouterConfig{
		Host: "0.0.0.0",
		Port: "8080",
	}
}

// Router 路由管理器
type Router struct {
	engine      *gin.Engine
	groups      map[string]*RouterGroup   // 路由组映射表
	cache       *cache.Cache[string, any] // 全局缓存实例
	sseHub      *sse.Hub                  // SSE中心实例
	mu          sync.RWMutex              // 用于保护路由组映射表的并发安全
	routes      map[string]bool           // 用于检测路由重复注册
	handlers    Handler                   // 处理器实例，用于处理动态路由
	middlewares []HandlerFunc             // 全局中间件

	// 增强功能字段
	config       *Config      // 框架配置
	errorHandler ErrorHandler // 错误处理器
	jwtAdapter   *JWTAdapter  // JWT适配器

	// OpenAPI相关字段
	apiRoutes   []*APIRoute // API路由记录（用于文档生成）
	openapiSpec *openapi3.T // 生成的OpenAPI规范

	// 日志相关字段
	logger Logger // 统一日志接口
}

// RouterGroup 路由组
type RouterGroup struct {
	group      *gin.RouterGroup
	basePath   string
	router     *Router
	handlers   Handler       // 组级处理器
	middleware []HandlerFunc // 组级中间件

	// OpenAPI相关字段
	defaultTags     []string              // 默认标签
	defaultSecurity []map[string][]string // 默认安全配置
}

// APIRoute API路由文档信息记录
type APIRoute struct {
	// 基础路由信息
	Method   string                 // HTTP方法
	Path     string                 // 路径
	Handler  HandlerFunc            // 处理函数
	Metadata map[string]interface{} // 存储文档元数据（保持向后兼容）

	// OpenAPI文档字段
	OperationID string   // 操作ID
	Summary     string   // 摘要
	Description string   // 描述
	Tags        []string // 标签
	Deprecated  bool     // 是否已弃用
	Hide        bool     // 是否在文档中隐藏

	// 参数
	PathParams  []*openapi3.ParameterRef // 路径参数
	QueryParams []*openapi3.ParameterRef // 查询参数
	Headers     []*openapi3.ParameterRef // 头部参数

	// 请求/响应
	Request         *openapi3.SchemaRef            // 请求体schema
	Responses       map[int]*openapi3.SchemaRef    // 响应schema
	ResponseHeaders map[string]*openapi3.HeaderRef // 响应头部

	// 安全认证
	BearerAuth bool                  // Bearer认证
	BasicAuth  bool                  // Basic认证
	Security   []map[string][]string // 安全配置

	// 示例
	RequestExample interface{} // 请求示例
}

// DocOption 文档选项接口
type DocOption interface {
	apply(route *APIRoute)
}

// docOptionFunc 函数式选项实现
type docOptionFunc func(route *APIRoute)

func (f docOptionFunc) apply(route *APIRoute) { f(route) }

// ========== 基础文档选项函数 ==========

// Summary 设置路由摘要
func Summary(text string) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		route.Metadata["summary"] = text
	})
}

// Description 设置路由描述
func Description(text string) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		route.Metadata["description"] = text
	})
}

// Tags 设置路由标签
func Tags(tags ...string) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		route.Metadata["tags"] = tags
	})
}

// Response 定义响应类型
func Response(statusOrValue interface{}, valueOptional ...interface{}) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		if route.Metadata["responses"] == nil {
			route.Metadata["responses"] = make(map[int]interface{})
		}
		responses := route.Metadata["responses"].(map[int]interface{})

		switch val := statusOrValue.(type) {
		case int:
			// 用法: Response(200, value)
			if len(valueOptional) > 0 && valueOptional[0] != nil {
				responses[val] = valueOptional[0]
			}
		default:
			// 用法: Response(value) - 默认200状态码
			if val != nil {
				responses[200] = val
			}
		}
	})
}

// RequestBody 定义请求体类型
func RequestBody(value interface{}) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		route.Metadata["requestBody"] = value
	})
}

// PathParam 定义路径参数
func PathParam(name, typ, description string) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		if route.Metadata["pathParams"] == nil {
			route.Metadata["pathParams"] = make([]map[string]string, 0)
		}
		pathParams := route.Metadata["pathParams"].([]map[string]string)
		pathParams = append(pathParams, map[string]string{
			"name":        name,
			"type":        typ,
			"description": description,
		})
		route.Metadata["pathParams"] = pathParams
	})
}

// QueryParam 定义查询参数
func QueryParam(name, typ, description string, required bool) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		if route.Metadata["queryParams"] == nil {
			route.Metadata["queryParams"] = make([]map[string]interface{}, 0)
		}
		queryParams := route.Metadata["queryParams"].([]map[string]interface{})
		queryParams = append(queryParams, map[string]interface{}{
			"name":        name,
			"type":        typ,
			"description": description,
			"required":    required,
		})
		route.Metadata["queryParams"] = queryParams
	})
}

// Security 定义安全要求
func Security(scheme string, scopes ...string) DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		if route.Metadata["security"] == nil {
			route.Metadata["security"] = make([]map[string][]string, 0)
		}
		security := route.Metadata["security"].([]map[string][]string)
		security = append(security, map[string][]string{scheme: scopes})
		route.Metadata["security"] = security
	})
}

// Deprecated 标记路由为已弃用
func Deprecated() DocOption {
	return docOptionFunc(func(route *APIRoute) {
		if route.Metadata == nil {
			route.Metadata = make(map[string]interface{})
		}
		route.Metadata["deprecated"] = true
	})
}

// ========== 泛型化的文档选项函数 ==========

// Resp 泛型化的响应定义，提供类型安全
func Resp[T any](status int) DocOption {
	var example T
	return Response(status, example)
}

// ReqBody 泛型化的请求体定义，提供类型安全
func ReqBody[T any]() DocOption {
	var example T
	return RequestBody(example)
}

// ResourceHandler 定义资源处理器接口
type ResourceHandler interface {
	Index(*Context)  // GET /resources      - 列表
	Show(*Context)   // GET /resources/:id  - 详情
	Create(*Context) // POST /resources     - 创建
	Update(*Context) // PUT /resources/:id  - 更新
	Delete(*Context) // DELETE /resources/:id - 删除
}

// RESTOption 自定义 REST 注册行为
type RESTOption func(*restConfig)

type restAction string

const (
	restActionList   restAction = "list"
	restActionShow   restAction = "show"
	restActionCreate restAction = "create"
	restActionUpdate restAction = "update"
	restActionDelete restAction = "delete"
)

type restConfig struct {
	basePath     string
	idParam      string
	middleware   []HandlerFunc
	routeOptions map[restAction][]interface{}
}

func newRESTConfig(resource string) *restConfig {
	path := strings.TrimSpace(resource)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	return &restConfig{
		basePath:     path,
		idParam:      "id",
		routeOptions: make(map[restAction][]interface{}),
	}
}

func (cfg *restConfig) itemPath() string {
	if cfg.basePath == "/" {
		return fmt.Sprintf("/:%s", cfg.idParam)
	}
	return fmt.Sprintf("%s/:%s", cfg.basePath, cfg.idParam)
}

func (cfg *restConfig) optionsFor(action restAction) []interface{} {
	options := make([]interface{}, 0, len(cfg.middleware)+len(cfg.routeOptions[action]))
	for _, m := range cfg.middleware {
		options = append(options, m)
	}
	options = append(options, cfg.routeOptions[action]...)
	return options
}

func (cfg *restConfig) registerWithRouter(r *Router, handler ResourceHandler) {
	if handler == nil {
		return
	}
	r.GET(cfg.basePath, handler.Index, cfg.optionsFor(restActionList)...)
	r.GET(cfg.itemPath(), handler.Show, cfg.optionsFor(restActionShow)...)
	r.POST(cfg.basePath, handler.Create, cfg.optionsFor(restActionCreate)...)
	r.PUT(cfg.itemPath(), handler.Update, cfg.optionsFor(restActionUpdate)...)
	r.PATCH(cfg.itemPath(), handler.Update, cfg.optionsFor(restActionUpdate)...)
	r.DELETE(cfg.itemPath(), handler.Delete, cfg.optionsFor(restActionDelete)...)
}

func (cfg *restConfig) registerWithGroup(rg *RouterGroup, handler ResourceHandler) {
	if handler == nil {
		return
	}
	rg.GET(cfg.basePath, handler.Index, cfg.optionsFor(restActionList)...)
	rg.GET(cfg.itemPath(), handler.Show, cfg.optionsFor(restActionShow)...)
	rg.POST(cfg.basePath, handler.Create, cfg.optionsFor(restActionCreate)...)
	rg.PUT(cfg.itemPath(), handler.Update, cfg.optionsFor(restActionUpdate)...)
	rg.PATCH(cfg.itemPath(), handler.Update, cfg.optionsFor(restActionUpdate)...)
	rg.DELETE(cfg.itemPath(), handler.Delete, cfg.optionsFor(restActionDelete)...)
}

// RESTWithBasePath 自定义基础路径
func RESTWithBasePath(path string) RESTOption {
	return func(cfg *restConfig) {
		if path != "" {
			cfg.basePath = normalizePath(path)
		}
	}
}

// RESTWithIDParam 自定义 ID 参数名
func RESTWithIDParam(name string) RESTOption {
	return func(cfg *restConfig) {
		name = strings.TrimSpace(name)
		if name != "" {
			cfg.idParam = name
		}
	}
}

// RESTWithMiddleware 添加全局中间件
func RESTWithMiddleware(m ...HandlerFunc) RESTOption {
	return func(cfg *restConfig) {
		cfg.middleware = append(cfg.middleware, m...)
	}
}

// RESTWithRouteOptions 添加指定动作的额外参数（中间件或文档）
func RESTWithRouteOptions(action string, options ...interface{}) RESTOption {
	return func(cfg *restConfig) {
		act := parseRESTAction(action)
		if act == "" {
			return
		}
		cfg.routeOptions[act] = append(cfg.routeOptions[act], options...)
	}
}

// RESTWithDoc 为指定动作添加文档选项
func RESTWithDoc(action string, opts ...DocOption) RESTOption {
	interfaces := make([]interface{}, len(opts))
	for i, opt := range opts {
		interfaces[i] = opt
	}
	return RESTWithRouteOptions(action, interfaces...)
}

// RESTWithDocsAll 为所有动作添加统一的文档配置
func RESTWithDocsAll(opts ...DocOption) RESTOption {
	return func(cfg *restConfig) {
		interfaces := make([]interface{}, len(opts))
		for i, opt := range opts {
			interfaces[i] = opt
		}
		for _, action := range []restAction{restActionList, restActionShow, restActionCreate, restActionUpdate, restActionDelete} {
			cfg.routeOptions[action] = append(cfg.routeOptions[action], interfaces...)
		}
	}
}

func parseRESTAction(action string) restAction {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "list":
		return restActionList
	case "show", "detail":
		return restActionShow
	case "create", "store":
		return restActionCreate
	case "update":
		return restActionUpdate
	case "delete", "remove":
		return restActionDelete
	default:
		return ""
	}
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return path
}

// RouteError 路由错误基类
type RouteError struct {
	Code      int                    `json:"code"`
	Type      string                 `json:"type"`
	Message   string                 `json:"message"`
	Route     string                 `json:"route,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Cause     error                  `json:"-"`
	Timestamp time.Time              `json:"timestamp"`
}

// Error 实现error接口
func (re *RouteError) Error() string {
	if re.Cause != nil {
		return fmt.Sprintf("%s: %s (原因: %s)", re.Type, re.Message, re.Cause.Error())
	}
	return fmt.Sprintf("%s: %s", re.Type, re.Message)
}

// Unwrap 获取底层错误
func (re *RouteError) Unwrap() error {
	return re.Cause
}

// PathValidationError 路径验证错误
type PathValidationError struct {
	RouteError
	Path        string   `json:"path"`
	Violations  []string `json:"violations"`
	Suggestions []string `json:"suggestions"`
}

// NewPathValidationError 创建路径验证错误
func NewPathValidationError(path string, violations []string, suggestions []string) *PathValidationError {
	return &PathValidationError{
		RouteError: RouteError{
			Code:      ErrCodeInvalidPath,
			Type:      "PathValidationError",
			Message:   "路径验证失败",
			Route:     path,
			Timestamp: time.Now(),
		},
		Path:        path,
		Violations:  violations,
		Suggestions: suggestions,
	}
}

// NewRouter 创建新的路由管理器（推荐使用）
// 提供更简洁的初始化方式，兼容传入nil engine的旧用法
func NewRouter(engineOrFirstOpt interface{}, opts ...RouterOption) *Router {
	// 初始化默认值
	engine := gin.New()
	config := DefaultConfig()
	var allOpts []RouterOption

	// 处理第一个参数的不同类型
	switch v := engineOrFirstOpt.(type) {
	case *gin.Engine:
		// 兼容旧用法: NewRouter(engine)
		if v != nil {
			engine = v
		}
		allOpts = opts
	case RouterOption:
		// 新用法: NewRouter(opt1, opt2, ...)
		allOpts = append([]RouterOption{v}, opts...)
	default:
		// nil 或其他情况，使用默认值
		allOpts = opts
	}

	// 应用选项配置
	for _, opt := range allOpts {
		opt(config, engine)
	}

	// 创建路由器实例
	router := &Router{
		engine:      engine,
		groups:      make(map[string]*RouterGroup),
		routes:      make(map[string]bool),
		handlers:    &BasicHandler{},
		middlewares: make([]HandlerFunc, 0),
		config:      config,
	}

	// 初始化日志器
	if config.LoggerConfig != nil {
		router.logger = config.LoggerConfig.GetLogger("GIN-ROUTER")
	} else {
		router.logger = NewGinCompatLogger("GIN-ROUTER")
	}

	// 初始化组件（失败时记录日志但继续）
	if err := router.initializeComponents(); err != nil {
		router.logger.Warn("[GIN-ROUTER] 组件初始化失败: %v", err)
	}

	// 设置增强中间件，确保与 New 保持一致
	router.setupMiddleware()

	return router
}

// RouterOption 路由器配置选项
type RouterOption func(*Config, *gin.Engine)

// WithCache 启用缓存功能
func WithCache(config *cache.Config) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		c.CacheEnabled = true
		if config != nil {
			c.CacheConfig = config
		}
	}
}

// WithSSE 启用SSE功能
func WithSSE(config *sse.Config) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		c.SSEEnabled = true
		if config != nil {
			c.SSEConfig = config
		}
	}
}

// WithOpenAPI 启用OpenAPI文档生成功能
func WithOpenAPI(config *OpenAPI) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		c.OpenAPIEnabled = true
		if config != nil {
			c.OpenAPI = config
		}
	}
}

// WithJWT 快速配置JWT密钥和安全选项
func WithJWT(secret string, customize ...func(*SecurityConfig)) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		if strings.TrimSpace(secret) == "" {
			return
		}

		if c.SecurityConfig == nil {
			c.SecurityConfig = DefaultSecurityConfig()
		}

		c.SecurityConfig.JWTSecretKey = []byte(secret)

		for _, fn := range customize {
			if fn != nil {
				fn(c.SecurityConfig)
			}
		}
	}
}

// WithSecurityConfig 提供统一的安全配置入口
func WithSecurityConfig(configure func(*SecurityConfig)) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		if configure == nil {
			return
		}
		if c.SecurityConfig == nil {
			c.SecurityConfig = DefaultSecurityConfig()
		}
		configure(c.SecurityConfig)
	}
}

// WithConfig 提供 access to 框架 Config 以便一次性调整
func WithConfig(customize func(*Config)) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		if customize != nil {
			customize(c)
		}
	}
}

// WithGinMode 设置Gin运行模式
func WithGinMode(mode string) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		gin.SetMode(mode)
	}
}

// WithMiddleware 添加全局中间件
func WithMiddleware(middlewares ...gin.HandlerFunc) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		engine.Use(middlewares...)
	}
}

// WithCORS 添加安全的CORS中间件
func WithCORS(allowOrigins ...string) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		// 使用安全配置中的CORS设置
		var corsConfig *SecurityConfig
		if c.SecurityConfig != nil {
			corsConfig = c.SecurityConfig
		} else {
			corsConfig = DefaultSecurityConfig()
		}

		// 如果提供了参数，覆盖默认配置
		if len(allowOrigins) > 0 {
			corsConfig.CORSAllowedOrigins = allowOrigins
		}

		// 验证CORS配置安全性
		if err := validateCORSConfig(corsConfig); err != nil {
			panic(fmt.Sprintf("不安全的CORS配置: %v", err))
		}

		engine.Use(func(ctx *gin.Context) {
			origin := ctx.Request.Header.Get("Origin")

			// 严格的来源检查
			allowed := false
			if origin != "" {
				for _, allowedOrigin := range corsConfig.CORSAllowedOrigins {
					if allowedOrigin == "*" {
						ctx.Header("Access-Control-Allow-Origin", origin)
						allowed = true
						break
					}
					if allowedOrigin == origin {
						ctx.Header("Access-Control-Allow-Origin", origin)
						allowed = true
						break
					}
				}
			}

			// 只有允许的来源才设置其他CORS头
			if allowed {
				ctx.Header("Access-Control-Allow-Methods", strings.Join(corsConfig.CORSAllowedMethods, ", "))
				ctx.Header("Access-Control-Allow-Headers", strings.Join(corsConfig.CORSAllowedHeaders, ", "))
				ctx.Header("Access-Control-Max-Age", strconv.Itoa(corsConfig.CORSMaxAge))
				ctx.Header("Vary", "Origin")

				// 只有在安全的情况下才允许凭据
				if corsConfig.CORSAllowCredentials && !containsString(corsConfig.CORSAllowedOrigins, "*") {
					ctx.Header("Access-Control-Allow-Credentials", "true")
				}
			}

			if ctx.Request.Method == "OPTIONS" {
				if allowed {
					ctx.AbortWithStatus(http.StatusNoContent)
				} else {
					ctx.AbortWithStatus(http.StatusForbidden)
				}
				return
			}

			ctx.Next()
		})
	}
}

// validateCORSConfig 验证CORS配置的安全性
func validateCORSConfig(config *SecurityConfig) error {
	// 检查危险的配置组合
	if containsString(config.CORSAllowedOrigins, "*") && config.CORSAllowCredentials {
		return fmt.Errorf("不能同时允许所有来源(*)和凭据(credentials)")
	}

	// 检查是否有明确的来源配置
	if len(config.CORSAllowedOrigins) == 0 {
		return fmt.Errorf("必须配置至少一个允许的CORS来源")
	}

	// 检查是否包含不安全的来源
	for _, origin := range config.CORSAllowedOrigins {
		if origin != "*" && !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return fmt.Errorf("无效的CORS来源格式: %s", origin)
		}
	}

	return nil
}

// containsString 检查切片是否包含指定元素
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// WithRateLimit 添加简单的内存限流中间件
func WithRateLimit(requestsPerMinute int) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		limiter := make(map[string][]time.Time)
		var mu sync.RWMutex
		ticker := time.NewTicker(time.Minute)
		// 清理长时间不用的 key，避免 map 无界增长
		go func() {
			for range ticker.C {
				cutoff := time.Now().Add(-2 * time.Minute)
				mu.Lock()
				for k, requests := range limiter {
					if len(requests) == 0 || requests[len(requests)-1].Before(cutoff) {
						delete(limiter, k)
					}
				}
				mu.Unlock()
			}
		}()

		engine.Use(func(ctx *gin.Context) {
			clientIP := ctx.ClientIP()
			now := time.Now()

			mu.Lock()
			defer mu.Unlock()

			// 清理过期记录
			if requests, exists := limiter[clientIP]; exists {
				var validRequests []time.Time
				for _, reqTime := range requests {
					if now.Sub(reqTime) <= time.Minute {
						validRequests = append(validRequests, reqTime)
					}
				}
				limiter[clientIP] = validRequests
			}

			// 检查限流
			if len(limiter[clientIP]) >= requestsPerMinute {
				ctx.JSON(http.StatusTooManyRequests, H{
					"error":       "rate limit exceeded",
					"retry_after": 60,
				})
				ctx.Abort()
				return
			}

			// 记录请求
			limiter[clientIP] = append(limiter[clientIP], now)
			ctx.Next()
		})
	}
}

// WithRequestID 添加请求ID中间件
func WithRequestID() RouterOption {
	return func(c *Config, engine *gin.Engine) {
		engine.Use(func(ctx *gin.Context) {
			incoming := strings.TrimSpace(ctx.GetHeader("X-Request-ID"))
			requestID := incoming
			if requestID == "" || len(requestID) > 128 || strings.ContainsAny(requestID, " \t\n\r") {
				requestID = generateRequestID()
			}
			ctx.Header("X-Request-ID", requestID)
			if incoming != "" && incoming != requestID {
				ctx.Header("X-Original-Request-ID", incoming)
			}
			ctx.Set("request_id", requestID)
			ctx.Next()
		})
	}
}

// WithTimeout 添加请求超时中间件
func WithTimeout(timeout time.Duration) RouterOption {
	return func(c *Config, engine *gin.Engine) {
		engine.Use(func(ctx *gin.Context) {
			tw := &timeoutWriter{ResponseWriter: ctx.Writer, h: make(chan struct{})}
			ctx.Writer = tw

			ctxCopy := ctx.Copy()
			ctxWithTimeout, cancel := context.WithTimeout(ctx.Request.Context(), timeout)
			ctxCopy.Request = ctx.Request.WithContext(ctxWithTimeout)

			done := make(chan struct{})
			go func() {
				ctxCopy.Next()
				close(done)
			}()

			select {
			case <-done:
				close(tw.h)
				cancel()
			case <-ctxWithTimeout.Done():
				tw.timeout()
				ctx.AbortWithStatusJSON(http.StatusRequestTimeout, H{"error": "request timeout"})
				cancel()
			}
		})
	}
}

type timeoutWriter struct {
	gin.ResponseWriter
	h        chan struct{}
	timedOut bool
	mu       sync.Mutex
}

func (t *timeoutWriter) timeout() {
	t.mu.Lock()
	if t.timedOut {
		t.mu.Unlock()
		return
	}
	if !isClosed(t.h) {
		close(t.h)
	}
	t.timedOut = true
	t.mu.Unlock()
}

func (t *timeoutWriter) hasTimedOut() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.timedOut
}

func (t *timeoutWriter) Write(p []byte) (int, error) {
	if t.hasTimedOut() {
		return 0, http.ErrHandlerTimeout
	}
	return t.ResponseWriter.Write(p)
}

func (t *timeoutWriter) WriteString(s string) (int, error) {
	if t.hasTimedOut() {
		return 0, http.ErrHandlerTimeout
	}
	return t.ResponseWriter.WriteString(s)
}

func (t *timeoutWriter) WriteHeader(statusCode int) {
	if t.hasTimedOut() {
		return
	}
	t.ResponseWriter.WriteHeader(statusCode)
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// NewRouterLegacy 创建新的路由管理器（保持向后兼容）
func NewRouterLegacy(engine *gin.Engine) *Router {
	if engine == nil {
		engine = gin.New() // 如果未提供引擎，创建新的
	}

	router := &Router{
		engine:      engine,
		groups:      make(map[string]*RouterGroup),
		routes:      make(map[string]bool),
		mu:          sync.RWMutex{},
		handlers:    NewBasicHandler(),
		middlewares: make([]HandlerFunc, 0),
	}

	return router
}

// WithHandler 设置路由器的处理器
func (r *Router) WithHandler(handler Handler) *Router {
	if handler != nil {
		r.handlers = handler
	}
	return r
}

// Register 注册路由
func (r *Router) Register(method, path string, handler HandlerFunc, middleware ...HandlerFunc) {
	// 使用新的路由模式验证功能
	if err := ValidateRoutePattern(method, path); err != nil {
		r.logger.Error("路由注册失败 '%s %s' - %v", method, path, err)
		return
	}

	// 规范化路径
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 解析路由模式以获取详细信息
	routePattern, err := ParseRoutePattern(method, path)
	if err != nil {
		r.logger.Error("路由模式解析失败 '%s %s' - %v", method, path, err)
		return
	}

	// 验证路由模式的完整性
	if err := routePattern.Validate(); err != nil {
		r.logger.Error("路由模式验证失败 '%s %s' - %v", method, path, err)
		return
	}

	// 构建路由标识符用于冲突检测
	routeID := method + ":" + path

	r.mu.Lock()
	defer r.mu.Unlock() // 使用defer确保锁一定会被释放

	// 确保handlers已初始化
	if r.handlers == nil {
		r.handlers = NewBasicHandler()
	}

	// 检测路由冲突 - 使用增强的冲突检测
	for existingRouteID := range r.routes {
		parts := strings.SplitN(existingRouteID, ":", 2)
		if len(parts) == 2 {
			existingMethod, existingPath := parts[0], parts[1]
			if existingPattern, err := ParseRoutePattern(existingMethod, existingPath); err == nil {
				if routePattern.IsConflictWith(existingPattern) {
					r.logger.Warn("路由冲突检测 '%s %s' 与现有路由 '%s %s' 冲突，忽略注册",
						method, path, existingMethod, existingPath)
					return
				}
			}
		}
	}

	// 检测完全相同的路由
	if _, exists := r.routes[routeID]; exists {
		r.logger.Warn("路由 '%s %s' 已存在，忽略重复注册", method, path)
		return
	}

	// 记录路由
	r.routes[routeID] = true

	// 输出路由注册信息（包含段类型信息）
	if len(routePattern.ParamNames) > 0 || routePattern.IsWildcard {
		r.logger.Info("注册路由: %s %s (参数: %v, 通配符: %t, 优先级: %d)",
			method, path, routePattern.ParamNames, routePattern.IsWildcard, routePattern.Priority)
	} else {
		r.logger.Debug("注册路由: %s %s", method, path)
	}

	// 设置到处理器
	r.handlers.SetHandler(routeID, handler)

	// 合并全局中间件和路由特定的中间件
	allMiddleware := make([]HandlerFunc, 0, len(r.middlewares)+len(middleware))
	allMiddleware = append(allMiddleware, r.middlewares...)
	allMiddleware = append(allMiddleware, middleware...)

	handlers := make([]gin.HandlerFunc, 0, len(allMiddleware)+1)

	// 转换中间件
	for _, m := range allMiddleware {
		handlers = append(handlers, r.wrapHandlerWithRouter(m))
	}

	// 添加主处理函数
	handlers = append(handlers, r.wrapHandlerWithRouter(handler))

	// 注册到 gin
	r.engine.Handle(method, path, handlers...)
}

// Group 创建或获取路由组
func (r *Router) Group(path string, middleware ...HandlerFunc) *RouterGroup {
	// 检查路径格式
	if path != "" && path[0] != '/' {
		path = "/" + path
	}

	r.mu.RLock()
	// 检查是否已存在该路由组
	if group, exists := r.groups[path]; exists {
		r.mu.RUnlock()
		// 更新中间件
		if len(middleware) > 0 {
			group.middleware = append(group.middleware, middleware...)
		}
		return group
	}
	r.mu.RUnlock()

	// 创建组级处理器
	groupHandler := r.handlers.Clone()

	// 转换中间件
	combinedMiddleware := make([]HandlerFunc, len(r.middlewares)+len(middleware))
	copy(combinedMiddleware, r.middlewares)
	copy(combinedMiddleware[len(r.middlewares):], middleware)

	handlers := make([]gin.HandlerFunc, len(combinedMiddleware))
	for i, m := range combinedMiddleware {
		handlers[i] = r.wrapHandlerWithRouter(m)
	}

	// 创建gin路由组
	ginGroup := r.engine.Group(path, handlers...)

	// 创建我们的路由组
	rg := &RouterGroup{
		group:      ginGroup,
		basePath:   path,
		router:     r,
		handlers:   groupHandler,
		middleware: make([]HandlerFunc, len(middleware)),
	}

	copy(rg.middleware, middleware)

	// 保存到映射表
	r.mu.Lock()
	r.groups[path] = rg
	r.mu.Unlock()

	return rg
}

// HTTP方法处理函数，减少重复代码
func (r *Router) httpMethod(method string, path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(method, path, handler, middleware...)
}

// httpMethodWithDoc 带文档支持的HTTP方法处理函数
func (r *Router) httpMethodWithDoc(method string, path string, handler HandlerFunc, options ...interface{}) {
	// 分离中间件和文档选项
	var middlewares []HandlerFunc
	var docOpts []DocOption

	for _, opt := range options {
		switch v := opt.(type) {
		case HandlerFunc:
			middlewares = append(middlewares, v)
		case DocOption:
			docOpts = append(docOpts, v)
		case []DocOption: // 支持批量传入
			docOpts = append(docOpts, v...)
		}
	}

	// 注册路由（原有逻辑）
	r.Register(method, path, handler, middlewares...)

	// 记录API路由文档（新增逻辑）
	if len(docOpts) > 0 {
		r.recordAPIRoute(method, path, handler, docOpts...)
	}
}

// recordAPIRoute 记录API路由用于文档生成
func (r *Router) recordAPIRoute(method, path string, handler HandlerFunc, opts ...DocOption) {
	if r.config == nil || !r.config.OpenAPIEnabled {
		return // 未启用 OpenAPI，跳过记录
	}

	// 路由变更时立即使缓存失效，防止文档与实际路由不一致
	r.InvalidateOpenAPICache()

	route := &APIRoute{
		Method:   method,
		Path:     path,
		Handler:  handler,
		Metadata: make(map[string]interface{}),
	}

	// 应用文档选项
	for _, opt := range opts {
		opt.apply(route)
	}

	// 添加到API路由列表
	r.mu.Lock()
	r.apiRoutes = append(r.apiRoutes, route)
	r.mu.Unlock()
}

// toInterfaceSlice 将HandlerFunc切片转换为interface{}切片
func toInterfaceSlice(handlers []HandlerFunc) []interface{} {
	result := make([]interface{}, len(handlers))
	for i, h := range handlers {
		result[i] = h
	}
	return result
}

// ========== OpenAPI 集成方法 ==========

// GenerateOpenAPISpec 生成OpenAPI规范
func (r *Router) GenerateOpenAPISpec() *openapi3.T {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.config.OpenAPIEnabled || r.config.OpenAPI == nil {
		return nil
	}

	// 使用缓存的规范（如果存在且仍然有效）
	if r.openapiSpec != nil {
		return r.openapiSpec
	}

	// 创建OpenAPI规范
	spec := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   r.config.OpenAPI.Title,
			Version: r.config.OpenAPI.Version,
		},
		Paths: &openapi3.Paths{},
	}

	// 设置服务器信息
	if len(r.config.OpenAPI.Servers) > 0 {
		for _, server := range r.config.OpenAPI.Servers {
			spec.Servers = append(spec.Servers, &openapi3.Server{
				URL:         server.URL,
				Description: server.Description,
			})
		}
	}

	// 设置组件（安全方案等）
	if len(r.config.OpenAPI.SecuritySchemes) > 0 {
		if spec.Components == nil {
			spec.Components = &openapi3.Components{}
		}
		spec.Components.SecuritySchemes = make(openapi3.SecuritySchemes)

		for _, scheme := range r.config.OpenAPI.SecuritySchemes {
			spec.Components.SecuritySchemes[scheme.Name] = &openapi3.SecuritySchemeRef{
				Value: &openapi3.SecurityScheme{
					Type:         scheme.Type,
					Scheme:       scheme.Scheme,
					BearerFormat: scheme.BearerFormat,
				},
			}
		}
	}

	// 处理API路由
	for _, route := range r.apiRoutes {
		r.addRouteToSpec(spec, route)
	}

	// 缓存生成的规范
	r.openapiSpec = spec
	return spec
}

// addRouteToSpec 将路由添加到OpenAPI规范
func (r *Router) addRouteToSpec(spec *openapi3.T, route *APIRoute) {
	path := route.Path
	method := strings.ToLower(route.Method)

	// 确保路径存在
	if spec.Paths.Value(path) == nil {
		spec.Paths.Set(path, &openapi3.PathItem{})
	}

	// 创建操作
	operation := &openapi3.Operation{
		OperationID: fmt.Sprintf("%s_%s", method, strings.ReplaceAll(path, "/", "_")),
	}

	// 应用元数据
	if route.Metadata != nil {
		if summary, ok := route.Metadata["summary"].(string); ok {
			operation.Summary = summary
		}
		if description, ok := route.Metadata["description"].(string); ok {
			operation.Description = description
		}
		if tags, ok := route.Metadata["tags"].([]string); ok {
			operation.Tags = tags
		}
		if deprecated, ok := route.Metadata["deprecated"].(bool); ok {
			operation.Deprecated = deprecated
		}

		// 处理响应
		if responses, ok := route.Metadata["responses"].(map[int]interface{}); ok {
			operation.Responses = &openapi3.Responses{}
			for status, example := range responses {
				statusStr := fmt.Sprintf("%d", status)
				schemaRef := r.generateSchemaFromExample(example)
				response := &openapi3.Response{
					Description: &statusStr,
				}
				if schemaRef != nil {
					response.Content = openapi3.NewContentWithJSONSchemaRef(schemaRef)
				}
				operation.Responses.Set(statusStr, &openapi3.ResponseRef{Value: response})
			}
		}

		// 处理请求体
		if requestBody, ok := route.Metadata["requestBody"]; ok {
			schemaRef := r.generateSchemaFromExample(requestBody)
			if schemaRef != nil {
				operation.RequestBody = &openapi3.RequestBodyRef{
					Value: &openapi3.RequestBody{
						Content: openapi3.NewContentWithJSONSchemaRef(schemaRef),
					},
				}
			}
		}

		// 处理参数
		if pathParams, ok := route.Metadata["pathParams"].([]map[string]string); ok {
			for _, param := range pathParams {
				operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:        param["name"],
						In:          "path",
						Required:    true,
						Description: param["description"],
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{param["type"]},
							},
						},
					},
				})
			}
		}

		if queryParams, ok := route.Metadata["queryParams"].([]map[string]interface{}); ok {
			for _, param := range queryParams {
				name, _ := param["name"].(string)
				typ, _ := param["type"].(string)
				description, _ := param["description"].(string)
				required, _ := param["required"].(bool)

				operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:        name,
						In:          "query",
						Required:    required,
						Description: description,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{typ},
							},
						},
					},
				})
			}
		}

		// 处理安全要求
		if security, ok := route.Metadata["security"].([]map[string][]string); ok {
			operation.Security = &openapi3.SecurityRequirements{}
			for _, req := range security {
				secReq := make(openapi3.SecurityRequirement)
				for scheme, scopes := range req {
					secReq[scheme] = scopes
				}
				*operation.Security = append(*operation.Security, secReq)
			}
		}
	}

	// 将操作添加到路径项
	pathItem := spec.Paths.Value(path)
	switch method {
	case "get":
		pathItem.Get = operation
	case "post":
		pathItem.Post = operation
	case "put":
		pathItem.Put = operation
	case "delete":
		pathItem.Delete = operation
	case "patch":
		pathItem.Patch = operation
	case "head":
		pathItem.Head = operation
	case "options":
		pathItem.Options = operation
	}
}

// generateSchemaFromExample 从示例生成schema
func (r *Router) generateSchemaFromExample(example interface{}) *openapi3.SchemaRef {
	if example == nil {
		return nil
	}

	// 简化的schema生成逻辑
	return r.reflectToSchema(example)
}

// reflectToSchema 简化的反射schema生成
func (r *Router) reflectToSchema(v interface{}) *openapi3.SchemaRef {
	if v == nil {
		return nil
	}

	// 缓存key
	key := fmt.Sprintf("schema_%T", v)
	if r.cache != nil {
		if cached, exists := r.cache.Get(key); exists {
			if schemaRef, ok := cached.(*openapi3.SchemaRef); ok {
				return schemaRef
			}
		}
	}

	schema := r.typeToSchema(v)

	// 缓存结果
	if r.cache != nil {
		r.cache.Set(key, schema, 24*time.Hour)
	}

	return schema
}

// typeToSchema 类型到schema的转换
func (r *Router) typeToSchema(v interface{}) *openapi3.SchemaRef {
	if v == nil {
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"null"},
			},
		}
	}

	// 使用反射获取类型信息
	t := reflect.TypeOf(v)
	if t == nil {
		return nil
	}

	// 处理指针类型
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		if t == nil {
			return nil
		}
	}

	switch t.Kind() {
	case reflect.String:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"string"},
			},
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"integer"},
			},
		}
	case reflect.Float32, reflect.Float64:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"number"},
			},
		}
	case reflect.Bool:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"boolean"},
			},
		}
	case reflect.Slice, reflect.Array:
		itemSchema := r.typeToSchema(reflect.New(t.Elem()).Elem().Interface())
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type:  &openapi3.Types{"array"},
				Items: itemSchema,
			},
		}
	case reflect.Map:
		// 简化处理，假设是 map[string]interface{}
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"object"},
			},
		}
	case reflect.Struct:
		return r.structToSchema(t)
	default:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: &openapi3.Types{"object"},
			},
		}
	}
}

// structToSchema 结构体到schema的转换
func (r *Router) structToSchema(t reflect.Type) *openapi3.SchemaRef {
	schema := &openapi3.Schema{
		Type:       &openapi3.Types{"object"},
		Properties: make(openapi3.Schemas),
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// 跳过非导出字段
		if !field.IsExported() {
			continue
		}

		// 获取字段名称
		fieldName := field.Name
		if jsonTag := field.Tag.Get("json"); jsonTag != "" {
			if jsonTag == "-" {
				continue
			}
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		}

		// 生成字段schema
		fieldValue := reflect.New(field.Type).Elem().Interface()
		fieldSchema := r.typeToSchema(fieldValue)

		if fieldSchema != nil {
			schema.Properties[fieldName] = fieldSchema
		}
	}

	return &openapi3.SchemaRef{Value: schema}
}

// EnableSwagger 启用Swagger UI
func (r *Router) EnableSwagger(paths ...string) {
	if !r.config.OpenAPIEnabled {
		return
	}

	basePath := "/swagger"
	if len(paths) > 0 {
		basePath = paths[0]
	}

	// 创建自定义处理器来避免路径冲突
	swaggerHandler := func(c *gin.Context) {
		path := c.Request.URL.Path

		// 处理文档JSON请求
		if strings.HasSuffix(path, "/doc.json") {
			spec := r.GenerateOpenAPISpec()
			if spec == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "OpenAPI not enabled"})
				return
			}
			c.JSON(http.StatusOK, spec)
			return
		}

		// 处理其他Swagger UI请求
		ginSwagger.WrapHandler(swaggerFiles.Handler)(c)
	}

	// 注册Swagger路由组
	swaggerGroup := r.engine.Group(basePath)
	swaggerGroup.GET("/*any", swaggerHandler)
}

// InvalidateOpenAPICache 使OpenAPI缓存失效，强制重新生成
func (r *Router) InvalidateOpenAPICache() {
	r.mu.Lock()
	r.openapiSpec = nil
	r.mu.Unlock()
}

// ========== With* 链式调用支持 ==========

// WithTags 为RouterGroup设置默认标签
func (rg *RouterGroup) WithTags(tags ...string) *RouterGroup {
	newRG := &RouterGroup{
		group:      rg.group,
		basePath:   rg.basePath,
		router:     rg.router,
		handlers:   rg.handlers.Clone(),
		middleware: append([]HandlerFunc{}, rg.middleware...),
		// 复制现有标签并添加新标签
		defaultTags:     append(append([]string{}, rg.defaultTags...), tags...),
		defaultSecurity: append([]map[string][]string{}, rg.defaultSecurity...),
	}
	return newRG
}

// WithSecurity 为RouterGroup设置默认安全配置
func (rg *RouterGroup) WithSecurity(scheme string, scopes ...string) *RouterGroup {
	newRG := &RouterGroup{
		group:       rg.group,
		basePath:    rg.basePath,
		router:      rg.router,
		handlers:    rg.handlers.Clone(),
		middleware:  append([]HandlerFunc{}, rg.middleware...),
		defaultTags: append([]string{}, rg.defaultTags...),
		// 添加新的安全配置
		defaultSecurity: append(append([]map[string][]string{}, rg.defaultSecurity...),
			map[string][]string{scheme: scopes}),
	}
	return newRG
}

// WithMiddleware 为RouterGroup添加中间件（链式调用）
func (rg *RouterGroup) WithMiddleware(middleware ...HandlerFunc) *RouterGroup {
	newRG := &RouterGroup{
		group:           rg.group,
		basePath:        rg.basePath,
		router:          rg.router,
		handlers:        rg.handlers.Clone(),
		middleware:      append(append([]HandlerFunc{}, rg.middleware...), middleware...),
		defaultTags:     append([]string{}, rg.defaultTags...),
		defaultSecurity: append([]map[string][]string{}, rg.defaultSecurity...),
	}
	return newRG
}

// WithPrefix 创建带路径前缀的新RouterGroup
func (rg *RouterGroup) WithPrefix(prefix string) *RouterGroup {
	return rg.Group(prefix)
}

// GET 注册GET方法的路由
// 支持两种使用方式:
// 1. 传统方式: GET(path, handler, middleware...)
// 2. 文档方式: GET(path, handler, Summary("描述"), Response(200, User{}), middleware...)
func (r *Router) GET(path string, handler HandlerFunc, options ...interface{}) {
	r.httpMethodWithDoc(types.MethodGet, path, handler, options...)
}

// POST 注册POST方法的路由
func (r *Router) POST(path string, handler HandlerFunc, options ...interface{}) {
	r.httpMethodWithDoc(types.MethodPost, path, handler, options...)
}

// PUT 注册PUT方法的路由
func (r *Router) PUT(path string, handler HandlerFunc, options ...interface{}) {
	r.httpMethodWithDoc(types.MethodPut, path, handler, options...)
}

// DELETE 注册DELETE方法的路由
func (r *Router) DELETE(path string, handler HandlerFunc, options ...interface{}) {
	r.httpMethodWithDoc(types.MethodDelete, path, handler, options...)
}

// PATCH 注册PATCH方法的路由
func (r *Router) PATCH(path string, handler HandlerFunc, options ...interface{}) {
	r.httpMethodWithDoc(types.MethodPatch, path, handler, options...)
}

// HEAD 注册HEAD方法的路由
func (r *Router) HEAD(path string, handler HandlerFunc, options ...interface{}) {
	r.httpMethodWithDoc(types.MethodHead, path, handler, options...)
}

// OPTIONS 注册OPTIONS方法的路由
func (r *Router) OPTIONS(path string, handler HandlerFunc, options ...interface{}) {
	r.httpMethodWithDoc(types.MethodOptions, path, handler, options...)
}

// ANY 注册支持所有HTTP方法的路由
func (r *Router) ANY(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	// 注册所有 HTTP 方法
	methods := []string{
		types.MethodGet, types.MethodPost, types.MethodPut, types.MethodDelete,
		types.MethodPatch, types.MethodHead, types.MethodOptions, types.MethodConnect, types.MethodTrace,
	}
	for _, method := range methods {
		r.httpMethod(method, path, handler, middleware...)
	}
}

// Register 注册路由到当前组
func (rg *RouterGroup) Register(method, path string, handler HandlerFunc, middleware ...HandlerFunc) {
	// 正确计算一次完整路径
	fullPath := rg.calculatePath(path)

	// 使用新的路由模式验证功能
	if err := ValidateRoutePattern(method, fullPath); err != nil {
		rg.router.logger.Error("路由组路由注册失败 '%s %s' - %v", method, fullPath, err)
		return
	}

	// 解析路由模式以获取详细信息
	routePattern, err := ParseRoutePattern(method, fullPath)
	if err != nil {
		rg.router.logger.Error("路由组路由模式解析失败 '%s %s' - %v", method, fullPath, err)
		return
	}

	// 验证路由模式的完整性
	if err := routePattern.Validate(); err != nil {
		rg.router.logger.Error("路由组路由模式验证失败 '%s %s' - %v", method, fullPath, err)
		return
	}

	// 构建路由标识符用于冲突检测
	routeID := method + ":" + fullPath

	rg.router.mu.Lock()
	defer rg.router.mu.Unlock() // 使用defer确保锁一定会被释放

	// 确保handlers已初始化
	if rg.handlers == nil {
		rg.handlers = NewBasicHandler()
	}

	// 检测路由冲突 - 使用增强的冲突检测
	for existingRouteID := range rg.router.routes {
		parts := strings.SplitN(existingRouteID, ":", 2)
		if len(parts) == 2 {
			existingMethod, existingPath := parts[0], parts[1]
			if existingPattern, err := ParseRoutePattern(existingMethod, existingPath); err == nil {
				if routePattern.IsConflictWith(existingPattern) {
					rg.router.logger.Warn("路由组路由冲突检测 '%s %s' 与现有路由 '%s %s' 冲突，忽略注册",
						method, fullPath, existingMethod, existingPath)
					return
				}
			}
		}
	}

	// 检测完全相同的路由
	if _, exists := rg.router.routes[routeID]; exists {
		rg.router.logger.Warn("路由组中的路由 '%s %s' 已存在，忽略重复注册", method, fullPath)
		return
	}

	// 记录路由
	rg.router.routes[routeID] = true

	// 输出路由注册信息（包含段类型信息）
	if len(routePattern.ParamNames) > 0 || routePattern.IsWildcard {
		rg.router.logger.Info("注册路由组路由: %s %s (参数: %v, 通配符: %t, 优先级: %d)",
			method, fullPath, routePattern.ParamNames, routePattern.IsWildcard, routePattern.Priority)
	} else {
		rg.router.logger.Debug("注册路由组路由: %s %s", method, fullPath)
	}

	// 设置到组处理器
	rg.handlers.SetHandler(routeID, handler)

	// 合并中间件
	allMiddleware := make([]HandlerFunc, 0, len(rg.middleware)+len(middleware))
	allMiddleware = append(allMiddleware, rg.middleware...)
	allMiddleware = append(allMiddleware, middleware...)

	// 收集中间件和处理函数
	allHandlers := make([]gin.HandlerFunc, 0, len(allMiddleware)+1)

	// 转换所有中间件
	for _, m := range allMiddleware {
		allHandlers = append(allHandlers, rg.router.wrapHandlerWithRouter(m))
	}

	// 添加主处理函数
	allHandlers = append(allHandlers, rg.router.wrapHandlerWithRouter(handler))

	// 注册到 gin
	if rg.group != nil {
		// 使用path的相对路径，而不是fullPath，因为gin.RouterGroup已经知道自己的basePath
		rg.group.Handle(method, path, allHandlers...)
	} else {
		// 如果没有路由组，则直接注册到路由器
		rg.router.engine.Handle(method, fullPath, allHandlers...)
	}
}

// HTTP方法处理函数，减少重复代码
func (rg *RouterGroup) httpMethod(method string, path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(method, path, handler, middleware...)
}

// httpMethodWithDoc 带文档支持的HTTP方法处理函数（RouterGroup版本）
func (rg *RouterGroup) httpMethodWithDoc(method string, path string, handler HandlerFunc, options ...interface{}) {
	// 分离中间件和文档选项
	var middlewares []HandlerFunc
	var docOpts []DocOption

	for _, opt := range options {
		switch v := opt.(type) {
		case HandlerFunc:
			middlewares = append(middlewares, v)
		case DocOption:
			docOpts = append(docOpts, v)
		case []DocOption: // 支持批量传入
			docOpts = append(docOpts, v...)
		}
	}

	// 注册路由（原有逻辑）
	rg.Register(method, path, handler, middlewares...)

	// 记录API路由文档（新增逻辑）
	if len(docOpts) > 0 || len(rg.defaultTags) > 0 || len(rg.defaultSecurity) > 0 {
		// 计算完整路径用于文档
		fullPath := rg.calculatePath(path)

		// 添加默认标签和安全配置
		allDocOpts := make([]DocOption, 0, len(docOpts)+2)
		if len(rg.defaultTags) > 0 {
			allDocOpts = append(allDocOpts, Tags(rg.defaultTags...))
		}
		if len(rg.defaultSecurity) > 0 {
			for _, sec := range rg.defaultSecurity {
				for scheme, scopes := range sec {
					allDocOpts = append(allDocOpts, Security(scheme, scopes...))
				}
			}
		}
		allDocOpts = append(allDocOpts, docOpts...)

		rg.router.recordAPIRoute(method, fullPath, handler, allDocOpts...)
	}
}

// GET 注册GET方法的路由
// 支持两种使用方式:
// 1. 传统方式: GET(path, handler, middleware...)
// 2. 文档方式: GET(path, handler, Summary("描述"), Response(200, User{}), middleware...)
func (rg *RouterGroup) GET(path string, handler HandlerFunc, options ...interface{}) {
	rg.httpMethodWithDoc(types.MethodGet, path, handler, options...)
}

// POST 注册POST方法的路由
func (rg *RouterGroup) POST(path string, handler HandlerFunc, options ...interface{}) {
	rg.httpMethodWithDoc(types.MethodPost, path, handler, options...)
}

// PUT 注册PUT方法的路由
func (rg *RouterGroup) PUT(path string, handler HandlerFunc, options ...interface{}) {
	rg.httpMethodWithDoc(types.MethodPut, path, handler, options...)
}

// DELETE 注册DELETE方法的路由
func (rg *RouterGroup) DELETE(path string, handler HandlerFunc, options ...interface{}) {
	rg.httpMethodWithDoc(types.MethodDelete, path, handler, options...)
}

// PATCH 注册PATCH方法的路由
func (rg *RouterGroup) PATCH(path string, handler HandlerFunc, options ...interface{}) {
	rg.httpMethodWithDoc(types.MethodPatch, path, handler, options...)
}

// HEAD 注册HEAD方法的路由
func (rg *RouterGroup) HEAD(path string, handler HandlerFunc, options ...interface{}) {
	rg.httpMethodWithDoc(types.MethodHead, path, handler, options...)
}

// OPTIONS 注册OPTIONS方法的路由
func (rg *RouterGroup) OPTIONS(path string, handler HandlerFunc, options ...interface{}) {
	rg.httpMethodWithDoc(types.MethodOptions, path, handler, options...)
}

// ANY 注册支持所有HTTP方法的路由
func (rg *RouterGroup) ANY(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	methods := []string{
		types.MethodGet, types.MethodPost, types.MethodPut, types.MethodDelete,
		types.MethodPatch, types.MethodHead, types.MethodOptions, types.MethodConnect, types.MethodTrace,
	}
	for _, method := range methods {
		rg.httpMethod(method, path, handler, middleware...)
	}
}

// Group 创建子路由组
func (rg *RouterGroup) Group(path string, middleware ...HandlerFunc) *RouterGroup {
	// 正确计算子组路径，避免重复斜杠
	fullPath := rg.calculatePath(path)

	// 检查是否已存在该路由组
	rg.router.mu.RLock()
	if group, exists := rg.router.groups[fullPath]; exists {
		rg.router.mu.RUnlock()
		// 更新中间件
		if len(middleware) > 0 {
			group.middleware = append(group.middleware, middleware...)
		}
		return group
	}
	rg.router.mu.RUnlock()

	// 创建组级处理器
	groupHandler := rg.handlers.Clone()

	// 合并中间件
	combinedMiddleware := make([]HandlerFunc, len(rg.middleware)+len(middleware))
	copy(combinedMiddleware, rg.middleware)
	copy(combinedMiddleware[len(rg.middleware):], middleware)

	// 转换中间件
	handlers := make([]gin.HandlerFunc, len(combinedMiddleware))
	for i, m := range combinedMiddleware {
		handlers[i] = rg.router.wrapHandlerWithRouter(m)
	}

	// 使用正确计算的路径创建gin路由组
	group := rg.group.Group(path, handlers...)

	// 创建我们自己的路由组，保存完整路径
	newGroup := &RouterGroup{
		group:      group,
		basePath:   fullPath,
		router:     rg.router,
		handlers:   groupHandler,
		middleware: combinedMiddleware,
	}

	// 记录到映射表中
	rg.router.mu.Lock()
	rg.router.groups[fullPath] = newGroup
	rg.router.mu.Unlock()

	return newGroup
}

// calculatePath 改进路径计算方法，避免重复斜杠
func (rg *RouterGroup) calculatePath(path string) string {
	if path == "" {
		return rg.basePath
	}

	// 更简洁的路径组合逻辑
	basePath := strings.TrimSuffix(rg.basePath, "/")
	path = strings.TrimPrefix(path, "/")

	if basePath == "" {
		return "/" + path
	}

	return basePath + "/" + path
}

// wrapHandler 包装 gin.HandlerFunc
func wrapHandler(h HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.IsAborted() {
			return
		}
		if ctxVal, exists := c.Get("enhanced_context"); exists {
			if enhancedCtx, ok := ctxVal.(*Context); ok {
				h(enhancedCtx)
				return
			}
		}

		// 使用newContext创建上下文
		ctx := newContext(c)

		// 确保Context在函数结束时被释放回对象池
		defer releaseContext(ctx)

		// 调用处理函数
		h(ctx)
	}
}

// wrapHandlerWithRouter 包装 gin.HandlerFunc 并注入Router组件
func (r *Router) wrapHandlerWithRouter(h HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.IsAborted() {
			return
		}
		if ctxVal, exists := c.Get("enhanced_context"); exists {
			if enhancedCtx, ok := ctxVal.(*Context); ok {
				h(enhancedCtx)
				return
			}
		}

		// 使用newContext创建上下文
		ctx := newContext(c)

		// 确保Context在函数结束时被释放回对象池
		defer releaseContext(ctx)

		// 注入Router的组件
		r.mu.RLock()
		cache := r.cache
		sseHub := r.sseHub
		r.mu.RUnlock()
		if cache != nil {
			ctx.setGlobalCache(cache)
		}
		if sseHub != nil {
			ctx.SetSSEHub(sseHub)
		}

		// 调用处理函数
		h(ctx)
	}
}

// Use 添加中间件到路由器
func (r *Router) Use(middleware ...HandlerFunc) {
	r.middlewares = append(r.middlewares, middleware...)
	handlers := make([]gin.HandlerFunc, len(middleware))
	for i, m := range middleware {
		handlers[i] = wrapHandler(m)
	}
	r.engine.Use(handlers...)
}

// UseGin 直接使用 gin.HandlerFunc 类型的中间件
func (r *Router) UseGin(middleware ...gin.HandlerFunc) {
	r.engine.Use(middleware...)
}

// Use 添加中间件到路由组
func (rg *RouterGroup) Use(middleware ...HandlerFunc) {
	rg.middleware = append(rg.middleware, middleware...)
	handlers := make([]gin.HandlerFunc, len(middleware))
	for i, m := range middleware {
		handlers[i] = wrapHandler(m)
	}
	rg.group.Use(handlers...)
}

// UseGin 直接使用 gin.HandlerFunc 类型的中间件
func (rg *RouterGroup) UseGin(middleware ...gin.HandlerFunc) {
	rg.group.Use(middleware...)
}

// WithCache 返回一个缓存初始化中间件
// 该中间件会将指定缓存实例注入到每个请求的Context中
func (r *Router) WithCache(cache *cache.Cache[string, any]) HandlerFunc {
	// 设置路由器的缓存实例
	r.mu.Lock()
	r.cache = cache
	r.mu.Unlock()

	return func(c *Context) {
		// 将缓存实例注入到Context中
		c.setGlobalCache(cache)
		// 继续处理请求
		c.Next()
	}
}

// SetGlobalCacheMiddleware 返回一个缓存初始化中间件，会自动创建缓存实例
//
// 参数:
//   - defaultExpiration: 缓存项默认过期时间
//   - cleanupInterval: 清理过期项的时间间隔
func (r *Router) SetGlobalCacheMiddleware(defaultExpiration, cleanupInterval time.Duration) HandlerFunc {
	return r.WithCache(cache.NewCache[string, any](defaultExpiration, cleanupInterval))
}

// SetPersistCacheMiddleware 返回一个带持久化功能的缓存初始化中间件
//
// 参数:
//   - defaultExpiration: 缓存项默认过期时间
//   - cleanupInterval: 清理过期项的时间间隔
//   - persistPath: 持久化文件路径
//   - autoPersistInterval: 自动持久化时间间隔
func (r *Router) SetPersistCacheMiddleware(defaultExpiration, cleanupInterval time.Duration, persistPath string, autoPersistInterval time.Duration) HandlerFunc {
	// 创建带持久化功能的全局缓存实例
	cache := cache.NewCache[string, any](defaultExpiration, cleanupInterval).WithPersistence(persistPath, autoPersistInterval)

	// 启用自动持久化
	cache.EnableAutoPersist()

	// 返回中间件函数
	return r.WithCache(cache)
}

// Run 启动服务器，支持优雅停机
func (r *Router) Run(addr ...string) error {
	config := DefaultServerConfig()

	if len(addr) > 0 {
		parts := strings.Split(addr[0], ":")
		if len(parts) == 2 {
			config.Host = parts[0]
			config.Port = parts[1]
		} else {
			config.Port = addr[0]
		}
	}

	// 启动服务器
	serverAddr := config.Host + ":" + config.Port
	return r.engine.Run(serverAddr)
}

// Engine 获取原始 gin.Engine
func (r *Router) Engine() *gin.Engine {
	return r.engine
}

// Close 关闭路由器和相关资源
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 关闭缓存（如果存在）
	if r.cache != nil {
		r.cache.Close()
		r.cache = nil
	}

	// 关闭SSE Hub（如果存在）
	if r.sseHub != nil {
		r.sseHub.Close()
		r.sseHub = nil
	}

	// 清理路由组
	r.groups = make(map[string]*RouterGroup)
	r.routes = make(map[string]bool)

	return nil
}

// NewSSEHub 创建新的 SSE Hub
//
// size 设置历史记录大小
func (r *Router) NewSSEHub(size ...int) *sse.Hub {
	var config *sse.Config
	if len(size) > 0 && size[0] > 0 {
		config = &sse.Config{
			HistorySize: size[0],
		}
	}

	r.mu.Lock()
	r.sseHub = sse.NewHub(config)
	r.mu.Unlock()

	return r.sseHub
}

// GetRoutes 获取所有已注册的路由
func (r *Router) GetRoutes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]string, 0, len(r.routes))
	for route := range r.routes {
		routes = append(routes, route)
	}
	return routes
}

// Resource 注册 RESTful 资源路由
func (r *Router) Resource(path string, handler ResourceHandler, middleware ...HandlerFunc) {
	r.REST(path, handler, RESTWithMiddleware(middleware...))
}

// CRUD 注册完整的 CRUD 资源路由（编译期校验 ResourceHandler）
// 等价于 REST(resource, handler, opts...)
func (r *Router) CRUD(resource string, handler ResourceHandler, opts ...RESTOption) {
	r.REST(resource, handler, opts...)
}

// REST 注册带自定义选项的 REST 风格路由
func (r *Router) REST(resource string, handler ResourceHandler, opts ...RESTOption) {
	cfg := newRESTConfig(resource)
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	cfg.registerWithRouter(r, handler)
}

// API 快捷方法 - 创建API版本路由组
func (r *Router) API(version string) *RouterGroup {
	return r.Group("/api/" + version)
}

// Health 添加健康检查端点
func (r *Router) Health(path ...string) {
	healthPath := "/health"
	if len(path) > 0 {
		healthPath = path[0]
	}

	r.GET(healthPath, func(c *Context) {
		c.JSON(http.StatusOK, H{
			"status":    "ok",
			"timestamp": time.Now().Unix(),
			"uptime":    time.Since(startTime).Seconds(),
		})
	})
}

// Metrics 添加指标端点
func (r *Router) Metrics(path ...string) {
	metricsPath := "/metrics"
	if len(path) > 0 {
		metricsPath = path[0]
	}

	r.GET(metricsPath, func(c *Context) {
		stats := r.getRouterStats()
		c.JSON(http.StatusOK, stats)
	})
}

// Static 静态文件服务增强
func (r *Router) StaticFiles(relativePath, root string, middleware ...HandlerFunc) {
	var handlers []gin.HandlerFunc
	for _, m := range middleware {
		handlers = append(handlers, wrapHandler(m))
	}

	group := r.engine.Group("", handlers...)
	group.Static(relativePath, root)
}

// Upload 文件上传路由
func (r *Router) Upload(path string, handler func(*Context, *multipart.FileHeader) error, middleware ...HandlerFunc) {
	uploadHandler := func(c *Context) {
		// 限制单文件默认最大 10MB，防止大文件占满内存；如需更大可在业务 handler 前自定义中间件覆盖
		const maxSize = 10 << 20
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)

		file, err := c.FormFile("file")
		if err != nil {
			c.ValidationError(H{"file": "文件上传失败: " + err.Error()})
			return
		}

		if file.Size > maxSize {
			c.ValidationError(H{"file": "文件过大，最大10MB"})
			return
		}

		if err := handler(c, file); err != nil {
			c.Error("文件处理失败: " + err.Error())
			return
		}

		c.Success(H{"filename": file.Filename, "size": file.Size})
	}

	// 将中间件转换为interface{}切片
	options := toInterfaceSlice(middleware)

	r.POST(path, uploadHandler, options...)
}

// OAuth 添加OAuth认证路由
func (r *Router) OAuth(basePath ...string) {
	path := "/oauth"
	if len(basePath) > 0 {
		path = basePath[0]
	}

	// 登录端点 - 生成令牌
	r.POST(path+"/token", func(c *Context) {
		var loginReq struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
			Scope    string `json:"scope,omitempty"`
		}

		if err := c.ShouldBindJSON(&loginReq); err != nil {
			c.ValidationError(H{"error": "请求参数错误: " + err.Error()})
			return
		}

		// 这里应该验证用户凭据，实际应用中需要连接数据库
		// 为演示目的，这里简化处理
		if loginReq.Username == "" || loginReq.Password == "" {
			c.Unauthorized("用户名或密码不能为空")
			return
		}

		// 模拟用户验证成功，创建用户声明
		userClaims := UserClaims{
			UserID:   "user_" + loginReq.Username,
			Username: loginReq.Username,
			Email:    loginReq.Username + "@example.com",
			Roles:    []string{"user"},
			Scope:    loginReq.Scope,
		}

		// 生成令牌对
		tokens, err := c.GenerateTokens(userClaims)
		if err != nil {
			c.ServerError("生成令牌失败: " + err.Error())
			return
		}

		c.Success(tokens)
	})

	// 刷新令牌端点
	r.POST(path+"/refresh", func(c *Context) {
		var refreshReq RefreshRequest

		if err := c.ShouldBindJSON(&refreshReq); err != nil {
			c.ValidationError(H{"error": "请求参数错误: " + err.Error()})
			return
		}

		// 刷新令牌
		tokens, err := c.RefreshTokens(refreshReq.RefreshToken)
		if err != nil {
			c.Unauthorized("刷新令牌失败: " + err.Error())
			return
		}

		c.Success(tokens)
	})

	// 令牌信息端点（需要认证）
	r.GET(path+"/userinfo", func(c *Context) {
		// 获取当前用户信息（需要先经过JWT中间件验证）
		payload := c.GetJWTPayload()
		if payload == nil {
			c.Unauthorized("未找到有效的令牌")
			return
		}

		userInfo := H{
			"user_id":  payload["user_id"],
			"username": payload["username"],
			"email":    payload["email"],
			"roles":    payload["roles"],
			"scope":    payload["scope"],
			"iss":      payload[ClaimIss],
			"exp":      payload[ClaimExp],
			"iat":      payload[ClaimIat],
		}

		c.Success(userInfo)
	}, r.RequireAuth())

	// 注销端点（可选实现）
	r.POST(path+"/revoke", func(c *Context) {
		var revokeReq struct {
			Token string `json:"token" binding:"required"`
		}

		if err := c.ShouldBindJSON(&revokeReq); err != nil {
			c.ValidationError(H{"error": "请求参数错误: " + err.Error()})
			return
		}

		// 这里实现真正的令牌撤销功能
		jwtAdapter := c.getJWTAdapter()
		if jwtAdapter == nil {
			c.ServerError("JWT适配器未初始化")
			return
		}

		// 验证并撤销令牌
		payload, err := jwtAdapter.ValidateToken(revokeReq.Token)
		if err != nil {
			c.ValidationError(H{"error": "无效的令牌: " + err.Error()})
			return
		}

		// 获取JTI和过期时间
		jti, _ := payload.GetClaim(ClaimJti)
		exp, _ := payload.GetClaim(ClaimExp)

		if jtiStr, ok := jti.(string); ok && jtiStr != "" {
			var expirationTime time.Time

			// 处理过期时间
			switch expVal := exp.(type) {
			case float64:
				expirationTime = time.Unix(int64(expVal), 0)
			case int64:
				expirationTime = time.Unix(expVal, 0)
			case int:
				expirationTime = time.Unix(int64(expVal), 0)
			default:
				// 如果无法获取过期时间，使用默认值（7天后）
				expirationTime = time.Now().Add(7 * 24 * time.Hour)
			}

			// 撤销令牌
			if err := jwtAdapter.RevokeToken(jtiStr, expirationTime); err != nil {
				c.ServerError("撤销令牌失败: " + err.Error())
				return
			}

			c.Success(H{
				"message":    "令牌已成功撤销",
				"jti":        jtiStr,
				"revoked_at": time.Now().Unix(),
			})
		} else {
			c.ValidationError(H{"error": "令牌缺少JTI字段"})
		}
	})
}

// RequireAuth 创建需要OAuth认证的中间件
func (r *Router) RequireAuth(scopes ...string) HandlerFunc {
	return func(c *Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Header("WWW-Authenticate", "Bearer")
			c.Unauthorized("缺少Authorization头")
			return
		}

		// 检查Bearer格式
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.Header("WWW-Authenticate", "Bearer")
			c.Unauthorized("Authorization头格式错误")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.Header("WWW-Authenticate", "Bearer")
			c.Unauthorized("令牌不能为空")
			return
		}

		// 验证令牌
		jwtAdapter := c.getJWTAdapter()
		if jwtAdapter == nil {
			c.ServerError("JWT适配器未初始化")
			return
		}

		payload, err := jwtAdapter.ValidateToken(token)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer")
			c.Unauthorized("令牌无效: " + err.Error())
			return
		}

		// 检查令牌是否已被撤销
		jti, _ := payload.GetClaim(ClaimJti)
		if jtiStr, ok := jti.(string); ok && jtiStr != "" {
			if jwtAdapter.IsTokenRevoked(jtiStr) {
				c.Header("WWW-Authenticate", "Bearer")
				c.Unauthorized("令牌已被撤销")
				return
			}
		}

		// 检查令牌类型（确保是访问令牌）
		tokenType, _ := payload.GetClaim(ClaimType)
		tokenTypeStr, _ := tokenType.(string)
		if tokenTypeStr != TokenTypeAccess {
			c.Header("WWW-Authenticate", "Bearer")
			c.Unauthorized("令牌类型错误")
			return
		}

		// 检查权限范围（如果指定了）
		if len(scopes) > 0 {
			scope, _ := payload.GetClaim("scope")
			tokenScope, _ := scope.(string)
			if !hasRequiredScope(tokenScope, scopes) {
				c.Forbidden("权限不足")
				return
			}
		}

		// 将载荷存储到上下文中
		c.SetJWTPayload(payload)

		c.Next()
	}
}

// RequireRoles 要求当前用户同时具备指定角色
func (r *Router) RequireRoles(roles ...string) HandlerFunc {
	return func(c *Context) {
		if len(roles) == 0 {
			c.Next()
			return
		}
		if !c.HasAllRoles(roles...) {
			c.Forbidden("需要具备指定角色")
			return
		}
		c.Next()
	}
}

// RequireAnyRole 允许用户具备任意一个角色即可通过
func (r *Router) RequireAnyRole(roles ...string) HandlerFunc {
	return func(c *Context) {
		if len(roles) == 0 {
			c.Next()
			return
		}
		if !c.HasAnyRole(roles...) {
			c.Forbidden("需要满足任意一个角色")
			return
		}
		c.Next()
	}
}

// hasRequiredScope 检查是否有必需的权限
func hasRequiredScope(tokenScope string, requiredScopes []string) bool {
	if tokenScope == "" {
		return false
	}

	tokenScopes := strings.Fields(tokenScope)
	for _, required := range requiredScopes {
		found := false
		for _, scope := range tokenScopes {
			if scope == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Resource 注册路由组内的 RESTful 资源路由
func (rg *RouterGroup) Resource(path string, handler ResourceHandler, middleware ...HandlerFunc) {
	rg.REST(path, handler, RESTWithMiddleware(middleware...))
}

// REST 在路由组中注册 REST 风格路由
func (rg *RouterGroup) REST(resource string, handler ResourceHandler, opts ...RESTOption) {
	cfg := newRESTConfig(resource)
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	cfg.registerWithGroup(rg, handler)
}

// GetHandler 获取路由器的处理器
func (r *Router) GetHandler() Handler {
	return r.handlers
}

// GetHandler 获取路由组的处理器
func (rg *RouterGroup) GetHandler() Handler {
	return rg.handlers
}

// RestfulHandler 提供 ResourceHandler 接口的默认实现
type RestfulHandler struct{}

// Index 获取资源列表
func (h *RestfulHandler) Index(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

// Show 获取资源详情
func (h *RestfulHandler) Show(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

// Create 创建资源
func (h *RestfulHandler) Create(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

// Update 更新资源
func (h *RestfulHandler) Update(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

// Delete 删除资源
func (h *RestfulHandler) Delete(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

// GetSSEHub 获取SSE中心
func (r *Router) GetSSEHub() *sse.Hub {
	return r.sseHub
}

// getRouterStats 获取路由器统计信息
func (r *Router) getRouterStats() H {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return H{
		"total_routes":   len(r.routes),
		"total_groups":   len(r.groups),
		"uptime_seconds": time.Since(startTime).Seconds(),
		"gin_mode":       gin.Mode(),
		"routes":         r.GetRoutes(),
	}
}

// SetEmbed 设置嵌入式文件系统静态资源服务
// urlPrefix: URL路径前缀，如 "/static" 或 "/assets"
// embedFS: embed.FS 文件系统
// subPaths: 可选的子路径，用于移除embed.FS中的路径前缀
//
// 使用示例:
//
//	//go:embed static/*
//	var staticFS embed.FS
//	router.SetEmbed("/static", staticFS, "static")
func (r *Router) SetEmbed(urlPrefix string, embedFS embed.FS, subPaths ...string) error {
	// 参数验证
	if urlPrefix == "" {
		return fmt.Errorf("URL前缀不能为空")
	}

	// 确保URL前缀以/开头
	if !strings.HasPrefix(urlPrefix, "/") {
		urlPrefix = "/" + urlPrefix
	}

	// 移除末尾的斜杠
	urlPrefix = strings.TrimSuffix(urlPrefix, "/")

	var fileSystem http.FileSystem

	// 处理子路径前缀移除
	if len(subPaths) > 0 && subPaths[0] != "" {
		subPath := strings.Trim(subPaths[0], "/")
		// 创建子文件系统，移除指定前缀
		subFS, err := fs.Sub(embedFS, subPath)
		if err != nil {
			return fmt.Errorf("无法创建子文件系统: %v", err)
		}
		fileSystem = http.FS(subFS)
		r.logger.Debug("设置嵌入式文件系统: %s -> embed.FS/%s", urlPrefix, subPath)
	} else {
		fileSystem = http.FS(embedFS)
		r.logger.Debug("设置嵌入式文件系统: %s -> embed.FS", urlPrefix)
	}

	// 注册静态文件服务
	r.engine.StaticFS(urlPrefix, fileSystem)

	// 记录路由
	r.mu.Lock()
	if r.routes == nil {
		r.routes = make(map[string]bool)
	}
	r.routes["STATIC "+urlPrefix+"/*filepath"] = true
	r.mu.Unlock()

	return nil
}

// SetEmbedFile 设置单个嵌入文件的路由
// urlPath: URL路径，如 "/favicon.ico"
// embedFS: embed.FS 文件系统
// filePath: 文件在embed.FS中的路径
//
// 使用示例:
//
//	//go:embed favicon.ico
//	var faviconFS embed.FS
//	router.SetEmbedFile("/favicon.ico", faviconFS, "favicon.ico")
func (r *Router) SetEmbedFile(urlPath string, embedFS embed.FS, filePath string) error {
	// 参数验证
	if urlPath == "" || filePath == "" {
		return fmt.Errorf("URL路径和文件路径不能为空")
	}

	// 确保URL路径以/开头
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}

	// 注册单文件路由
	r.engine.GET(urlPath, func(c *gin.Context) {
		// 读取嵌入文件
		data, err := embedFS.ReadFile(filePath)
		if err != nil {
			c.String(http.StatusNotFound, "文件未找到")
			return
		}

		// 根据文件扩展名设置Content-Type，使用标准mime包
		contentType := mime.TypeByExtension(path.Ext(filePath))
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		c.Header("Content-Type", contentType)
		c.Data(http.StatusOK, contentType, data)
	})

	// 记录路由
	r.mu.Lock()
	if r.routes == nil {
		r.routes = make(map[string]bool)
	}
	r.routes["GET "+urlPath] = true
	r.mu.Unlock()

	r.logger.Debug("设置嵌入式文件: %s -> %s", urlPath, filePath)

	return nil
}

// ========== Zip文件系统集成方法 ==========

// SetZipFS 设置zip文件系统静态资源服务
// zipPath: zip文件路径
// urlPrefix: URL路径前缀，如 "/static" 或 "/app"
// options: 可选配置项
//
// 使用示例:
//
//	router.SetZipFS("./web.zip", "/app", WithHotReload(5*time.Second))
//	router.SetZipFS("./assets.zip", "/static", WithIndexFile("main.html"))
func (r *Router) SetZipFS(zipPath, urlPrefix string, options ...func(*ZipFSConfig)) error {
	// 创建配置
	config := NewZipFSConfig(zipPath, urlPrefix, options...)

	// 创建zip文件系统
	zfs, err := NewZipFileSystem(config)
	if err != nil {
		return fmt.Errorf("创建zip文件系统失败: %w", err)
	}

	// 启动热更新（如果启用）
	if config.HotReload {
		zfs.StartHotReload()
	}

	// 注册路由处理器
	pattern := config.URLPrefix + "/*filepath"
	r.engine.GET(pattern, func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 记录路由
	r.mu.Lock()
	if r.routes == nil {
		r.routes = make(map[string]bool)
	}
	r.routes["GET "+pattern] = true
	r.mu.Unlock()

	r.logger.Debug("设置zip文件系统: %s -> %s", config.URLPrefix, config.ZipPath)
	return nil
}

// SetZipFile 设置单个zip文件的路由服务
// urlPath: URL路径，如 "/api/docs"
// zipPath: zip文件路径
// filePath: 文件在zip中的路径
// options: 可选配置项
//
// 使用示例:
//
//	router.SetZipFile("/api.json", "./docs.zip", "api.json", WithFileHotReload(3*time.Second))
//	router.SetZipFile("/favicon.ico", "./assets.zip", "favicon.ico")
func (r *Router) SetZipFile(urlPath, zipPath, filePath string, options ...ZipFileOption) error {
	// 参数验证
	if urlPath == "" || zipPath == "" || filePath == "" {
		return fmt.Errorf("URL路径、zip文件路径和文件路径不能为空")
	}

	// 确保URL路径以/开头
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}

	// 创建配置
	config := &ZipFileConfig{
		CheckInterval: 3 * time.Second,
	}
	for _, opt := range options {
		opt(config)
	}

	// 创建zip文件管理器
	zf, err := NewZipFile(zipPath, filePath, config)
	if err != nil {
		return fmt.Errorf("创建zip文件管理器失败: %w", err)
	}

	// 启动热更新（如果启用）
	if config.HotReload {
		zf.StartHotReload()
	}

	// 注册路由
	r.engine.GET(urlPath, func(c *gin.Context) {
		zf.ServeHTTP(c)
	})

	// 记录路由
	r.mu.Lock()
	if r.routes == nil {
		r.routes = make(map[string]bool)
	}
	r.routes["GET "+urlPath] = true
	r.mu.Unlock()

	r.logger.Debug("设置zip文件: %s -> %s/%s", urlPath, zipPath, filePath)
	return nil
}

// SetZipFSWithMiddleware 设置带中间件的zip文件系统服务
// config: zip文件系统配置
// middlewares: 中间件列表
//
// 使用示例:
//
//	config := NewZipFSConfig("./app.zip", "/app", WithHotReload(3*time.Second))
//	router.SetZipFSWithMiddleware(config, corsMiddleware(), authMiddleware())
func (r *Router) SetZipFSWithMiddleware(config ZipFSConfig, middlewares ...gin.HandlerFunc) error {
	// 创建zip文件系统
	zfs, err := NewZipFileSystem(config)
	if err != nil {
		return fmt.Errorf("创建zip文件系统失败: %w", err)
	}

	// 启动热更新（如果启用）
	if config.HotReload {
		zfs.StartHotReload()
	}

	// 创建路由组并应用中间件
	group := r.engine.Group(config.URLPrefix)
	group.Use(middlewares...)

	// 注册通配符路由
	group.GET("/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 记录路由
	pattern := config.URLPrefix + "/*filepath"
	r.mu.Lock()
	if r.routes == nil {
		r.routes = make(map[string]bool)
	}
	r.routes["GET "+pattern+" (with middleware)"] = true
	r.mu.Unlock()

	r.logger.Debug("设置带中间件的zip文件系统: %s -> %s", config.URLPrefix, config.ZipPath)
	return nil
}

// ========== RouterGroup Zip文件系统集成方法 ==========

// SetZipFS 为路由组设置zip文件系统静态资源服务
func (rg *RouterGroup) SetZipFS(zipPath string, options ...func(*ZipFSConfig)) error {
	// 创建配置，使用路由组的basePath作为URLPrefix
	config := NewZipFSConfig(zipPath, rg.basePath, options...)

	// 创建zip文件系统
	zfs, err := NewZipFileSystem(config)
	if err != nil {
		return fmt.Errorf("创建zip文件系统失败: %w", err)
	}

	// 启动热更新（如果启用）
	if config.HotReload {
		zfs.StartHotReload()
	}

	// 注册路由处理器到路由组
	rg.group.GET("/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 记录路由
	fullPath := rg.calculatePath("/*filepath")
	rg.router.mu.Lock()
	if rg.router.routes == nil {
		rg.router.routes = make(map[string]bool)
	}
	rg.router.routes["GET "+fullPath] = true
	rg.router.mu.Unlock()

	rg.router.logger.Debug("路由组设置zip文件系统: %s -> %s", config.URLPrefix, config.ZipPath)
	return nil
}

// SetZipFile 为路由组设置单个zip文件的路由服务
func (rg *RouterGroup) SetZipFile(urlPath, zipPath, filePath string, options ...ZipFileOption) error {
	// 参数验证
	if urlPath == "" || zipPath == "" || filePath == "" {
		return fmt.Errorf("URL路径、zip文件路径和文件路径不能为空")
	}

	// 创建配置
	config := &ZipFileConfig{
		CheckInterval: 3 * time.Second,
	}
	for _, opt := range options {
		opt(config)
	}

	// 创建zip文件管理器
	zf, err := NewZipFile(zipPath, filePath, config)
	if err != nil {
		return fmt.Errorf("创建zip文件管理器失败: %w", err)
	}

	// 启动热更新（如果启用）
	if config.HotReload {
		zf.StartHotReload()
	}

	// 注册路由到路由组
	rg.group.GET(urlPath, func(c *gin.Context) {
		zf.ServeHTTP(c)
	})

	// 记录路由
	fullPath := rg.calculatePath(urlPath)
	rg.router.mu.Lock()
	if rg.router.routes == nil {
		rg.router.routes = make(map[string]bool)
	}
	rg.router.routes["GET "+fullPath] = true
	rg.router.mu.Unlock()

	rg.router.logger.Debug("路由组设置zip文件: %s -> %s/%s", fullPath, zipPath, filePath)
	return nil
}

// SetZipFSWithMiddleware 为路由组设置带中间件的zip文件系统服务
func (rg *RouterGroup) SetZipFSWithMiddleware(zipPath string, middlewares []gin.HandlerFunc, options ...func(*ZipFSConfig)) error {
	// 创建配置
	config := NewZipFSConfig(zipPath, rg.basePath, options...)

	// 创建zip文件系统
	zfs, err := NewZipFileSystem(config)
	if err != nil {
		return fmt.Errorf("创建zip文件系统失败: %w", err)
	}

	// 启动热更新（如果启用）
	if config.HotReload {
		zfs.StartHotReload()
	}

	// 创建子路由组并应用中间件
	subGroup := rg.group.Group("", middlewares...)

	// 注册通配符路由
	subGroup.GET("/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 记录路由
	fullPath := rg.calculatePath("/*filepath")
	rg.router.mu.Lock()
	if rg.router.routes == nil {
		rg.router.routes = make(map[string]bool)
	}
	rg.router.routes["GET "+fullPath+" (with middleware)"] = true
	rg.router.mu.Unlock()

	rg.router.logger.Debug("路由组设置带中间件的zip文件系统: %s -> %s", config.URLPrefix, config.ZipPath)
	return nil
}
