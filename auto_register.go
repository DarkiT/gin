// Package gin 提供基于 Gin 的增强上下文与路由扩展能力。
package gin

import (
	"net/http"
	"reflect"
	"strings"
	"sync"

	ggin "github.com/gin-gonic/gin"
)

// ==================== 接口定义 ====================

// AutoController 定义自动注册控制器接口，用于自定义路由前缀。
type AutoController interface {
	RoutePrefix() string
}

// RegexPatternProvider 定义正则路由模式提供者接口。
type RegexPatternProvider interface {
	// RegexPatterns 返回方法名到完整 Chi 风格路径的映射
	// 键: 方法名（如 "GetUserIDRegex"）
	// 值: 完整路径（如 "/user/{id:[0-9]+}"）
	RegexPatterns() map[string]string
}

// ==================== 选项定义 ====================

// AutoOption 定义自动注册选项函数。
type AutoOption func(*autoOptions)

type autoOptions struct {
	prefix        string
	middleware    []any
	regexPatterns map[string]string // 正则路由路径覆盖
}

// WithPrefix 设置自动注册的路由前缀。
func WithPrefix(prefix string) AutoOption {
	return func(o *autoOptions) {
		o.prefix = prefix
	}
}

// WithMiddleware 设置自动注册时应用的中间件。
func WithMiddleware(middleware ...any) AutoOption {
	return func(o *autoOptions) {
		o.middleware = append(o.middleware, middleware...)
	}
}

// WithRegexPattern 设置特定方法的正则路由路径。
// methodName 为方法名（如 "GetUserIDRegex"），pattern 为完整 Chi 风格路径。
func WithRegexPattern(methodName, pattern string) AutoOption {
	return func(o *autoOptions) {
		if o.regexPatterns == nil {
			o.regexPatterns = make(map[string]string)
		}
		o.regexPatterns[methodName] = pattern
	}
}

// ==================== 默认正则模式 ====================

// defaultRegexPatterns 定义常见参数名的默认正则模式。
var defaultRegexPatterns = map[string]string{
	"id":      "[0-9]+",
	"uuid":    "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
	"slug":    "[a-z0-9-]+",
	"year":    "[0-9]{4}",
	"month":   "[0-9]{2}",
	"day":     "[0-9]{2}",
	"version": "[0-9]+",
	"name":    "[a-zA-Z0-9_-]+",
}

// ==================== 路由缓存 ====================

// routeCache 缓存控制器方法到路由的解析结果。
var routeCache = struct {
	sync.RWMutex
	entries map[reflect.Type][]cachedRoute
}{entries: make(map[reflect.Type][]cachedRoute)}

type cachedRoute struct {
	methodName string        // 原始方法名
	httpMethod string        // HTTP 方法
	path       string        // 推断的路径
	handler    reflect.Value // 方法反射值
	isRegex    bool          // 是否正则路由
}

// ==================== 核心实现 ====================

// AutoRegister 自动注册控制器到路由。
//
// 用法:
//
//	type Hello struct{}
//	func (h *Hello) GetTest(c *Context) { c.Success(H{"msg": "test"}) }
//	r.AutoRegister(&Hello{})  // 注册 GET /hello/test
//
// 方法命名规则:
//   - GetXxx    → GET /xxx
//   - PostXxx   → POST /xxx
//   - PutXxx    → PUT /xxx
//   - DeleteXxx → DELETE /xxx
//   - PatchXxx  → PATCH /xxx
//   - HeadXxx   → HEAD /xxx
//   - OptionsXxx → OPTIONS /xxx
//   - AnyXxx    → ANY /xxx
//
// 正则路由:
//   - 方法名以 Regex 结尾 → 注册到 RegexRouter
//   - GetUserIDRegex → GET /user/{id:[0-9]+}
//
// 自定义正则模式:
//  1. 实现 RegexPatternProvider 接口（控制器级）
//  2. 使用 WithRegexPattern 选项（注册时）
//  3. 使用默认推断（回退）
func (r *Router) AutoRegister(ctrl any, opts ...AutoOption) {
	options := &autoOptions{}
	for _, opt := range opts {
		opt(options)
	}

	ctrlType := reflect.TypeOf(ctrl)
	ctrlValue := reflect.ValueOf(ctrl)

	if ctrlType.Kind() != reflect.Pointer {
		panic("AutoRegister: controller must be a pointer")
	}

	// 获取或创建路由缓存
	routes := getOrCreateRoutes(ctrlType, ctrlValue)

	// 标准路由使用相对路径注册到当前 RouterGroup，正则路由需要补齐当前 Router 的 BasePath。
	basePath := getBasePath(ctrl, ctrlType, options)
	regexBasePath := joinRoutePaths(r.BasePath(), basePath)

	// 应用中间件
	var targetRouter *Router
	if len(options.middleware) > 0 {
		targetRouter = r.Group(basePath)
		targetRouter.UseAny(options.middleware...)
		basePath = ""
	} else {
		targetRouter = r
	}

	// 预热正则路由器,确保 NoRoute 已绑定
	var regexTarget *RegexRouter
	if hasRegexRoutes(routes) {
		r.engine.RegexRouter()
		regexTarget = buildRegexRouterTarget(r, options.middleware)
	}

	// 注册路由
	for _, route := range routes {
		fullPath := joinRoutePaths(basePath, route.path)
		handler := createHandler(route.handler)

		if route.isRegex {
			// 解析正则路由路径（按优先级）
			regexPath := resolveRegexPath(ctrl, route.methodName, joinRoutePaths(regexBasePath, route.path), options)
			// 注册到 RegexRouter
			regexTarget.Handle(route.httpMethod, regexPath, handler)
		} else {
			// 注册到标准路由
			registerRoute(targetRouter, route.httpMethod, fullPath, handler)
		}
	}
}

// hasRegexRoutes 判断是否包含正则路由。
func hasRegexRoutes(routes []cachedRoute) bool {
	for _, route := range routes {
		if route.isRegex {
			return true
		}
	}
	return false
}

// resolveRegexPath 解析正则路由路径，优先级为选项 > 接口 > 默认推断。
func resolveRegexPath(ctrl any, methodName, inferredPath string, opts *autoOptions) string {
	// 1. 检查注册选项（最高优先级）
	if opts.regexPatterns != nil {
		if pattern, ok := opts.regexPatterns[methodName]; ok {
			return pattern
		}
	}

	// 2. 检查接口实现
	if provider, ok := ctrl.(RegexPatternProvider); ok {
		patterns := provider.RegexPatterns()
		if pattern, ok := patterns[methodName]; ok {
			return pattern
		}
	}

	// 3. 使用默认推断
	return inferRegexPath(inferredPath)
}

// inferRegexPath 默认路径推断，将最后一个路径段转换为正则参数。
func inferRegexPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return path
	}

	lastPart := parts[len(parts)-1]

	// 查找匹配的默认模式
	for paramName, pattern := range defaultRegexPatterns {
		if strings.EqualFold(lastPart, paramName) {
			parts[len(parts)-1] = "{" + lastPart + ":" + pattern + "}"
			return "/" + strings.Join(parts, "/")
		}
	}

	// 默认使用通用模式
	parts[len(parts)-1] = "{" + lastPart + ":[^/]+}"
	return "/" + strings.Join(parts, "/")
}

// joinRoutePaths 拼接路由路径，避免重复或缺失斜杠。
func joinRoutePaths(parts ...string) string {
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" || trimmed == "/" {
			continue
		}
		segments = append(segments, strings.Trim(trimmed, "/"))
	}
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}

// ==================== 辅助函数 ====================

// getOrCreateRoutes 获取或创建控制器的路由缓存。
func getOrCreateRoutes(ctrlType reflect.Type, ctrlValue reflect.Value) []cachedRoute {
	routeCache.RLock()
	if routes, ok := routeCache.entries[ctrlType]; ok {
		routeCache.RUnlock()
		return routes
	}
	routeCache.RUnlock()

	routeCache.Lock()
	defer routeCache.Unlock()

	// 双重检查
	if routes, ok := routeCache.entries[ctrlType]; ok {
		return routes
	}

	// 扫描方法
	routes := scanControllerMethods(ctrlType, ctrlValue)
	routeCache.entries[ctrlType] = routes
	return routes
}

// scanControllerMethods 扫描控制器方法并生成路由列表。
func scanControllerMethods(ctrlType reflect.Type, ctrlValue reflect.Value) []cachedRoute {
	var routes []cachedRoute

	for i := 0; i < ctrlType.NumMethod(); i++ {
		method := ctrlType.Method(i)
		httpMethod, path, isRegex := parseMethodName(method.Name)

		if httpMethod == "" {
			continue
		}

		routes = append(routes, cachedRoute{
			methodName: method.Name,
			httpMethod: httpMethod,
			path:       path,
			handler:    ctrlValue.Method(i),
			isRegex:    isRegex,
		})
	}

	return routes
}

// getBasePath 计算控制器基础路径。
func getBasePath(ctrl any, ctrlType reflect.Type, options *autoOptions) string {
	// 优先使用选项中的前缀
	if options.prefix != "" {
		return options.prefix
	}

	// 检查是否实现 AutoController 接口
	if ac, ok := ctrl.(AutoController); ok {
		if prefix := ac.RoutePrefix(); prefix != "" {
			return prefix
		}
	}

	// 使用类型名
	typeName := ctrlType.Elem().Name()
	return "/" + strings.ToLower(typeName)
}

// parseMethodName 解析方法名获取 HTTP 方法、路径和是否正则。
// 示例:
//
//	GetTest        → ("GET", "/test", false)
//	GetUserProfile → ("GET", "/user/profile", false)
//	PostLogin      → ("POST", "/login", false)
//	GetUserIDRegex → ("GET", "/user/id", true)
func parseMethodName(name string) (httpMethod, path string, isRegex bool) {
	prefixes := []string{"Get", "Post", "Put", "Delete", "Patch", "Head", "Options", "Any"}

	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			httpMethod = strings.ToUpper(prefix)
			remaining := strings.TrimPrefix(name, prefix)

			if strings.HasSuffix(remaining, "Regex") {
				isRegex = true
				remaining = strings.TrimSuffix(remaining, "Regex")
			}

			path = camelToSlashPath(remaining)
			return
		}
	}
	return "", "", false
}

// camelToSlashPath 将驼峰命名转换为斜杠分隔路径。
// 示例:
//
//	UserProfile → /user/profile
//	ID          → /id
//	UserID      → /user/id
//	APIVersion  → /api/version
func camelToSlashPath(s string) string {
	if s == "" {
		return ""
	}

	var segments []string
	start := 0
	runes := []rune(s)

	for i := 1; i < len(runes); i++ {
		curr := runes[i]
		prev := runes[i-1]
		var next rune
		if i+1 < len(runes) {
			next = runes[i+1]
		}

		// 分词规则:
		// 1) 小写/数字 -> 大写: 新词开始
		// 2) 连续大写遇到后续小写: 在最后一个大写前切分 (APIVersion -> API + Version)
		if isUpper(curr) {
			if isLowerOrDigit(prev) || (isUpper(prev) && next != 0 && isLower(next)) {
				segments = append(segments, string(runes[start:i]))
				start = i
			}
		}
	}

	segments = append(segments, string(runes[start:]))
	for i, seg := range segments {
		segments[i] = strings.ToLower(seg)
	}

	return "/" + strings.Join(segments, "/")
}

func isUpper(r rune) bool {
	return r >= 'A' && r <= 'Z'
}

func isLower(r rune) bool {
	return r >= 'a' && r <= 'z'
}

func isLowerOrDigit(r rune) bool {
	return isLower(r) || (r >= '0' && r <= '9')
}

// registerRoute 根据方法注册标准路由。
func registerRoute(r *Router, method, path string, handler HandlerFunc) {
	switch method {
	case "GET":
		r.GET(path, handler)
	case "POST":
		r.POST(path, handler)
	case "PUT":
		r.PUT(path, handler)
	case "DELETE":
		r.DELETE(path, handler)
	case "PATCH":
		r.PATCH(path, handler)
	case "HEAD":
		r.HEAD(path, handler)
	case "OPTIONS":
		r.OPTIONS(path, handler)
	case "ANY":
		r.Any(path, handler)
	}
}

// createHandler 将反射方法包装为 HandlerFunc。
func createHandler(method reflect.Value) HandlerFunc {
	return func(c *Context) {
		method.Call([]reflect.Value{reflect.ValueOf(c)})
	}
}

// buildRegexRouterTarget 为正则路由构造继承当前 RouterGroup 中间件的目标路由器。
func buildRegexRouterTarget(r *Router, middlewares []any) *RegexRouter {
	target := r.engine.RegexRouter().Group("")
	if len(r.regexMiddlewares) > 0 {
		target.Use(r.regexMiddlewares...)
	}
	for _, middleware := range middlewares {
		if handler, ok := adaptMiddlewareToHandlerFunc(middleware); ok {
			target.Use(handler)
		}
	}
	return target
}

// adaptMiddlewareToHandlerFunc 将多种中间件类型统一适配为增强型 HandlerFunc。
func adaptMiddlewareToHandlerFunc(middleware any) (HandlerFunc, bool) {
	switch handler := middleware.(type) {
	case HandlerFunc:
		return handler, true
	case func(*Context):
		return HandlerFunc(handler), true
	case ggin.HandlerFunc:
		return WrapMiddleware(handler), true
	case func(*ggin.Context):
		return WrapMiddleware(ggin.HandlerFunc(handler)), true
	case func(http.Handler) http.Handler:
		return adaptHTTPMiddleware(handler), true
	default:
		return nil, false
	}
}
