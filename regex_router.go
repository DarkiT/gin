// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	ggin "github.com/gin-gonic/gin"
)

// RegexRoute 定义正则路由信息。
type RegexRoute struct {
	Method  string         // HTTP 方法或 "*" 表示所有方法
	Pattern *regexp.Regexp // 编译后的诊断正则表达式
	Params  []string       // 参数名列表，按声明顺序排列
	Handler HandlerFunc    // 路由处理器
	route   string         // 原始 Chi 风格路径
}

// RegexRouter 提供完整 chi 风格正则路由支持，并通过 NoRoute 作为标准路由的兜底。
type RegexRouter struct {
	routes         []RegexRoute            // Any 路由索引，保留兼容性与调试用途
	routesByMethod map[string][]RegexRoute // 按方法分组的路由索引
	tree           *node                   // chi 风格正则路由树
	mu             sync.RWMutex
	notFound       HandlerFunc
	paramsPool     sync.Pool
	contextPool    sync.Pool
	prefix         string
	middlewares    []HandlerFunc
	parent         *RegexRouter
	engine         *Engine
}

type regexParam struct {
	Key   string
	Value string
}

type regexMatchResult struct {
	handler          HandlerFunc
	params           map[string]string
	orderedParams    []regexParam
	pattern          string
	found            bool
	methodNotAllowed bool
	methodsAllowed   []string
}

// NewRegexRouter 创建正则路由器。
func NewRegexRouter() *RegexRouter {
	return &RegexRouter{
		routes:         make([]RegexRoute, 0),
		routesByMethod: make(map[string][]RegexRoute),
		tree:           &node{},
		notFound: func(c *Context) {
			c.JSON(http.StatusNotFound, H{"error": "not found"})
		},
		paramsPool: sync.Pool{
			New: func() any {
				return make(map[string]string)
			},
		},
		contextPool: sync.Pool{
			New: func() any {
				return &routeContext{}
			},
		},
	}
}

func (r *RegexRouter) root() *RegexRouter {
	if r.parent != nil {
		return r.parent.root()
	}
	return r
}

// Use 为正则路由器设置中间件，对后续注册的路由生效。
func (r *RegexRouter) Use(handlers ...HandlerFunc) {
	if len(handlers) == 0 {
		return
	}
	r.middlewares = append(r.middlewares, handlers...)
}

// Group 创建带路径前缀的正则路由分组，并继承当前中间件链。
func (r *RegexRouter) Group(prefix string, handlers ...HandlerFunc) *RegexRouter {
	child := &RegexRouter{
		prefix:      joinRegexPath(r.prefix, prefix),
		middlewares: append([]HandlerFunc{}, r.middlewares...),
		parent:      r,
		engine:      r.engine,
	}
	if len(handlers) > 0 {
		child.middlewares = append(child.middlewares, handlers...)
	}
	return child
}

// compilePattern 将 Chi 风格模式转换为 Go 正则表达式。
//
// 说明：
//   - 该表达式主要用于调试与兼容性暴露，不参与真实匹配决策。
//   - 真正的匹配、优先级与参数提取由 chi 风格路由树负责。
func compilePattern(pattern string) (*regexp.Regexp, []string) {
	var regexStr strings.Builder
	params := patParamKeys(pattern)

	regexStr.WriteString("^")

	search := pattern
	for len(search) > 0 {
		segTyp, _, rexpat, _, segStartIdx, segEndIdx := patNextSegment(search)

		switch segTyp {
		case ntStatic:
			regexStr.WriteString(regexp.QuoteMeta(search))
			search = ""

		case ntParam:
			if segEndIdx > 0 {
				staticPrefix := search[:strings.Index(search, "{")]
				if len(staticPrefix) > 0 {
					regexStr.WriteString(regexp.QuoteMeta(staticPrefix))
				}
			}
			regexStr.WriteString("([^/]+)")
			search = search[segEndIdx:]

		case ntRegexp:
			if segEndIdx > 0 {
				staticPrefix := search[:strings.Index(search, "{")]
				if len(staticPrefix) > 0 {
					regexStr.WriteString(regexp.QuoteMeta(staticPrefix))
				}
			}
			cleanRexpat := strings.TrimPrefix(rexpat, "^")
			cleanRexpat = strings.TrimSuffix(cleanRexpat, "$")
			regexStr.WriteString("(")
			regexStr.WriteString(cleanRexpat)
			regexStr.WriteString(")")
			search = search[segEndIdx:]

		case ntCatchAll:
			if segStartIdx > 0 {
				staticPrefix := search[:segStartIdx]
				if len(staticPrefix) > 0 {
					regexStr.WriteString(regexp.QuoteMeta(staticPrefix))
				}
			}
			regexStr.WriteString("(.*)")
			search = ""
		}
	}

	regexStr.WriteString("$")

	compiled, err := regexp.Compile(regexStr.String())
	if err != nil {
		panic(fmt.Sprintf("gin: invalid regexp pattern '%s' compiled from '%s': %v",
			regexStr.String(), pattern, err))
	}

	return compiled, params
}

// Handle 注册正则路由，pattern 使用 Chi 风格语法。
//
// pattern 示例：
//   - /users/{id:[0-9]+}
//   - /posts/{slug}
//   - /api/v{version:[0-9]+}/*
//   - /files/*
func (r *RegexRouter) Handle(method, pattern string, handlers ...HandlerFunc) {
	if len(handlers) == 0 {
		return
	}

	root := r.root()
	fullPattern := joinRegexPath(r.prefix, pattern)
	if fullPattern == "" || fullPattern[0] != '/' {
		panic(fmt.Sprintf("gin: routing pattern must begin with '/' in '%s'", fullPattern))
	}

	upperMethod := strings.ToUpper(strings.TrimSpace(method))
	if upperMethod == "" {
		panic("gin: regex route method cannot be empty")
	}

	compiled, params := compilePattern(fullPattern)
	route := RegexRoute{
		Method:  upperMethod,
		Pattern: compiled,
		Params:  params,
		Handler: r.wrapHandlers(fullPattern, handlers...),
		route:   fullPattern,
	}

	root.mu.Lock()
	defer root.mu.Unlock()

	if root.tree == nil {
		root.tree = &node{}
	}

	if upperMethod == "*" {
		root.tree.InsertRoute(mALL, fullPattern, route.Handler)
		root.routes = upsertRegexRoute(root.routes, route)
		return
	}

	root.tree.InsertRoute(registerMethod(upperMethod), fullPattern, route.Handler)
	root.routesByMethod[upperMethod] = upsertRegexRoute(root.routesByMethod[upperMethod], route)
}

func upsertRegexRoute(routes []RegexRoute, route RegexRoute) []RegexRoute {
	for i := range routes {
		if routes[i].Method == route.Method && routes[i].route == route.route {
			routes[i] = route
			return routes
		}
	}
	return append(routes, route)
}

// GET 注册 GET 方法的正则路由。
func (r *RegexRouter) GET(pattern string, handlers ...HandlerFunc) {
	r.Handle(http.MethodGet, pattern, handlers...)
}

// POST 注册 POST 方法的正则路由。
func (r *RegexRouter) POST(pattern string, handlers ...HandlerFunc) {
	r.Handle(http.MethodPost, pattern, handlers...)
}

// PUT 注册 PUT 方法的正则路由。
func (r *RegexRouter) PUT(pattern string, handlers ...HandlerFunc) {
	r.Handle(http.MethodPut, pattern, handlers...)
}

// DELETE 注册 DELETE 方法的正则路由。
func (r *RegexRouter) DELETE(pattern string, handlers ...HandlerFunc) {
	r.Handle(http.MethodDelete, pattern, handlers...)
}

// PATCH 注册 PATCH 方法的正则路由。
func (r *RegexRouter) PATCH(pattern string, handlers ...HandlerFunc) {
	r.Handle(http.MethodPatch, pattern, handlers...)
}

// HEAD 注册 HEAD 方法的正则路由。
func (r *RegexRouter) HEAD(pattern string, handlers ...HandlerFunc) {
	r.Handle(http.MethodHead, pattern, handlers...)
}

// OPTIONS 注册 OPTIONS 方法的正则路由。
func (r *RegexRouter) OPTIONS(pattern string, handlers ...HandlerFunc) {
	r.Handle(http.MethodOptions, pattern, handlers...)
}

// Any 注册所有 HTTP 方法的正则路由。
func (r *RegexRouter) Any(pattern string, handlers ...HandlerFunc) {
	r.Handle("*", pattern, handlers...)
}

// Match 匹配请求并返回处理器与参数。
func (r *RegexRouter) Match(method, path string) (HandlerFunc, map[string]string, bool) {
	result := r.lookup(method, path)
	if !result.found {
		return nil, nil, false
	}

	params := make(map[string]string, len(result.params))
	maps.Copy(params, result.params)
	r.root().paramsPool.Put(result.params)

	return result.handler, params, true
}

func (r *RegexRouter) lookup(method, path string) regexMatchResult {
	root := r.root()
	path = normalizeLookupPath(path)

	root.mu.RLock()
	defer root.mu.RUnlock()

	if root.tree == nil {
		return regexMatchResult{}
	}

	mt, ok := lookupMethod(method)
	if !ok {
		return regexMatchResult{}
	}

	rctx := root.contextPool.Get().(*routeContext)
	rctx.Reset()
	defer root.contextPool.Put(rctx)

	_, _, handler := root.tree.FindRoute(rctx, mt, path)
	if handler == nil {
		if rctx.methodNotAllowed {
			return regexMatchResult{
				methodNotAllowed: true,
				methodsAllowed:   methodNames(rctx.methodsAllowed),
			}
		}
		return regexMatchResult{}
	}

	params := root.paramsPool.Get().(map[string]string)
	clear(params)

	orderedParams := make([]regexParam, 0, len(rctx.URLParams.Keys))
	for i, key := range rctx.URLParams.Keys {
		value := rctx.URLParams.Values[i]
		params[key] = value
		orderedParams = append(orderedParams, regexParam{Key: key, Value: value})
	}

	return regexMatchResult{
		handler:       handler,
		params:        params,
		orderedParams: orderedParams,
		pattern:       rctx.routePattern,
		found:         true,
	}
}

func methodNames(methods []methodTyp) []string {
	if len(methods) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(methods))
	allowed := make([]string, 0, len(methods))

	methodMu.RLock()
	defer methodMu.RUnlock()

	for _, mt := range methods {
		if mt == mALL || mt == mSTUB {
			continue
		}
		name, ok := reverseMethodMap[mt]
		if !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		allowed = append(allowed, name)
	}

	slices.Sort(allowed)
	return allowed
}

// NotFound 设置真正的 404 处理器。并发安全：写入持 root 写锁，与 Handler() 的读取互斥。
func (r *RegexRouter) NotFound(handler HandlerFunc) {
	root := r.root()
	root.mu.Lock()
	root.notFound = handler
	root.mu.Unlock()
}

// Handler 返回用于 NoRoute 的处理器函数。
func (r *RegexRouter) Handler() HandlerFunc {
	return func(c *Context) {
		match := r.lookup(c.Request.Method, requestLookupPath(c.Request))
		if match.found {
			injectRegexMatch(c, match)
			defer r.root().paramsPool.Put(match.params)
			match.handler(c)
			return
		}

		if match.methodNotAllowed {
			writeAllowHeader(c, match.methodsAllowed)
			c.Status(http.StatusMethodNotAllowed)
			return
		}

		// 持读锁取出 notFound，与 NotFound() 的写入互斥，避免并发 data race。
		root := r.root()
		root.mu.RLock()
		notFound := root.notFound
		root.mu.RUnlock()
		if notFound != nil {
			notFound(c)
		}
	}
}

func injectRegexMatch(c *Context, match regexMatchResult) {
	c.Params = c.Params[:0]
	for _, param := range match.orderedParams {
		c.Params = append(c.Params, ggin.Param{Key: param.Key, Value: param.Value})
		if param.Key != "" {
			c.Request.SetPathValue(param.Key, param.Value)
		}
	}
	if match.pattern != "" {
		c.Request.Pattern = match.pattern
	}
}

func writeAllowHeader(c *Context, methods []string) {
	for _, method := range methods {
		c.Writer.Header().Add("Allow", method)
	}
}

func requestLookupPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	if r.URL.RawPath != "" {
		return normalizeLookupPath(r.URL.RawPath)
	}
	return normalizeLookupPath(r.URL.Path)
}

func normalizeLookupPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func (r *RegexRouter) routesInfo() RoutesInfo {
	root := r.root()
	root.mu.RLock()
	defer root.mu.RUnlock()

	routes := make(map[string]RouteInfo, len(root.routes)+len(root.routesByMethod))
	methods := sortedRegexMethods(root.routesByMethod)
	for _, method := range methods {
		for _, route := range root.routesByMethod[method] {
			key := observableRouteKey(method, route.route)
			routes[key] = observableRouteInfo(method, route.route, route.Handler)
		}
	}
	for _, route := range root.routes {
		for _, method := range observableAnyMethods {
			key := observableRouteKey(method, route.route)
			if _, exists := routes[key]; exists {
				continue
			}
			routes[key] = observableRouteInfo(method, route.route, route.Handler)
		}
	}

	infos := make(RoutesInfo, 0, len(routes))
	for _, info := range routes {
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Path == infos[j].Path {
			return infos[i].Method < infos[j].Method
		}
		return infos[i].Path < infos[j].Path
	})

	return infos
}

func (r *RegexRouter) wrapHandlers(fullPath string, handlers ...HandlerFunc) HandlerFunc {
	chain := make([]HandlerFunc, 0, len(r.middlewares)+len(handlers))
	chain = append(chain, r.middlewares...)
	chain = append(chain, handlers...)
	ginChain := wrapHandlersChain(chain, r.engine)

	return func(c *Context) {
		if c == nil {
			return
		}
		if c.Context == nil {
			for _, handler := range chain {
				if handler == nil {
					continue
				}
				handler(c)
				if c.IsAborted() {
					return
				}
			}
			return
		}

		executeGinHandlerChain(c.Context, ginChain, fullPath)
	}
}

// IsRegexPattern 判断是否为 chi 风格正则/通配路由 pattern。
func IsRegexPattern(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "{") {
		return true
	}

	star := strings.IndexByte(pattern, '*')
	if star < 0 {
		return false
	}

	// 仅将 chi 风格的裸 catch-all（如 /files/*、/*）自动路由到 RegexRouter。
	// Gin 原生命名 catch-all（如 /*path、/:id/*path）保留给底层 Gin 处理，
	// 以继承其路由优先级、参数值与调试行为。
	return star == len(pattern)-1 && (star == 0 || pattern[star-1] == '/')
}

func joinRegexPath(prefix, pattern string) string {
	prefix = normalizeRegexPrefix(prefix)
	pattern = normalizeRegexPattern(pattern)
	if prefix == "" {
		return pattern
	}
	if pattern == "" {
		return prefix
	}
	return prefix + pattern
}

func normalizeRegexPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
}

func normalizeRegexPattern(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return ""
	}
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	return pattern
}

var observableAnyMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodHead,
	http.MethodOptions,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodTrace,
}

func sortedRegexMethods(routesByMethod map[string][]RegexRoute) []string {
	methods := make([]string, 0, len(routesByMethod))
	for method := range routesByMethod {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return methods
}

func observableRouteKey(method, path string) string {
	return method + "\x00" + path
}

func observableRouteInfo(method, path string, handler HandlerFunc) RouteInfo {
	return RouteInfo{
		Method:  method,
		Path:    path,
		Handler: handlerName(handler),
	}
}

func handlerName(handler HandlerFunc) string {
	if handler == nil {
		return ""
	}
	fn := runtime.FuncForPC(reflect.ValueOf(handler).Pointer())
	if fn == nil {
		return ""
	}
	return fn.Name()
}
