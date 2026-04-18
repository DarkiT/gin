package middleware

import (
	"strings"

	"github.com/darkit/gin"
)

// RouteHeaders 基于请求头的条件路由中间件
// 允许根据请求头的值动态应用不同的中间件
//
// 使用场景:
//   - 根据 Host 头分发到不同的处理器
//   - 根据 Origin 头应用不同的 CORS 策略
//   - 根据 User-Agent 头区分移动/桌面端
//   - 根据自定义头实现 A/B 测试
//
// 使用示例:
//
//	// 根据 Origin 应用不同的 CORS 策略
//	router.Use(middleware.RouteHeaders().
//	    Route("Origin", "https://app.example.com", strictCORS).
//	    Route("Origin", "*", publicCORS).
//	    Handler())
//
//	// 根据 Host 分发请求
//	router.Use(middleware.RouteHeaders().
//	    Route("Host", "api.example.com", apiHandler).
//	    Route("Host", "*.example.com", wildcardHandler).
//	    RouteDefault(defaultHandler).
//	    Handler())
//
//	// 根据 User-Agent 区分客户端
//	router.Use(middleware.RouteHeaders().
//	    RouteAny("User-Agent", []string{"*Mobile*", "*Android*", "*iPhone*"}, mobileMiddleware).
//	    Route("User-Agent", "*", desktopMiddleware).
//	    Handler())
func RouteHeaders() *HeaderRouter {
	return &HeaderRouter{
		routes: make(map[string][]HeaderRoute),
	}
}

// HeaderRouter 请求头路由器
type HeaderRouter struct {
	routes map[string][]HeaderRoute
}

// Route 添加单个匹配规则
// header: 请求头名称(不区分大小写)
// match: 匹配模式,支持通配符 * (例如: "*.example.com", "api.example.com", "*mobile*")
// middleware: 匹配时执行的中间件
func (hr *HeaderRouter) Route(header, match string, middleware gin.HandlerFunc) *HeaderRouter {
	header = strings.ToLower(header)
	hr.routes[header] = append(hr.routes[header], HeaderRoute{
		MatchOne:   NewPattern(match),
		Middleware: middleware,
	})
	return hr
}

// RouteAny 添加多个匹配规则(OR 关系)
// 当请求头匹配任一模式时,执行中间件
//
// 使用示例:
//
//	RouteAny("User-Agent", []string{"*Mobile*", "*Android*", "*iPhone*"}, mobileHandler)
func (hr *HeaderRouter) RouteAny(header string, matches []string, middleware gin.HandlerFunc) *HeaderRouter {
	header = strings.ToLower(header)
	patterns := make([]Pattern, 0, len(matches))
	for _, m := range matches {
		patterns = append(patterns, NewPattern(m))
	}
	hr.routes[header] = append(hr.routes[header], HeaderRoute{
		MatchAny:   patterns,
		Middleware: middleware,
	})
	return hr
}

// RouteDefault 设置默认处理器
// 当所有规则都不匹配时执行
func (hr *HeaderRouter) RouteDefault(middleware gin.HandlerFunc) *HeaderRouter {
	hr.routes["*"] = []HeaderRoute{{Middleware: middleware}}
	return hr
}

// Handler 返回中间件处理函数
func (hr *HeaderRouter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 没有配置路由规则,直接继续
		if len(hr.routes) == 0 {
			c.Next()
			return
		}

		// 查找第一个匹配的规则
		for header, matchers := range hr.routes {
			if header == "*" {
				continue // 默认规则最后处理
			}

			var headerValue string
			// Host 头需要特殊处理
			if header == "host" {
				headerValue = c.Request.Host
			} else {
				headerValue = c.GetHeader(header)
			}

			if headerValue == "" {
				continue
			}

			headerValue = strings.ToLower(headerValue)
			for _, matcher := range matchers {
				if matcher.IsMatch(headerValue) {
					// 匹配成功,执行中间件
					matcher.Middleware(c)
					return
				}
			}
		}

		// 没有匹配,检查默认规则
		if defaultRoute, ok := hr.routes["*"]; ok && len(defaultRoute) > 0 && defaultRoute[0].Middleware != nil {
			defaultRoute[0].Middleware(c)
			return
		}

		// 没有默认规则,继续正常流程
		c.Next()
	}
}

// HeaderRoute 请求头路由规则
type HeaderRoute struct {
	Middleware gin.HandlerFunc // 匹配时执行的中间件
	MatchOne   Pattern         // 单个匹配模式
	MatchAny   []Pattern       // 多个匹配模式(OR)
}

// IsMatch 检查值是否匹配规则
func (r HeaderRoute) IsMatch(value string) bool {
	// 检查多个模式(OR)
	if len(r.MatchAny) > 0 {
		for _, m := range r.MatchAny {
			if m.Match(value) {
				return true
			}
		}
		return false
	}
	// 检查单个模式
	return r.MatchOne.Match(value)
}

// Pattern 匹配模式
// 支持通配符 * 进行前缀/后缀/包含匹配
type Pattern struct {
	original string
	prefix   string
	suffix   string
	wildcard bool
}

// NewPattern 创建匹配模式
// 支持的格式:
//   - "exact" - 精确匹配
//   - "prefix*" - 前缀匹配
//   - "*suffix" - 后缀匹配
//   - "*contains*" - 包含匹配
//   - "prefix*suffix" - 前后缀匹配
//   - "*" - 匹配任意值
func NewPattern(value string) Pattern {
	value = strings.ToLower(value)

	// 没有通配符,精确匹配
	if !strings.Contains(value, "*") {
		return Pattern{
			original: value,
			prefix:   value,
			wildcard: false,
		}
	}

	// 有通配符
	parts := strings.SplitN(value, "*", 3)

	switch len(parts) {
	case 2:
		// 一个 *: "prefix*" 或 "*suffix"
		return Pattern{
			original: value,
			prefix:   parts[0],
			suffix:   parts[1],
			wildcard: true,
		}
	case 3:
		// 两个 *: "*contains*" 或 "prefix*suffix" (如果第一部分为空则是包含匹配)
		if parts[0] == "" && parts[2] == "" {
			// "*contains*" - 包含匹配
			return Pattern{
				original: value,
				prefix:   "",
				suffix:   parts[1], // 复用 suffix 存储要包含的字符串
				wildcard: true,
			}
		}
		// "prefix*middle*suffix" - 复杂模式,简化为前后缀匹配
		return Pattern{
			original: value,
			prefix:   parts[0],
			suffix:   parts[2],
			wildcard: true,
		}
	default:
		// 不应该到这里
		return Pattern{original: value}
	}
}

// Match 检查值是否匹配模式
func (p Pattern) Match(v string) bool {
	v = strings.ToLower(v)

	// 没有通配符,精确匹配
	if !p.wildcard {
		return p.prefix == v
	}

	// 单个 * 匹配所有
	if p.original == "*" {
		return true
	}

	// *contains* 形式的包含匹配
	if p.prefix == "" && p.suffix != "" && strings.HasPrefix(p.original, "*") && strings.HasSuffix(p.original, "*") {
		return strings.Contains(v, p.suffix)
	}

	// 前缀或后缀或前后缀匹配
	totalLen := len(p.prefix) + len(p.suffix)
	return len(v) >= totalLen &&
		strings.HasPrefix(v, p.prefix) &&
		strings.HasSuffix(v, p.suffix)
}
