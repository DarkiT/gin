package gin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	MethodAny     = "ANY"
	MethodGet     = "GET"
	MethodHead    = "HEAD"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodPatch   = "PATCH" // RFC 5789
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
	MethodOptions = "OPTIONS"
	MethodTrace   = "TRACE"
)

var apis []*api

type api struct {
	Method   string
	Path     string
	Handlers []HandlerFunc
}

// _Router 结构体，封装了 gin.RouterGroup
type _Router struct {
	*gin.RouterGroup
}

// Controller 结构体，包含 router 和 Handler
type Controller struct {
	r *_Router
	h Handler
}

// HandlerFunc 定义处理函数的类型
type HandlerFunc func(c *Context)

// Register 注册路由
func Register(method, path string, handlers ...HandlerFunc) error {
	method = strings.ToUpper(method)

	for _, a := range apis {
		if a.Path == path && (a.Method == method || a.Method == MethodAny || method == MethodAny) {
			return fmt.Errorf("路由冲突: 已存在的路由 [%s %s] 与新路由 [%s %s] 冲突", a.Method, a.Path, method, path)
		}
	}

	apis = append(apis, &api{
		Method:   method,
		Path:     path,
		Handlers: handlers,
	})
	return nil
}

// InitRouting 初始化路由前请先调用 Register 注册路由
func InitRouting(engine *gin.Engine) *gin.Engine {
	router := NewRouter(engine)
	for _, a := range apis {
		switch a.Method {
		case MethodAny:
			// 将 a.Handlers 转换为 gin.HandlerFunc 类型
			hds := make([]gin.HandlerFunc, 0, len(a.Handlers))
			for _, handler := range a.Handlers {
				hds = append(hds, WrapHandler(handler))
			}
			router.Any(a.Path, hds...) // 注册支持所有方法的路由
		case MethodGet:
			router.GET(a.Path, a.Handlers...) // 注册 GET 请求的路由
		case MethodPost:
			router.POST(a.Path, a.Handlers...) // 注册 POST 请求的路由
		case MethodPut:
			router.PUT(a.Path, a.Handlers...) // 注册 PUT 请求的路由
		case MethodPatch:
			router.PATCH(a.Path, a.Handlers...) // 注册 PATCH 请求的路由
		case MethodDelete:
			router.DELETE(a.Path, a.Handlers...) // 注册 DELETE 请求的路由
		case MethodHead:
			router.HEAD(a.Path, a.Handlers...) // 注册 HEAD 请求的路由
		case MethodOptions:
			router.OPTIONS(a.Path, a.Handlers...) // 注册 OPTIONS 请求的路由
		case MethodConnect:
			router.CONNECT(a.Path, a.Handlers...) // 注册 CONNECT 请求的路由
		case MethodTrace:
			router.TRACE(a.Path, a.Handlers...) // 注册 TRACE 请求的路由
		default:
		}
	}
	return engine
}

// WrapHandler 方法用于将自定义的处理函数转换为 gin.HandlerFunc 类型
func WrapHandler(hd HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		hd(&Context{ctx})
	}
}

// NewRouter 创建一个新的 router 实例
func NewRouter(e *gin.Engine) *_Router {
	return &_Router{
		RouterGroup: &e.RouterGroup, // 将 gin.Engine 的 RouterGroup 赋值给 router
	}
}

// GET 方法用于注册 GET 请求的路由
func (r *_Router) GET(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodGet, relativePath, handlers...)
	return r
}

// POST 方法用于注册 POST 请求的路由
func (r *_Router) POST(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodPost, relativePath, handlers...)
	return r
}

// PUT 方法用于注册 PUT 请求的路由
func (r *_Router) PUT(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodPut, relativePath, handlers...)
	return r
}

// PATCH 方法用于注册 PATCH 请求的路由
func (r *_Router) PATCH(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodPatch, relativePath, handlers...)
	return r
}

// HEAD 方法用于注册 HEAD 请求的路由
func (r *_Router) HEAD(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodHead, relativePath, handlers...)
	return r
}

// OPTIONS 方法用于注册 OPTIONS 请求的路由
func (r *_Router) OPTIONS(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodOptions, relativePath, handlers...)
	return r
}

// DELETE 方法用于注册 DELETE 请求的路由
func (r *_Router) DELETE(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodDelete, relativePath, handlers...)
	return r
}

// CONNECT 方法用于注册 CONNECT 请求的路由
func (r *_Router) CONNECT(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodConnect, relativePath, handlers...)
	return r
}

// TRACE 方法用于注册 TRACE 请求的路由
func (r *_Router) TRACE(relativePath string, handlers ...HandlerFunc) *_Router {
	r.wrapRoute(http.MethodTrace, relativePath, handlers...)
	return r
}

// Use 方法用于注册中间件
func (r *_Router) Use(handlers ...HandlerFunc) *_Router {
	r.wrapRoute("use", "", handlers...)
	return r
}

// Group 方法用于创建路由组
func (r *_Router) Group(relativePath string, handlers ...HandlerFunc) *_Router {
	g := r.wrapRoute("group", relativePath, handlers...).(*gin.RouterGroup)
	return &_Router{
		RouterGroup: g,
	}
}

// wrapRoute 用于封装路由注册的逻辑
func (r *_Router) wrapRoute(method string, relativePath string, handlers ...HandlerFunc) gin.IRoutes {
	hds := make([]gin.HandlerFunc, 0, len(handlers))
	for _, hd := range handlers {
		hds = append(hds, WrapHandler(hd))
	}
	// 根据请求方法注册路由
	switch method {
	case http.MethodGet:
		return r.RouterGroup.GET(relativePath, hds...)
	case http.MethodPost:
		return r.RouterGroup.POST(relativePath, hds...)
	case http.MethodPut:
		return r.RouterGroup.PUT(relativePath, hds...)
	case http.MethodPatch:
		return r.RouterGroup.PATCH(relativePath, hds...)
	case http.MethodHead:
		return r.RouterGroup.HEAD(relativePath, hds...)
	case http.MethodOptions:
		return r.RouterGroup.OPTIONS(relativePath, hds...)
	case http.MethodDelete:
		return r.RouterGroup.DELETE(relativePath, hds...)
	case http.MethodConnect:
		return r.RouterGroup.Handle(http.MethodConnect, relativePath, hds...)
	case "use":
		return r.RouterGroup.Use(hds...)
	case "group":
		return r.RouterGroup.Group(relativePath, hds...)
	}
	return r.RouterGroup.Handle(http.MethodTrace, relativePath, hds...)
}

// Controller 方法返回一个 Controller 实例
func (r *_Router) Controller(h Handler) *Controller {
	return &Controller{r: r, h: h}
}

// GET 方法用于在 Controller 中注册 GET 请求的路由
func (c *Controller) GET(relativePath, action string) *Controller {
	c.r.GET(relativePath, c.cloneHandler(action, c.h))
	return c
}

// POST 方法用于在 Controller 中注册 POST 请求的路由
func (c *Controller) POST(relativePath, action string) *Controller {
	c.r.POST(relativePath, c.cloneHandler(action, c.h))
	return c
}

// PUT 方法用于在 Controller 中注册 PUT 请求的路由
func (c *Controller) PUT(relativePath, action string) *Controller {
	c.r.PUT(relativePath, c.cloneHandler(action, c.h))
	return c
}

// PATCH 方法用于在 Controller 中注册 PATCH 请求的路由
func (c *Controller) PATCH(relativePath, action string) *Controller {
	c.r.PATCH(relativePath, c.cloneHandler(action, c.h))
	return c
}

// HEAD 方法用于在 Controller 中注册 HEAD 请求的路由
func (c *Controller) HEAD(relativePath, action string) *Controller {
	c.r.HEAD(relativePath, c.cloneHandler(action, c.h))
	return c
}

// OPTIONS 方法用于在 Controller 中注册 OPTIONS 请求的路由
func (c *Controller) OPTIONS(relativePath, action string) *Controller {
	c.r.OPTIONS(relativePath, c.cloneHandler(action, c.h))
	return c
}

// DELETE 方法用于在 Controller 中注册 DELETE 请求的路由
func (c *Controller) DELETE(relativePath, action string) *Controller {
	c.r.DELETE(relativePath, c.cloneHandler(action, c.h))
	return c
}

// CONNECT 方法用于在 Controller 中注册 CONNECT 请求的路由
func (c *Controller) CONNECT(relativePath, action string) *Controller {
	c.r.CONNECT(relativePath, c.cloneHandler(action, c.h))
	return c
}

// TRACE 方法用于在 Controller 中注册 TRACE 请求的路由
func (c *Controller) TRACE(relativePath, action string) *Controller {
	c.r.TRACE(relativePath, c.cloneHandler(action, c.h))
	return c
}

// Use 方法用于在 Controller 中注册中间件
func (c *Controller) Use(action string) *Controller {
	c.r.wrapRoute("use", "", c.cloneHandler(action, c.h))
	return c
}

// Group 方法用于在 Controller 中创建路由组
func (c *Controller) Group(relativePath, action string) *Controller {
	g := c.r.wrapRoute("group", relativePath, c.cloneHandler(action, c.h)).(*gin.RouterGroup)
	r := &_Router{
		RouterGroup: g,
	}
	return r.Controller(c.h)
}

// Resource 方法用于在 Controller 中注册 RESTful 风格的路由
func (c *Controller) Resource(relativePath string) *Controller {
	c.GET(relativePath, http.MethodGet)
	c.POST(relativePath, http.MethodPost)
	c.PUT(relativePath, http.MethodPut)
	c.PATCH(relativePath, http.MethodPatch)
	c.DELETE(relativePath, http.MethodDelete)
	return c
}

// cloneHandler 方法用于克隆处理函数
func (c *Controller) cloneHandler(action string, h Handler) HandlerFunc {
	return func(c *Context) {
		hd := h.Clone().GetHandler(action) // 获取处理函数
		if hd != nil {
			hd(c) // 调用处理函数
		} else {
			c.Error(action + " handler not implemented")
		}
	}
}
