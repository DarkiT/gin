package gin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// HandlerFunc 定义处理函数类型
type HandlerFunc func(*Context)

// 常用 HTTP 方法常量
const (
	MethodAny     = "ANY"     // 任意方法
	MethodGet     = "GET"     // GET 请求
	MethodHead    = "HEAD"    // HEAD 请求
	MethodPost    = "POST"    // POST 请求
	MethodPut     = "PUT"     // PUT 请求
	MethodPatch   = "PATCH"   // PATCH 请求 (RFC 5789)
	MethodDelete  = "DELETE"  // DELETE 请求
	MethodConnect = "CONNECT" // CONNECT 请求
	MethodOptions = "OPTIONS" // OPTIONS 请求
	MethodTrace   = "TRACE"   // TRACE 请求
)

// Router 路由管理器
type Router struct {
	engine *gin.Engine
	groups map[string]*RouterGroup // 路由组映射表
}

// RouterGroup 路由组
type RouterGroup struct {
	group    *gin.RouterGroup
	basePath string
	router   *Router
}

// ResourceHandler 定义资源处理器接口
type ResourceHandler interface {
	Index(*Context)  // GET /resources      - 列表
	Show(*Context)   // GET /resources/:id  - 详情
	Create(*Context) // POST /resources     - 创建
	Update(*Context) // PUT /resources/:id  - 更新
	Delete(*Context) // DELETE /resources/:id - 删除
}

// Register 注册路由
func (r *Router) Register(method, path string, handler HandlerFunc, middleware ...HandlerFunc) {
	handlers := make([]gin.HandlerFunc, 0, len(middleware)+1)

	// 转换中间件
	for _, m := range middleware {
		handlers = append(handlers, wrapHandler(m))
	}

	// 添加主处理函数
	handlers = append(handlers, wrapHandler(handler))

	// 注册到 gin
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	r.engine.Handle(method, path, handlers...)
}

// Group 创建或获取路由组
func (r *Router) Group(path string, middleware ...HandlerFunc) *RouterGroup {
	// 转换中间件
	handlers := make([]gin.HandlerFunc, len(middleware))
	for i, m := range middleware {
		handlers[i] = wrapHandler(m)
	}

	// 创建或获取路由组
	group := r.engine.Group(path, handlers...)
	rg := &RouterGroup{
		group:    group,
		basePath: path,
		router:   r,
	}
	r.groups[path] = rg
	return rg
}

func (r *Router) GET(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodGet, path, handler, middleware...)
}

func (r *Router) POST(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodPost, path, handler, middleware...)
}

func (r *Router) PUT(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodPut, path, handler, middleware...)
}

func (r *Router) DELETE(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodDelete, path, handler, middleware...)
}

func (r *Router) HEAD(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodHead, path, handler, middleware...)
}

func (r *Router) CONNECT(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodConnect, path, handler, middleware...)
}

func (r *Router) OPTIONS(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodOptions, path, handler, middleware...)
}

func (r *Router) TRACE(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodTrace, path, handler, middleware...)
}

func (r *Router) PATCH(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	r.Register(MethodPatch, path, handler, middleware...)
}

func (r *Router) ANY(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	// 注册所有 HTTP 方法
	methods := []string{
		MethodGet, MethodPost, MethodPut, MethodDelete,
		MethodPatch, MethodHead, MethodOptions, MethodConnect, MethodTrace,
	}
	for _, method := range methods {
		r.Register(method, path, handler, middleware...)
	}
}

// Register 注册路由到当前组
func (rg *RouterGroup) Register(method, path string, handler HandlerFunc, middleware ...HandlerFunc) {
	fullPath := rg.calculatePath(path)

	// 收集中间件和处理函数
	allHandlers := make([]gin.HandlerFunc, 0, len(middleware)+1)

	// 转换所有中间件
	for _, m := range middleware {
		allHandlers = append(allHandlers, wrapHandler(m))
	}

	// 添加主处理函数
	allHandlers = append(allHandlers, wrapHandler(handler))

	// 注册到 gin
	if rg.group != nil {
		rg.group.Handle(method, rg.calculatePath(path), allHandlers...)
	} else {
		// 如果没有路由组，则直接注册到路由器
		rg.router.engine.Handle(method, fullPath, allHandlers...)
	}
}

func (rg *RouterGroup) GET(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodGet, path, handler, middleware...)
}

func (rg *RouterGroup) POST(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodPost, path, handler, middleware...)
}

func (rg *RouterGroup) PUT(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodPut, path, handler, middleware...)
}

func (rg *RouterGroup) DELETE(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodDelete, path, handler, middleware...)
}

func (rg *RouterGroup) HEAD(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodHead, path, handler, middleware...)
}

func (rg *RouterGroup) CONNECT(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodConnect, path, handler, middleware...)
}

func (rg *RouterGroup) OPTIONS(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodOptions, path, handler, middleware...)
}

func (rg *RouterGroup) TRACE(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodTrace, path, handler, middleware...)
}

func (rg *RouterGroup) PATCH(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	rg.Register(MethodPatch, path, handler, middleware...)
}

func (rg *RouterGroup) ANY(path string, handler HandlerFunc, middleware ...HandlerFunc) {
	methods := []string{
		MethodGet, MethodPost, MethodPut, MethodDelete,
		MethodPatch, MethodHead, MethodOptions, MethodConnect, MethodTrace,
	}
	for _, method := range methods {
		rg.Register(method, path, handler, middleware...)
	}
}

// Group 创建子路由组
func (rg *RouterGroup) Group(path string, middleware ...HandlerFunc) *RouterGroup {
	fullPath := rg.calculatePath(path)
	return rg.router.Group(fullPath, middleware...)
}

// 工具方法
func (rg *RouterGroup) calculatePath(path string) string {
	if path == "" {
		return rg.basePath
	}
	if path[0] != '/' {
		path = "/" + path
	}
	return rg.basePath + path
}

// 包装 gin.HandlerFunc
func wrapHandler(h HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.IsAborted() {
			return
		}
		// 创建我们自己的上下文
		ctx := &Context{Context: c}

		// 调用处理函数
		h(ctx)
	}
}

// Use 中间件
func (r *Router) Use(middleware ...HandlerFunc) {
	handlers := make([]gin.HandlerFunc, len(middleware))
	for i, m := range middleware {
		handlers[i] = wrapHandler(m)
	}
	r.engine.Use(handlers...)
}

// UseGin 中间件 直接使用 gin.HandlerFunc
func (r *Router) UseGin(middleware ...gin.HandlerFunc) {
	handlers := make([]gin.HandlerFunc, len(middleware))
	for i, m := range middleware {
		handlers[i] = func(c *gin.Context) {
			m(c)
		}
	}
	r.engine.Use(handlers...)
}

// Run 启动服务器
func (r *Router) Run(addr ...string) error {
	return r.engine.Run(addr...)
}

// Engine 获取原始 gin.Engine
func (r *Router) Engine() *gin.Engine {
	return r.engine
}

// Resource 注册 RESTful 资源路由
func (r *Router) Resource(path string, handler ResourceHandler, middleware ...HandlerFunc) {
	// 移除路径后的斜杠
	path = strings.TrimRight(path, "/")

	// 注册资源路由
	r.GET(path, handler.Index, middleware...)            // 列表
	r.GET(path+"/:id", handler.Show, middleware...)      // 详情
	r.POST(path, handler.Create, middleware...)          // 创建
	r.PUT(path+"/:id", handler.Update, middleware...)    // 更新
	r.PATCH(path+"/:id", handler.Update, middleware...)  // 更新
	r.DELETE(path+"/:id", handler.Delete, middleware...) // 删除
}

// Resource 注册路由组内的 RESTful 资源路由
func (rg *RouterGroup) Resource(path string, handler ResourceHandler, middleware ...HandlerFunc) {
	// 移除路径后的斜杠
	path = strings.TrimRight(path, "/")

	// 注册资源路由
	rg.GET(path, handler.Index, middleware...)            // 列表
	rg.GET(path+"/:id", handler.Show, middleware...)      // 详情
	rg.POST(path, handler.Create, middleware...)          // 创建
	rg.PUT(path+"/:id", handler.Update, middleware...)    // 更新
	rg.PATCH(path+"/:id", handler.Update, middleware...)  // 更新
	rg.DELETE(path+"/:id", handler.Delete, middleware...) // 删除
}

// RestfulHandler 提供 ResourceHandler 接口的默认实现
type RestfulHandler struct{}

func (h *RestfulHandler) Index(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

func (h *RestfulHandler) Show(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

func (h *RestfulHandler) Create(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

func (h *RestfulHandler) Update(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}

func (h *RestfulHandler) Delete(c *Context) {
	c.String(http.StatusNotImplemented, "Not Implemented")
}
