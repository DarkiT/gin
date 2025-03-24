package gin

import (
	"net/http"
	"strings"
	"time"

	"github.com/darkit/gin/cache"
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
	groups map[string]*RouterGroup   // 路由组映射表
	cache  *cache.Cache[string, any] // 全局缓存实例
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
	// 检查路径格式
	if path != "" && path[0] != '/' {
		path = "/" + path
	}

	// 检查是否已存在该路由组
	if group, exists := r.groups[path]; exists {
		return group
	}

	// 转换中间件
	handlers := make([]gin.HandlerFunc, len(middleware))
	for i, m := range middleware {
		handlers[i] = wrapHandler(m)
	}

	// 创建gin路由组
	ginGroup := r.engine.Group(path, handlers...)

	// 创建我们的路由组
	rg := &RouterGroup{
		group:    ginGroup,
		basePath: path,
		router:   r,
	}

	// 保存到映射表
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
	// 正确计算一次完整路径
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
		// 使用path的相对路径，而不是fullPath，因为gin.RouterGroup已经知道自己的basePath
		rg.group.Handle(method, path, allHandlers...)
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
	// 正确计算子组路径，避免重复斜杠
	fullPath := rg.calculatePath(path)

	// 转换中间件
	handlers := make([]gin.HandlerFunc, len(middleware))
	for i, m := range middleware {
		handlers[i] = wrapHandler(m)
	}

	// 使用正确计算的路径创建gin路由组
	group := rg.group.Group(path, handlers...)

	// 创建我们自己的路由组，保存完整路径
	newGroup := &RouterGroup{
		group:    group,
		basePath: fullPath,
		router:   rg.router,
	}

	// 记录到映射表中
	rg.router.groups[fullPath] = newGroup
	return newGroup
}

// 改进路径计算方法，避免重复斜杠
func (rg *RouterGroup) calculatePath(path string) string {
	if path == "" {
		return rg.basePath
	}

	// 确保basePath和path之间只有一个斜杠
	if path[0] == '/' && rg.basePath != "" && rg.basePath[len(rg.basePath)-1] == '/' {
		// 如果basePath以/结尾且path以/开头，移除path开头的斜杠
		path = path[1:]
	} else if path[0] != '/' && rg.basePath != "" && rg.basePath[len(rg.basePath)-1] != '/' {
		// 如果basePath不以/结尾且path不以/开头，添加斜杠
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
		// 使用newContext创建上下文
		ctx := newContext(c)

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

// WithCache 返回一个缓存初始化中间件
// 该中间件会将指定缓存实例注入到每个请求的Context中
func (r *Router) WithCache(cache *cache.Cache[string, any]) HandlerFunc {
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
