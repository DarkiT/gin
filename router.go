// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"embed"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/darkit/gin/pkg/swagger"
	"github.com/gin-gonic/gin"
)

// HandlerFunc 定义增强上下文处理器类型。
type HandlerFunc func(*Context)

// Router 封装 gin.RouterGroup 并扩展能力。
type Router struct {
	*gin.RouterGroup
	engine           *Engine
	regexMiddlewares []HandlerFunc
	lastSwaggerRoute *SwaggerRouteInfo
}

// SwaggerRouteInfo 定义 Swagger 路由信息（内部使用）。
type SwaggerRouteInfo struct {
	path        string
	method      string
	handlers    []HandlerFunc
	summary     string
	description string
	operationID string
	params      []swagger.ParamDoc
	responses   map[int]swagger.ResponseDoc
	tags        []string
	deprecated  bool
	security    string
}

func newRouter(e *Engine) *Router {
	return &Router{
		RouterGroup: &e.RouterGroup,
		engine:      e,
	}
}

func wrapHandler(handler HandlerFunc, engine *Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			handler(&Context{Context: c})
			return
		}
		ctx := engine.acquireContext(c)
		defer engine.releaseContext(ctx)
		handler(ctx)
	}
}

func wrapHeadHandler(handler HandlerFunc) HandlerFunc {
	return func(c *Context) {
		originalWriter := c.Writer
		c.Writer = &headResponseWriter{ResponseWriter: c.Writer}
		handler(c)
		c.Writer = originalWriter
	}
}

func joinObservedPath(basePath, relativePath string) string {
	if relativePath == "" {
		return basePath
	}

	finalPath := path.Join(basePath, relativePath)
	if hasTrailingSlash(relativePath) && !hasTrailingSlash(finalPath) {
		return finalPath + "/"
	}
	return finalPath
}

func hasTrailingSlash(value string) bool {
	return value != "" && value[len(value)-1] == '/'
}

func (r *Router) regexTarget(extra ...HandlerFunc) *RegexRouter {
	target := r.engine.RegexRouter().Group(r.BasePath())
	if len(r.regexMiddlewares) > 0 {
		target.Use(r.regexMiddlewares...)
	}
	if len(extra) > 0 {
		target.Use(extra...)
	}
	return target
}

func (r *Router) registerRegexRoute(method, path string, handlers ...HandlerFunc) {
	r.regexTarget().Handle(method, path, handlers...)
}

// GET 注册 GET 路由。
func (r *Router) GET(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(http.MethodGet, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodGet, handlers...)
		return r
	}
	r.RouterGroup.GET(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodGet, handlers...)
	return r
}

// GetHead 同时注册 GET 和 HEAD 路由，HEAD 请求不返回响应体。
//
// 功能说明：
//   - 注册 GET 路由处理正常请求
//   - 自动注册 HEAD 路由，响应头相同但无响应体
//   - 避免手动定义重复的 HEAD 路由
//
// 使用场景：
//   - RESTful API 需要支持 HEAD 请求检查资源存在性
//   - 客户端获取响应元数据（Content-Length、ETag 等）
//   - 节省带宽（不传输响应体）
//
// 使用示例：
//
//	// 单个路由
//	r.GetHead("/users/:id", func(c *gin.Context) {
//	    c.JSON(200, user)  // GET 返回完整数据，HEAD 只返回头
//	})
//
//	// 资源集合
//	r.GetHead("/articles", listArticles)
//	r.GetHead("/articles/:id", showArticle)
func (r *Router) GetHead(path string, handler HandlerFunc) {
	if IsRegexPattern(path) {
		target := r.regexTarget()
		target.GET(path, handler)
		target.HEAD(path, wrapHeadHandler(handler))
		return
	}

	wrapped := wrapHandler(handler, r.engine)
	r.RouterGroup.GET(path, wrapped)

	// 使用 middleware 包的 WrapHeadHandler 包装 HEAD 处理器
	// 需要导入 middleware 包，或者直接在这里实现包装逻辑
	// 为避免循环依赖，直接实现包装逻辑
	r.RouterGroup.HEAD(path, func(c *gin.Context) {
		originalWriter := c.Writer
		c.Writer = &headResponseWriter{ResponseWriter: c.Writer}
		wrapped(c)
		c.Writer = originalWriter
	})
}

// headResponseWriter 包装 gin.ResponseWriter，丢弃响应体但保留响应头。
type headResponseWriter struct {
	gin.ResponseWriter
}

// Write 丢弃写入的数据，但返回成功状态。
func (w *headResponseWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

// WriteString 丢弃写入的字符串，但返回成功状态。
func (w *headResponseWriter) WriteString(s string) (int, error) {
	return len(s), nil
}

// POST 注册 POST 路由。
func (r *Router) POST(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(http.MethodPost, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodPost, handlers...)
		return r
	}
	r.RouterGroup.POST(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodPost, handlers...)
	return r
}

// PUT 注册 PUT 路由。
func (r *Router) PUT(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(http.MethodPut, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodPut, handlers...)
		return r
	}
	r.RouterGroup.PUT(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodPut, handlers...)
	return r
}

// PATCH 注册 PATCH 路由。
func (r *Router) PATCH(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(http.MethodPatch, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodPatch, handlers...)
		return r
	}
	r.RouterGroup.PATCH(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodPatch, handlers...)
	return r
}

// DELETE 注册 DELETE 路由。
func (r *Router) DELETE(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(http.MethodDelete, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodDelete, handlers...)
		return r
	}
	r.RouterGroup.DELETE(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodDelete, handlers...)
	return r
}

// HEAD 注册 HEAD 路由。
func (r *Router) HEAD(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(http.MethodHead, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodHead, handlers...)
		return r
	}
	r.RouterGroup.HEAD(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodHead, handlers...)
	return r
}

// OPTIONS 注册 OPTIONS 路由。
func (r *Router) OPTIONS(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(http.MethodOptions, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodOptions, handlers...)
		return r
	}
	r.RouterGroup.OPTIONS(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, http.MethodOptions, handlers...)
	return r
}

// Any 注册所有 HTTP 方法的路由，匹配全部标准方法。
func (r *Router) Any(path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.regexTarget().Any(path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, "ANY", handlers...)
		return r
	}
	r.RouterGroup.Any(path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, "ANY", handlers...)
	return r
}

// Match 注册匹配指定多个 HTTP 方法的路由。
//
// 使用示例：
//
//	// 同时支持 GET 和 POST
//	r.Match([]string{"GET", "POST"}, "/user", handler)
func (r *Router) Match(methods []string, relativePath string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(relativePath) {
		target := r.regexTarget()
		for _, method := range methods {
			target.Handle(method, relativePath, handlers...)
		}
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(relativePath, strings.Join(methods, ","), handlers...)
		return r
	}
	r.RouterGroup.Match(methods, relativePath, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(relativePath, strings.Join(methods, ","), handlers...)
	return r
}

// BasePath 返回路由组的基础路径。
// 用于路由调试和诊断。
//
// 使用示例：
//
//	v1 := r.Group("/api/v1")
//	basePath := v1.BasePath() // "/api/v1"
func (r *Router) BasePath() string {
	return r.RouterGroup.BasePath()
}

// Handle 注册指定方法与路径的处理器。
func (r *Router) Handle(method, path string, handlers ...HandlerFunc) IRoutes {
	if len(handlers) == 0 {
		return r
	}
	if IsRegexPattern(path) {
		r.registerRegexRoute(method, path, handlers...)
		r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, method, handlers...)
		return r
	}
	r.RouterGroup.Handle(method, path, wrapHandlersChain(handlers, r.engine)...)
	r.lastSwaggerRoute = r.newSwaggerRouteInfo(path, method, handlers...)
	return r
}

// Group 创建路由分组，path 为分组前缀。
func (r *Router) Group(path string, handlers ...HandlerFunc) *RouterGroup {
	group := &Router{
		RouterGroup:      r.RouterGroup.Group(path, wrapHandlersChain(handlers, r.engine)...),
		engine:           r.engine,
		regexMiddlewares: append([]HandlerFunc{}, r.regexMiddlewares...),
	}
	if len(handlers) > 0 {
		group.regexMiddlewares = append(group.regexMiddlewares, handlers...)
	}
	return group
}

// adaptHTTPMiddleware 将标准 http 中间件适配为 gin.HandlerFunc。
// 支持 Chi 风格中间件：func(http.Handler) http.Handler。
//
// 功能说明：
//   - 自动包装标准 http.Handler 中间件
//   - 跟踪中间件是否调用了 next.ServeHTTP
//   - 未调用时自动执行 c.Abort() 中断链
//   - 检测 Writer.Written() 状态,避免重复写入
//
// 使用场景：
//   - 复用 Chi 框架的中间件生态
//   - 使用标准 http.Handler 中间件
//   - 无需手动适配即可直接传入 Use()
//
// ⚠️ 重要：Chi 中间件使用注意事项
//
// ✅ 安全用法（只读取请求，最后调用 next）:
//
//	chimw.RequestID  // 只设置 Header，然后调用 next
//	chimw.Logger     // 只记录日志，然后调用 next
//
// ⚠️ 注意事项（提前写响应）:
//
//	func customChiMiddleware(next http.Handler) http.Handler {
//	    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	        w.WriteHeader(403)           // ⚠️ 提前写入响应
//	        w.Write([]byte("Forbidden"))
//	        // next.ServeHTTP(w, r)      // ⚠️ 不要调用 next（会导致重复写入）
//	    })
//	}
//
// ✅ 建议：使用 Gin 风格中间件处理响应:
//
//	func ginMiddleware(c *gin.Context) {
//	    c.JSON(403, gin.H{"error": "Forbidden"})
//	    c.Abort()  // 明确中断后续链
//	}
func adaptHTTPMiddleware(mw func(http.Handler) http.Handler) HandlerFunc {
	return func(c *Context) {
		if c == nil || c.Context == nil {
			return
		}
		// 记录进入时是否已写入,避免误判上游写入
		wasWritten := c.Writer.Written()

		// 标志位: 记录 Chi 中间件是否调用了 next.ServeHTTP
		nextCalled := false

		// 创建一个 http.Handler 包装 Gin 的中间件链
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.Writer.Written() {
				return
			}
			nextCalled = true
			c.Next()
		})

		// 应用 Chi 中间件
		mw(nextHandler).ServeHTTP(c.Writer, c.Request)

		if c.Writer.Written() && !wasWritten {
			c.Abort()
			return
		}

		// 如果 Chi 中间件没有调用 next.ServeHTTP
		// 说明它选择中断执行链,我们需要调用 Abort 阻止 Gin 继续执行
		if !nextCalled {
			c.Abort()
		}
	}
}

// Use 添加路由组中间件，并返回 IRoutes 以保持与上游一致。
func (r *Router) Use(handlers ...HandlerFunc) IRoutes {
	chain := wrapHandlersChain(handlers, r.engine)
	if len(chain) > 0 {
		r.RouterGroup.Use(chain...)
		r.regexMiddlewares = append(r.regexMiddlewares, handlers...)
	}
	return r
}

// UseAny 接受任意可适配的中间件类型。
func (r *Router) UseAny(handlers ...any) IRoutes {
	adapted := make([]HandlerFunc, 0, len(handlers))
	for _, h := range handlers {
		handler, ok := adaptMiddlewareToHandlerFunc(h)
		if !ok {
			panic(fmt.Sprintf("gin: unsupported middleware type: %T, expected HandlerFunc, gin.HandlerFunc, or func(http.Handler) http.Handler", h))
		}
		adapted = append(adapted, handler)
	}
	return r.Use(adapted...)
}

// WrapMiddleware 将原始 gin 中间件包装为增强型。
func WrapMiddleware(h gin.HandlerFunc) HandlerFunc {
	return func(c *Context) {
		h(c.Context)
	}
}

// AdaptHandler 将增强型处理器转换为原始 gin.HandlerFunc。
func (r *Router) AdaptHandler(h HandlerFunc) gin.HandlerFunc {
	return wrapHandler(h, r.engine)
}

// ResourceController 定义资源型控制器接口。
type ResourceController interface {
	Index(c *Context)
	Show(c *Context)
	Create(c *Context)
	Update(c *Context)
	Patch(c *Context)
	Destroy(c *Context)
}

// ResourceOption 定义资源路由配置选项。
type ResourceOption func(*resourceOptions)

type resourceOptions struct {
	idParam string
}

// WithIDParam 设置资源路由的主键参数名。
func WithIDParam(name string) ResourceOption {
	return func(o *resourceOptions) {
		if name != "" {
			o.idParam = name
		}
	}
}

// Resource 注册 RESTful 资源路由，name 为资源名。
func (r *Router) Resource(name string, ctrl ResourceController, opts ...ResourceOption) {
	if ctrl == nil {
		return
	}
	options := resourceOptions{idParam: "id"}
	for _, opt := range opts {
		opt(&options)
	}
	base := "/" + strings.Trim(name, "/")
	idPath := base + "/:" + options.idParam

	r.GET(base, ctrl.Index)
	r.POST(base, ctrl.Create)
	r.GET(idPath, ctrl.Show)
	r.PUT(idPath, ctrl.Update)
	r.PATCH(idPath, ctrl.Patch)
	r.DELETE(idPath, ctrl.Destroy)
}

// CRUD 注册简化的资源路由，使用默认 id 参数。
func (r *Router) CRUD(name string, ctrl ResourceController) {
	if ctrl == nil {
		return
	}
	base := "/" + strings.Trim(name, "/")
	idPath := base + "/:id"

	r.GET(base, ctrl.Index)
	r.POST(base, ctrl.Create)
	r.GET(idPath, ctrl.Show)
	r.PUT(idPath, ctrl.Update)
	r.DELETE(idPath, ctrl.Destroy)
}

// Version 创建版本前缀分组，v 为版本号。
func (r *Router) Version(v string) *Router {
	version := strings.TrimSpace(v)
	if version == "" {
		version = "1"
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return r.Group("/" + version)
}

// VersionedAPI 创建版本化路由并执行 setup。
func (r *Router) VersionedAPI(v string, setup func(*Router)) {
	if setup == nil {
		return
	}
	setup(r.Version(v))
}

// HealthCheck 注册健康检查路由，path 为空时使用 /health。
func (r *Router) HealthCheck(path ...string) {
	p := "/health"
	if len(path) > 0 && path[0] != "" {
		p = path[0]
	}
	r.GET(p, func(c *Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
}

// Static 设置静态文件目录服务。
// 提供本地文件系统目录的静态文件访问。
//
// 使用示例：
//
//	r.Static("/assets", "./public")
func (r *Router) Static(relativePath, root string) IRoutes {
	r.RouterGroup.Static(relativePath, root)
	return r
}

// StaticFS 设置基于 http.FileSystem 的静态文件服务。
// 支持自定义文件系统实现（embed.FS, zip.FS 等）。
//
// 使用示例：
//
//	r.StaticFS("/static", http.Dir("./public"))
func (r *Router) StaticFS(relativePath string, fs http.FileSystem) IRoutes {
	r.RouterGroup.StaticFS(relativePath, fs)
	return r
}

// StaticFile 设置单个静态文件路由。
// 将 URL 路径映射到文件系统中的具体文件。
//
// 使用示例：
//
//	r.StaticFile("/favicon.ico", "./assets/favicon.ico")
func (r *Router) StaticFile(relativePath, filepath string) IRoutes {
	r.RouterGroup.StaticFile(relativePath, filepath)
	return r
}

// StaticFileFS 设置单个静态文件路由，并使用自定义文件系统。
func (r *Router) StaticFileFS(relativePath, filepath string, fs http.FileSystem) IRoutes {
	r.RouterGroup.StaticFileFS(relativePath, filepath, fs)
	return r
}

// EmbedFS 设置嵌入式文件系统静态资源服务。
// 支持可选的子路径参数用于移除 embed.FS 中的路径前缀。
//
// 使用示例：
//
//	// 直接使用 embedFS 根目录
//	r.EmbedFS("/static", embedFS)
//
//	// 使用 embedFS 中的 dist 子目录
//	r.EmbedFS("/static", embedFS, "dist")
func (r *Router) EmbedFS(relativePath string, embedFS embed.FS, subPath ...string) error {
	if strings.TrimSpace(relativePath) == "" {
		return nil
	}

	var fileSystem http.FileSystem
	if len(subPath) > 0 && subPath[0] != "" {
		trimmedPath := strings.Trim(subPath[0], "/")
		subFS, err := fs.Sub(embedFS, trimmedPath)
		if err != nil {
			return err
		}
		fileSystem = http.FS(subFS)
	} else {
		fileSystem = http.FS(embedFS)
	}

	r.StaticFS(relativePath, fileSystem)
	return nil
}

// EmbedFile 设置单个嵌入文件路由。
// 将 URL 路径映射到 embed.FS 中的具体文件。
//
// 使用示例：
//
//	r.EmbedFile("/favicon.ico", embedFS, "assets/favicon.ico")
func (r *Router) EmbedFile(relativePath string, embedFS embed.FS, filePath string) error {
	if strings.TrimSpace(relativePath) == "" {
		return nil
	}
	if strings.TrimSpace(filePath) == "" {
		return nil
	}

	r.GET(relativePath, func(c *Context) {
		data, err := embedFS.ReadFile(filePath)
		if err != nil {
			c.String(http.StatusNotFound, "file not found")
			return
		}

		contentType := mime.TypeByExtension(path.Ext(filePath))
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		c.Data(http.StatusOK, contentType, data)
	})
	return nil
}

// LastRouteDoc 返回最近一次注册路由对应的 Swagger 信息。
func (r *Router) LastRouteDoc() *SwaggerRouteInfo {
	return r.lastSwaggerRoute
}

// GETDoc 在注册 GET 路由后返回其 Swagger 信息。
func (r *Router) GETDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	r.GET(path, handlers...)
	return r.lastSwaggerRoute
}

// POSTDoc 在注册 POST 路由后返回其 Swagger 信息。
func (r *Router) POSTDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	r.POST(path, handlers...)
	return r.lastSwaggerRoute
}

// PUTDoc 在注册 PUT 路由后返回其 Swagger 信息。
func (r *Router) PUTDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	r.PUT(path, handlers...)
	return r.lastSwaggerRoute
}

// PATCHDoc 在注册 PATCH 路由后返回其 Swagger 信息。
func (r *Router) PATCHDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	r.PATCH(path, handlers...)
	return r.lastSwaggerRoute
}

// DELETEDoc 在注册 DELETE 路由后返回其 Swagger 信息。
func (r *Router) DELETEDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	r.DELETE(path, handlers...)
	return r.lastSwaggerRoute
}

// HEADDoc 在注册 HEAD 路由后返回其 Swagger 信息。
func (r *Router) HEADDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	r.HEAD(path, handlers...)
	return r.lastSwaggerRoute
}

// OPTIONSDoc 在注册 OPTIONS 路由后返回其 Swagger 信息。
func (r *Router) OPTIONSDoc(path string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	r.OPTIONS(path, handlers...)
	return r.lastSwaggerRoute
}

// newSwaggerRouteInfo 创建 Swagger 路由信息。
func (r *Router) newSwaggerRouteInfo(path, method string, handlers ...HandlerFunc) *SwaggerRouteInfo {
	if len(handlers) == 0 {
		return nil
	}
	info := &SwaggerRouteInfo{
		path:      joinObservedPath(r.BasePath(), path),
		method:    method,
		handlers:  append([]HandlerFunc(nil), handlers...),
		params:    make([]swagger.ParamDoc, 0),
		responses: make(map[int]swagger.ResponseDoc),
		tags:      make([]string, 0),
	}

	// 如果 Swagger 启用，添加到引擎
	if r.engine.swaggerEnabled {
		r.engine.addSwaggerRoute(info)
	}

	return info
}

// Doc 设置路由的简要说明。
func (s *SwaggerRouteInfo) Doc(summary string) *SwaggerRouteInfo {
	s.summary = summary
	return s
}

// Description 设置路由的详细描述。
func (s *SwaggerRouteInfo) Description(desc string) *SwaggerRouteInfo {
	s.description = desc
	return s
}

// Param 添加参数定义，name 为参数名。
func (s *SwaggerRouteInfo) Param(name, in, typ, desc string, required bool) *SwaggerRouteInfo {
	s.params = append(s.params, swagger.ParamDoc{
		Name:        name,
		In:          in,
		Type:        typ,
		Description: desc,
		Required:    required,
	})
	return s
}

// ParamModel 添加带模型的参数定义（用于 body 参数）。
func (s *SwaggerRouteInfo) ParamModel(name, in, desc string, required bool, model interface{}) *SwaggerRouteInfo {
	s.params = append(s.params, swagger.ParamDoc{
		Name:        name,
		In:          in,
		Type:        "object",
		Description: desc,
		Required:    required,
		Model:       model,
	})
	return s
}

// Response 添加响应定义。
func (s *SwaggerRouteInfo) Response(code int, desc string, model ...interface{}) *SwaggerRouteInfo {
	resp := s.responses[code]
	resp.Description = desc
	if len(model) > 0 && model[0] != nil {
		resp.Model = model[0]
	}
	s.responses[code] = resp
	return s
}

// Tag 添加标签。
func (s *SwaggerRouteInfo) Tag(tags ...string) *SwaggerRouteInfo {
	s.tags = append(s.tags, tags...)
	return s
}

// Deprecated 标记为废弃。
func (s *SwaggerRouteInfo) Deprecated() *SwaggerRouteInfo {
	s.deprecated = true
	return s
}

// Security 设置安全方案。
func (s *SwaggerRouteInfo) Security(name string) *SwaggerRouteInfo {
	s.security = name
	return s
}

// OperationID 设置路由的稳定操作 ID。
func (s *SwaggerRouteInfo) OperationID(id string) *SwaggerRouteInfo {
	s.operationID = id
	return s
}

// RequestExample 设置请求体示例。
func (s *SwaggerRouteInfo) RequestExample(example any) *SwaggerRouteInfo {
	param := s.ensureBodyParam()
	param.Example = example
	return s
}

// RequestExamples 设置请求体多示例。
func (s *SwaggerRouteInfo) RequestExamples(examples map[string]swagger.Example) *SwaggerRouteInfo {
	param := s.ensureBodyParam()
	param.Examples = cloneSwaggerExamples(examples)
	return s
}

// ResponseExample 设置指定响应的示例。
func (s *SwaggerRouteInfo) ResponseExample(code int, example any) *SwaggerRouteInfo {
	resp := s.responses[code]
	if resp.Description == "" {
		resp.Description = http.StatusText(code)
	}
	resp.Example = example
	s.responses[code] = resp
	return s
}

// ResponseExamples 设置指定响应的多示例。
func (s *SwaggerRouteInfo) ResponseExamples(code int, examples map[string]swagger.Example) *SwaggerRouteInfo {
	resp := s.responses[code]
	if resp.Description == "" {
		resp.Description = http.StatusText(code)
	}
	resp.Examples = cloneSwaggerExamples(examples)
	s.responses[code] = resp
	return s
}

// ProblemResponse 添加 Problem Details 响应模型。
func (s *SwaggerRouteInfo) ProblemResponse(code int, desc string) *SwaggerRouteInfo {
	resp := s.responses[code]
	resp.Description = desc
	resp.Model = ProblemDetail{}
	resp.ContentType = "application/problem+json"
	s.responses[code] = resp
	return s
}

// DefaultError 为指定状态码添加默认错误模型。
func (s *SwaggerRouteInfo) DefaultError(code int, desc ...string) *SwaggerRouteInfo {
	description := http.StatusText(code)
	if len(desc) > 0 && desc[0] != "" {
		description = desc[0]
	}
	return s.ProblemResponse(code, description)
}

// DefaultErrors 批量添加常见默认错误模型。
func (s *SwaggerRouteInfo) DefaultErrors(codes ...int) *SwaggerRouteInfo {
	if len(codes) == 0 {
		codes = []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
			http.StatusConflict,
			http.StatusUnprocessableEntity,
			http.StatusTooManyRequests,
			http.StatusInternalServerError,
		}
	}
	for _, code := range codes {
		s.DefaultError(code)
	}
	return s
}

func (s *SwaggerRouteInfo) ensureBodyParam() *swagger.ParamDoc {
	for i := range s.params {
		if strings.EqualFold(s.params[i].In, "body") {
			if s.params[i].Type == "" {
				s.params[i].Type = "object"
			}
			if s.params[i].ContentType == "" {
				s.params[i].ContentType = "application/json"
			}
			return &s.params[i]
		}
	}

	s.params = append(s.params, swagger.ParamDoc{
		Name:        "body",
		In:          "body",
		Type:        "object",
		Description: "请求体",
		Required:    true,
		ContentType: "application/json",
	})
	return &s.params[len(s.params)-1]
}

func cloneSwaggerExamples(examples map[string]swagger.Example) map[string]swagger.Example {
	if len(examples) == 0 {
		return nil
	}

	cloned := make(map[string]swagger.Example, len(examples))
	for name, example := range examples {
		cloned[name] = example
	}
	return cloned
}
