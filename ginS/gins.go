package ginS

import (
	"html/template"
	"net/http"
	"sync"

	gin "github.com/darkit/gin"
)

var engine = sync.OnceValue(func() *gin.Engine {
	return gin.Default()
})

// LoadHTMLGlob 是 Engine.LoadHTMLGlob 的快捷包装。
func LoadHTMLGlob(pattern string) {
	engine().LoadHTMLGlob(pattern)
}

// LoadHTMLFiles 是 Engine.LoadHTMLFiles 的快捷包装。
func LoadHTMLFiles(files ...string) {
	engine().LoadHTMLFiles(files...)
}

// LoadHTMLFS 是 Engine.LoadHTMLFS 的快捷包装。
func LoadHTMLFS(fs http.FileSystem, patterns ...string) {
	engine().LoadHTMLFS(fs, patterns...)
}

// SetHTMLTemplate 是 Engine.SetHTMLTemplate 的快捷包装。
func SetHTMLTemplate(templ *template.Template) {
	engine().SetHTMLTemplate(templ)
}

// NoRoute 为 NoRoute 注册处理器，默认返回 404 状态码。
func NoRoute(handlers ...gin.HandlerFunc) {
	engine().NoRoute(adaptHandlers(handlers...)...)
}

// NoMethod 是 Engine.NoMethod 的快捷包装。
func NoMethod(handlers ...gin.HandlerFunc) {
	engine().NoMethod(adaptHandlers(handlers...)...)
}

// Group 创建新的路由分组。
func Group(relativePath string, handlers ...gin.HandlerFunc) *gin.RouterGroup {
	return engine().Group(relativePath, handlers...)
}

// Handle 是 Engine.Handle 的快捷包装。
func Handle(httpMethod, relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().Handle(httpMethod, relativePath, handlers...)
}

// POST 是 `router.Handle("POST", path, handlers)` 的快捷方式。
func POST(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().POST(relativePath, handlers...)
}

// GET 是 `router.Handle("GET", path, handlers)` 的快捷方式。
func GET(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().GET(relativePath, handlers...)
}

// DELETE 是 `router.Handle("DELETE", path, handlers)` 的快捷方式。
func DELETE(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().DELETE(relativePath, handlers...)
}

// PATCH 是 `router.Handle("PATCH", path, handlers)` 的快捷方式。
func PATCH(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().PATCH(relativePath, handlers...)
}

// PUT 是 `router.Handle("PUT", path, handlers)` 的快捷方式。
func PUT(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().PUT(relativePath, handlers...)
}

// OPTIONS 是 `router.Handle("OPTIONS", path, handlers)` 的快捷方式。
func OPTIONS(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().OPTIONS(relativePath, handlers...)
}

// HEAD 是 `router.Handle("HEAD", path, handlers)` 的快捷方式。
func HEAD(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().HEAD(relativePath, handlers...)
}

// Any 是 Engine.Any 的快捷包装。
func Any(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	return engine().Any(relativePath, handlers...)
}

// StaticFile 是 Engine.StaticFile 的快捷包装。
func StaticFile(relativePath, filepath string) gin.IRoutes {
	return engine().StaticFile(relativePath, filepath)
}

// Static 从指定文件系统根目录提供静态文件服务。
func Static(relativePath, root string) gin.IRoutes {
	return engine().Static(relativePath, root)
}

// StaticFS 是 Engine.StaticFS 的快捷包装。
func StaticFS(relativePath string, fs http.FileSystem) gin.IRoutes {
	return engine().StaticFS(relativePath, fs)
}

// Use 为路由器挂载全局中间件。
func Use(middlewares ...gin.HandlerFunc) gin.IRoutes {
	return engine().Use(middlewares...)
}

// Routes 返回当前已注册的路由列表。
func Routes() gin.RoutesInfo {
	return engine().Routes()
}

// Run 绑定到 `http.Server` 并开始监听与处理 HTTP 请求。
func Run(addr ...string) error {
	return engine().Run(addr...)
}

// RunTLS 绑定到 `http.Server` 并开始监听与处理 HTTPS 请求。
func RunTLS(addr, certFile, keyFile string) error {
	return engine().RunTLS(addr, certFile, keyFile)
}

// RunUnix 绑定到 `http.Server` 并通过 Unix Socket 监听与处理 HTTP 请求。
func RunUnix(file string) error {
	return engine().RunUnix(file)
}

// RunFd 将路由器绑定到 `http.Server`，并通过指定文件描述符监听与处理 HTTP 请求。
func RunFd(fd int) error {
	return engine().RunFd(fd)
}

func adaptHandlers(handlers ...gin.HandlerFunc) []gin.GinHandlerFunc {
	adapted := make([]gin.GinHandlerFunc, 0, len(handlers))
	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		h := handler
		adapted = append(adapted, func(c *gin.GinContext) {
			h(&gin.Context{Context: c})
		})
	}
	return adapted
}
