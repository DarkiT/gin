package auth

import (
	"io"
	"net/http"

	"github.com/darkit/gin/auth/core/adapter"
	"github.com/gin-gonic/gin"
)

// GinRequestContext Gin 框架请求上下文适配器
// 实现 core/adapter.RequestContext 接口
type GinRequestContext struct {
	ctx     *gin.Context
	aborted bool
}

// NewGinRequestContext 创建 Gin 请求上下文适配器
func NewGinRequestContext(c *gin.Context) adapter.RequestContext {
	return &GinRequestContext{
		ctx:     c,
		aborted: false,
	}
}

// ============ Request Methods | 请求方法 ============

// GetHeader 获取请求头
func (g *GinRequestContext) GetHeader(key string) string {
	return g.ctx.GetHeader(key)
}

// GetHeaders 获取所有请求头
func (g *GinRequestContext) GetHeaders() map[string][]string {
	return g.ctx.Request.Header
}

// GetQuery 获取查询参数
func (g *GinRequestContext) GetQuery(key string) string {
	return g.ctx.Query(key)
}

// GetQueryAll 获取所有查询参数
func (g *GinRequestContext) GetQueryAll() map[string][]string {
	return g.ctx.Request.URL.Query()
}

// GetPostForm 获取 POST 表单参数
func (g *GinRequestContext) GetPostForm(key string) string {
	return g.ctx.PostForm(key)
}

// GetCookie 获取 Cookie
func (g *GinRequestContext) GetCookie(key string) string {
	cookie, err := g.ctx.Cookie(key)
	if err != nil {
		return ""
	}
	return cookie
}

// GetBody 获取请求体字节数据
func (g *GinRequestContext) GetBody() ([]byte, error) {
	return io.ReadAll(g.ctx.Request.Body)
}

// GetClientIP 获取客户端 IP 地址
func (g *GinRequestContext) GetClientIP() string {
	return g.ctx.ClientIP()
}

// GetMethod 获取请求方法（GET、POST 等）
func (g *GinRequestContext) GetMethod() string {
	return g.ctx.Request.Method
}

// GetPath 获取请求路径
func (g *GinRequestContext) GetPath() string {
	return g.ctx.Request.URL.Path
}

// GetURL 获取完整请求 URL
func (g *GinRequestContext) GetURL() string {
	return g.ctx.Request.URL.String()
}

// GetUserAgent 获取 User-Agent
func (g *GinRequestContext) GetUserAgent() string {
	return g.ctx.Request.UserAgent()
}

// ============ Response Methods | 响应方法 ============

// SetHeader 设置响应头
func (g *GinRequestContext) SetHeader(key, value string) {
	g.ctx.Header(key, value)
}

// SetCookie 设置 Cookie（兼容旧版本的方法）
func (g *GinRequestContext) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	g.ctx.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)
}

// SetCookieWithOptions 使用选项设置 Cookie
func (g *GinRequestContext) SetCookieWithOptions(options *adapter.CookieOptions) {
	if options == nil {
		return
	}

	// 转换 SameSite 模式
	sameSite := http.SameSiteDefaultMode
	switch options.SameSite {
	case "Strict":
		sameSite = http.SameSiteStrictMode
	case "Lax":
		sameSite = http.SameSiteLaxMode
	case "None":
		sameSite = http.SameSiteNoneMode
	}

	g.ctx.SetSameSite(sameSite)
	g.ctx.SetCookie(
		options.Name,
		options.Value,
		options.MaxAge,
		options.Path,
		options.Domain,
		options.Secure,
		options.HttpOnly,
	)
}

// ============ Context Storage Methods | 上下文存储方法 ============

// Set 设置上下文值
func (g *GinRequestContext) Set(key string, value any) {
	g.ctx.Set(key, value)
}

// Get 获取上下文值
func (g *GinRequestContext) Get(key string) (any, bool) {
	return g.ctx.Get(key)
}

// GetString 从上下文获取字符串值
func (g *GinRequestContext) GetString(key string) string {
	return g.ctx.GetString(key)
}

// MustGet 获取上下文值，不存在则 panic
func (g *GinRequestContext) MustGet(key string) any {
	return g.ctx.MustGet(key)
}

// ============ Utility Methods | 工具方法 ============

// Abort 中止请求处理
func (g *GinRequestContext) Abort() {
	g.aborted = true
	g.ctx.Abort()
}

// IsAborted 检查请求是否已中止
func (g *GinRequestContext) IsAborted() bool {
	return g.aborted || g.ctx.IsAborted()
}
