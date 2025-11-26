package gin

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkit/gin/cache"
	"github.com/darkit/gin/pkg/errors"
	"github.com/darkit/gin/pkg/sse"
	"github.com/darkit/gin/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/language"
)

var (
	// contextPool Context对象池，用于减少GC压力和提高性能
	contextPool = sync.Pool{
		New: func() interface{} {
			return &Context{
				pooled: true,
			}
		},
	}

	// componentsPool 组件对象池
	componentsPool = sync.Pool{
		New: func() interface{} {
			return &contextComponents{}
		},
	}
)

// Context 增强的请求上下文，实现types.RequestContext接口
// 优化版本：减少字段数量，使用延迟初始化，支持对象池化
type Context struct {
	*gin.Context

	// 核心组件 - 使用指针减少内存占用，支持延迟初始化
	components *contextComponents

	// 性能优化字段
	pooled bool // 标记是否来自对象池

	// 中间件管理字段
	nextFunc   func() // 自定义的next函数，用于中间件管理器
	nextCalled bool   // 标记是否调用了Next方法
}

func (c *Context) ginCtx() *gin.Context {
	return c.Context
}

// contextComponents 上下文组件集合
// 使用单独结构体减少Context主体大小，支持延迟初始化
type contextComponents struct {
	cache        *cache.Cache[string, any] // 缓存实例
	errorHandler types.ErrorHandler        // 错误处理器
	jwtAdapter   *JWTAdapter               // JWT适配器
	sseHub       *sse.Hub                  // SSE中心
}

// GenerateRequestID 生成基于UUID v5标准的请求ID
// 使用时间戳和随机数作为名称，确保唯一性
func (c *Context) GenerateRequestID() string {
	return generateRequestID()
}

// generateRequestID 包级别的请求ID生成函数
func generateRequestID() string {
	if id, err := uuid.NewRandom(); err == nil {
		return id.String()
	}

	// uuid 生成失败时退化为随机字节 + 时间戳，保证稳定性
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return fmt.Sprintf("fallback-%s", base64.RawURLEncoding.EncodeToString(buf))
	}

	return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
}

// 统一响应方法

// Success 成功响应
func (c *Context) Success(data interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusOK, types.Response{
		Code: types.SuccessCode,
		Msg:  "success",
		Data: data,
		URL:  respUrl,
	})
	c.Abort()
}

// Fail 失败响应
func (c *Context) Fail(msg string, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusBadRequest, types.Response{
		Code: types.FailCode,
		Msg:  msg,
		Data: nil,
		URL:  respUrl,
	})
	c.Abort()
}

// Error 错误响应
func (c *Context) Error(msg string, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusInternalServerError, types.Response{
		Code: types.ErrorCode,
		Msg:  msg,
		Data: nil,
		URL:  respUrl,
	})
	c.Abort()
}

// ErrorWithCode 使用错误处理包的错误响应
func (c *Context) ErrorWithCode(err error) {
	handler := c.getErrorHandler()
	if handler != nil {
		handler.HandleError(c, err)
		return
	}

	// 默认错误处理
	if appErr, ok := err.(*errors.Error); ok {
		c.JSON(appErr.GetStatus(), types.Response{
			Code: appErr.Code,
			Msg:  appErr.Message,
			Data: appErr.Data,
		})
	} else {
		c.JSON(http.StatusInternalServerError, types.Response{
			Code: types.ErrorCode,
			Msg:  err.Error(),
		})
	}
	c.Abort()
}

// Forbidden 禁止访问响应
func (c *Context) Forbidden(msg string, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	if msg == "" {
		msg = "没有权限访问"
	}
	c.JSON(http.StatusForbidden, types.Response{
		Code: types.ForbiddenCode,
		Msg:  msg,
		Data: nil,
		URL:  respUrl,
	})
	c.Abort()
}

// NotFound 资源不存在响应
func (c *Context) NotFound(msg string, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	if msg == "" {
		msg = "资源不存在"
	}
	c.JSON(http.StatusNotFound, types.Response{
		Code: types.NotFoundCode,
		Msg:  msg,
		Data: nil,
		URL:  respUrl,
	})
	c.Abort()
}

// Unauthorized 未授权响应
func (c *Context) Unauthorized(msg string) {
	if msg == "" {
		msg = "未授权访问"
	}
	c.JSON(http.StatusUnauthorized, types.Response{
		Code: http.StatusUnauthorized,
		Msg:  msg,
	})
	c.Abort()
}

// 请求信息获取方法

// GetIP 获取请求IP
func (c *Context) GetIP() string {
	ip := c.GetHeader("X-Real-IP")
	if ip == "" {
		ip = c.GetHeader("X-Forwarded-For")
		if ip != "" {
			ips := strings.Split(ip, ",")
			if len(ips) > 0 {
				ip = strings.TrimSpace(ips[0])
			}
		}
	}
	if ip == "" {
		ip = c.ClientIP()
	}
	return ip
}

// GetUserAgent 获取用户代理信息
func (c *Context) GetUserAgent() string {
	return c.GetHeader("User-Agent")
}

// 参数获取方法

// Param 获取当前请求的变量
func (c *Context) Param(param string, defaultValue ...string) string {
	sources := []func(string) string{
		c.ginCtx().Param,
		c.ginCtx().Query,
		c.ginCtx().PostForm,
	}
	for _, source := range sources {
		if val := source(param); val != "" {
			return val
		}
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

// ParamInt 获取当前请求的整数变量
func (c *Context) ParamInt(param string, defaultValue ...int) int {
	sources := []func(string) string{
		c.ginCtx().Param,
		c.ginCtx().Query,
		c.ginCtx().PostForm,
	}
	for _, source := range sources {
		if val := source(param); val != "" {
			intVal, err := strconv.Atoi(val)
			if err != nil {
				if len(defaultValue) > 0 {
					return defaultValue[0]
				}
				return 0
			}
			return intVal
		}
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return 0
}

// RequireParams 检查必需参数
func (c *Context) RequireParams(params ...string) bool {
	for _, param := range params {
		if c.Query(param) == "" && c.PostForm(param) == "" {
			c.Fail(fmt.Sprintf("缺少必需参数: %s", param))
			return false
		}
	}
	return true
}

// 数据绑定和验证方法

// BindAndValidate 绑定并验证请求数据
func (c *Context) BindAndValidate(obj interface{}) bool {
	if err := c.ShouldBind(obj); err != nil {
		c.ErrorWithCode(errors.WrapWithMessage(err, errors.ErrCodeInvalidParam, "参数绑定失败"))
		return false
	}
	return true
}

// BindJSON 绑定JSON请求数据并处理错误
func (c *Context) BindJSON(obj interface{}) bool {
	if err := c.ShouldBindJSON(obj); err != nil {
		c.ErrorWithCode(errors.WrapWithMessage(err, errors.ErrCodeInvalidParam, "JSON参数绑定失败"))
		return false
	}
	return true
}

// BindQuery 绑定查询参数并处理错误
func (c *Context) BindQuery(obj interface{}) bool {
	if err := c.ShouldBindQuery(obj); err != nil {
		c.ErrorWithCode(errors.WrapWithMessage(err, errors.ErrCodeInvalidParam, "查询参数绑定失败"))
		return false
	}
	return true
}

// Validate 验证数据
func (c *Context) Validate(v types.Validator) bool {
	if valid, msg := v.Validate(); !valid {
		c.Fail(msg)
		return false
	}
	return true
}

// 请求信息方法

// Method 获取当前请求的方法
func (c *Context) Method() string {
	return c.Request.Method
}

// Host 获取当前请求的主机名
func (c *Context) Host() string {
	return c.Request.Host
}

// Scheme 获取当前请求的协议
func (c *Context) Scheme() string {
	if c.IsSSL() {
		return "https"
	}
	return "http"
}

// URL 获取当前请求的完整URL
func (c *Context) URL() string {
	return c.Request.URL.String()
}

// BaseURL 获取当前请求的基本URL（不含QUERY_STRING）
func (c *Context) BaseURL() string {
	return c.Request.URL.Path
}

// IsSSL 判断是否是SSL
func (c *Context) IsSSL() bool {
	return c.Request.TLS != nil
}

// IsAjax 判断是否是Ajax请求
func (c *Context) IsAjax() bool {
	return c.GetHeader("X-Requested-With") == "XMLHttpRequest"
}

// IsJSON 判断是否是JSON请求
func (c *Context) IsJSON() bool {
	return c.Type() == "json"
}

// Type 获取当前请求的资源类型
// 使用标准库 mime 包解析 Accept 头,更加标准和高效
func (c *Context) Type() string {
	accept := c.GetHeader("Accept")
	if accept == "" {
		return ""
	}

	// 使用 mime.ParseMediaType 解析第一个媒体类型
	// Accept 头格式: "type/subtype; param=value, type2/subtype2"
	mediaTypes := strings.Split(accept, ",")
	if len(mediaTypes) == 0 {
		return ""
	}

	// 解析第一个媒体类型(优先级最高)
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(mediaTypes[0]))
	if err != nil {
		return ""
	}

	// 映射标准 MIME 类型到简化类型名
	switch {
	case mediaType == "application/json" || mediaType == "text/json":
		return "json"
	case mediaType == "application/xml" || mediaType == "text/xml":
		return "xml"
	case mediaType == "text/html" || mediaType == "application/xhtml+xml":
		return "html"
	case mediaType == "text/plain":
		return "text"
	case mediaType == "application/javascript" || mediaType == "text/javascript":
		return "js"
	case mediaType == "text/css":
		return "css"
	case mediaType == "application/pdf":
		return "pdf"
	case mediaType == "text/csv":
		return "csv"
	case mediaType == "application/rss+xml":
		return "rss"
	case mediaType == "application/atom+xml":
		return "atom"
	case mediaType == "application/x-yaml" || mediaType == "text/yaml":
		return "yaml"
	case strings.HasPrefix(mediaType, "image/"):
		return "image"
	case mediaType == "*/*":
		return "html" // 默认返回 html
	default:
		return ""
	}
}

// Domain 获取当前包含协议的域名
func (c *Context) Domain() string {
	return c.Scheme() + "://" + c.Host()
}

// RootDomain 获取当前访问的根域名
// 使用 golang.org/x/net/publicsuffix 获取 eTLD+1 (有效顶级域名+1级)
// 例如: www.example.com -> example.com, blog.example.co.uk -> example.co.uk
func (c *Context) RootDomain() string {
	host := c.Host()
	if host == "" {
		return ""
	}

	// 尝试分离主机名和端口号
	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		// 没有端口号,使用原始 host
		hostOnly = host
	}

	// 移除 IPv6 的方括号
	hostOnly = strings.Trim(hostOnly, "[]")

	// 检查是否是 IP 地址
	if net.ParseIP(hostOnly) != nil {
		return "" // IP 地址没有域名
	}

	// 使用 publicsuffix 包获取 eTLD+1 (有效顶级域名+1)
	// 这会正确处理 .com, .co.uk, .com.cn 等各种公共后缀
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(hostOnly)
	if err != nil {
		// 如果解析失败(例如输入就是 TLD 本身),返回原始主机名
		return hostOnly
	}

	return eTLDPlusOne
}

// 组件访问辅助方法 - 支持延迟初始化

// getComponents 获取组件集合，支持延迟初始化
func (c *Context) getComponents() *contextComponents {
	if c.components == nil {
		c.components = componentsPool.Get().(*contextComponents)
	}
	return c.components
}

// getCache 获取缓存实例
func (c *Context) getCache() *cache.Cache[string, any] {
	return c.getComponents().cache
}

// getErrorHandler 获取错误处理器
func (c *Context) getErrorHandler() types.ErrorHandler {
	return c.getComponents().errorHandler
}

// getJWTAdapter 获取JWT适配器
func (c *Context) getJWTAdapter() *JWTAdapter {
	return c.getComponents().jwtAdapter
}

// getSSEHub 获取SSE中心
func (c *Context) getSSEHub() *sse.Hub {
	return c.getComponents().sseHub
}

// 缓存方法 - 使用延迟初始化优化性能

// CacheSet 设置缓存值
func (c *Context) CacheSet(key string, value interface{}, duration ...time.Duration) {
	if cache := c.getCache(); cache != nil {
		cache.Set(key, value, duration...)
	}
}

// CacheGet 从缓存获取值
func (c *Context) CacheGet(key string) (interface{}, bool) {
	if cache := c.getCache(); cache != nil {
		return cache.Get(key)
	}
	return nil, false
}

// CacheDelete 从缓存删除值
func (c *Context) CacheDelete(key string) {
	if cache := c.getCache(); cache != nil {
		cache.Delete(key)
	}
}

// CacheHas 检查缓存中是否存在键
func (c *Context) CacheHas(key string) bool {
	if cache := c.getCache(); cache != nil {
		return cache.Has(key)
	}
	return false
}

// CacheClear 清空缓存
func (c *Context) CacheClear() {
	if cache := c.getCache(); cache != nil {
		cache.Clear()
	}
}

// JWT方法 - 使用JWT适配器

// SetJWT 设置JWT令牌到Cookie
func (c *Context) SetJWT(token string, maxAge int) {
	c.SetCookie(types.JWTCookieKey, token, maxAge, "/", c.RootDomain(), c.IsSSL(), true)
}

// GetJWT 获取JWT令牌
func (c *Context) GetJWT() string {
	// 从Header获取
	token := c.GetHeader(types.JWTHeaderKey)
	if token != "" {
		return strings.TrimPrefix(token, types.JWTPrefix)
	}

	// 从Query获取
	token = c.Query(types.JWTQueryKey)
	if token != "" {
		return token
	}

	// 从Cookie获取
	token, _ = c.Cookie(types.JWTCookieKey)
	return token
}

// JWTClaimString 获取JWT载荷中的字符串声明
func (c *Context) JWTClaimString(key string) string {
	if key == "" {
		return ""
	}
	payload := c.GetJWTPayload()
	if payload == nil {
		return ""
	}
	if value, exists := payload[key]; exists {
		switch v := value.(type) {
		case string:
			return v
		case fmt.Stringer:
			return v.String()
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// JWTClaimStrings 获取JWT载荷中的字符串数组声明
func (c *Context) JWTClaimStrings(key string) []string {
	if key == "" {
		return nil
	}
	payload := c.GetJWTPayload()
	if payload == nil {
		return nil
	}
	value, exists := payload[key]
	if !exists {
		return nil
	}
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			switch val := item.(type) {
			case string:
				result = append(result, val)
			default:
				result = append(result, fmt.Sprintf("%v", val))
			}
		}
		return result
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return []string{fmt.Sprintf("%v", v)}
	}
}

// AuthInfo 解析JWT载荷为 AuthInfo 结构
func (c *Context) AuthInfo() (*types.AuthInfo, bool) {
	payload := c.GetJWTPayload()
	if payload == nil {
		return nil, false
	}
	info := &types.AuthInfo{
		UserID:   c.JWTClaimString("user_id"),
		Username: c.JWTClaimString("username"),
		Email:    c.JWTClaimString("email"),
		Roles:    c.JWTClaimStrings("roles"),
		Extra:    make(types.H),
	}
	for k, v := range payload {
		info.Extra[k] = v
	}
	return info, true
}

// HasRole 判断当前JWT是否包含指定角色
func (c *Context) HasRole(role string) bool {
	roles := c.JWTClaimStrings("roles")
	if len(roles) == 0 {
		return false
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return false
	}
	for _, r := range roles {
		if strings.ToLower(r) == role {
			return true
		}
	}
	return false
}

// HasAllRoles 判断是否同时拥有所有指定角色
func (c *Context) HasAllRoles(roles ...string) bool {
	if len(roles) == 0 {
		return false
	}
	available := c.JWTClaimStrings("roles")
	if len(available) == 0 {
		return false
	}
	roleMap := make(map[string]struct{}, len(available))
	for _, r := range available {
		roleMap[strings.ToLower(strings.TrimSpace(r))] = struct{}{}
	}
	for _, required := range roles {
		if required == "" {
			continue
		}
		if _, ok := roleMap[strings.ToLower(strings.TrimSpace(required))]; !ok {
			return false
		}
	}
	return true
}

// HasAnyRole 判断是否拥有任意一个指定角色
func (c *Context) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if c.HasRole(role) {
			return true
		}
	}
	return false
}

// GenerateJWT 生成JWT令牌（需要JWT适配器）
func (c *Context) GenerateJWT(payload JWTPayload) (string, error) {
	adapter := c.getJWTAdapter()
	if adapter == nil {
		return "", fmt.Errorf("JWT适配器未初始化")
	}
	return adapter.GenerateToken(payload)
}

// ValidateJWT 验证JWT令牌（需要JWT适配器）
func (c *Context) ValidateJWT(token ...string) (JWTPayload, error) {
	adapter := c.getJWTAdapter()
	if adapter == nil {
		return nil, fmt.Errorf("JWT适配器未初始化")
	}

	tk := c.GetJWT()
	if len(token) > 0 {
		tk = token[0]
	}
	return adapter.ValidateToken(tk)
}

// RequireJWT 要求JWT令牌有效并返回载荷
func (c *Context) RequireJWT(secretKey ...string) (JWTPayload, bool) {
	adapter := c.getJWTAdapter()
	if adapter == nil {
		c.Unauthorized("JWT适配器未初始化")
		return nil, false
	}

	// 获取JWT令牌
	token := c.GetJWT()
	if token == "" {
		c.Unauthorized("未授权访问，请先登录")
		return nil, false
	}

	// 验证JWT令牌
	payload, err := adapter.ValidateToken(token)
	if err != nil {
		c.Unauthorized("未授权访问，请先登录")
		return nil, false
	}

	return payload, true
}

// 文件处理方法

// ValidateFile 验证上传文件
func (c *Context) ValidateFile(file *multipart.FileHeader, config types.UploadConfig) error {
	if config.MaxSize > 0 && file.Size > config.MaxSize {
		return errors.New(errors.ErrCodeInvalidParam).WithMessage("文件大小超过限制")
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	if len(config.AllowedExts) > 0 {
		allowed := false
		for _, allowedExt := range config.AllowedExts {
			if "."+strings.ToLower(allowedExt) == ext {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New(errors.ErrCodeInvalidParam).WithMessage("不支持的文件类型")
		}
	}
	return nil
}

// SaveUploadedFile 保存上传文件
func (c *Context) SaveUploadedFile(file *multipart.FileHeader, config types.UploadConfig) (string, error) {
	if err := c.ValidateFile(file, config); err != nil {
		return "", err
	}

	ext := filepath.Ext(file.Filename)
	newFileName := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	savePath := filepath.Join(config.SavePath, newFileName)

	if err := os.MkdirAll(config.SavePath, 0o755); err != nil {
		return "", errors.Wrap(err, errors.ErrCodeInternal).WithMessage("创建目录失败")
	}

	if err := c.Context.SaveUploadedFile(file, savePath); err != nil {
		return "", errors.Wrap(err, errors.ErrCodeInternal).WithMessage("保存文件失败")
	}

	return newFileName, nil
}

// StreamFile 以 attachment 形式发送文件
func (c *Context) StreamFile(filepath string, filename string) {
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", url.PathEscape(filename)))
	c.File(filepath)
}

// 分页响应方法

// PageResponse 分页响应方法
func (c *Context) PageResponse(list interface{}, totalCount int64, currentPage, pageSize int) {
	if pageSize <= 0 {
		pageSize = 10
	}

	totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))

	if currentPage <= 0 {
		currentPage = 1
	}

	c.JSON(http.StatusOK, types.Response{
		Code: types.SuccessCode,
		Msg:  "success",
		Data: types.ListResponse{
			Data: list,
			Pagination: types.Pagination{
				CurrentPage: currentPage,
				PageSize:    pageSize,
				TotalCount:  totalCount,
				TotalPages:  totalPages,
			},
		},
	})
	c.Abort()
}

// Paginate 分页参数处理
func (c *Context) Paginate(defaultPageSize ...int) (page, pageSize int) {
	page = 1
	pageSize = 10

	if len(defaultPageSize) > 0 && defaultPageSize[0] > 0 {
		pageSize = defaultPageSize[0]
	}

	if p := c.Query("page"); p != "" {
		if val, err := strconv.Atoi(p); err == nil && val > 0 {
			page = val
		}
	}

	if ps := c.Query("page_size"); ps != "" {
		if val, err := strconv.Atoi(ps); err == nil && val > 0 {
			pageSize = val
		}
	}

	if pageSize > 100 {
		pageSize = 100
	}

	return page, pageSize
}

// PaginateResponse 组合 Paginate 与 PageResponse
func (c *Context) PaginateResponse(fetch func(page, size int) (interface{}, int64)) {
	page, size := c.Paginate()
	data, total := fetch(page, size)
	c.PageResponse(data, total, page, size)
}

// URL构建方法

// BuildURL 创建一个 URLBuilder 实例
func (c *Context) BuildURL(path string) *URLBuilder {
	return &URLBuilder{
		scheme: c.Scheme(),
		path:   path,
	}
}

// URLBuilder 结构体用于构建 URL
type URLBuilder struct {
	domain, path, ext, scheme string
	params                    H
	err                       error
}

// Set 设置 URL 的Query参数
func (ub *URLBuilder) Set(query string, value interface{}) *URLBuilder {
	if ub.err != nil {
		return ub
	}

	if query == "" {
		ub.err = fmt.Errorf("查询参数键不能为空")
		return ub
	}

	if ub.params == nil {
		ub.params = H{}
	}
	ub.params[query] = value
	return ub
}

// Scheme 设置 URL 的访问协议
func (ub *URLBuilder) Scheme(scheme string) *URLBuilder {
	if ub.err != nil {
		return ub
	}
	ub.scheme = scheme
	return ub
}

// Domain 设置是否使用域名
func (ub *URLBuilder) Domain(domain string) *URLBuilder {
	if ub.err != nil {
		return ub
	}

	if domain == "" {
		ub.err = fmt.Errorf("域名不能为空")
		return ub
	}

	ub.domain = domain
	return ub
}

// Build 生成最终的 URL
func (ub *URLBuilder) Build() string {
	if ub.err != nil {
		return ""
	}

	u := &url.URL{}

	if ub.domain != "" {
		u.Scheme = ub.scheme
		if u.Scheme == "" {
			u.Scheme = "http"
		}
		u.Host = ub.domain
		ub.path = strings.TrimLeft(ub.path, "/")
	}

	if ub.ext != "" {
		ub.path += "." + ub.ext
	}
	u.Path = ub.path

	if len(ub.params) > 0 {
		query := u.Query()
		for key, value := range ub.params {
			query.Set(key, fmt.Sprintf("%v", value))
		}
		u.RawQuery = query.Encode()
	}

	return u.String()
}

// SSE方法

// NewSSEClient 创建新的 SSE 客户端连接
func (c *Context) NewSSEClient(filters ...string) *sse.Client {
	return c.NewSSEClientWithOptions(filters, nil...)
}

// NewSSEClientWithOptions 创建带选项的 SSE 客户端
func (c *Context) NewSSEClientWithOptions(filters []string, opts ...sse.ClientOption) *sse.Client {
	hub := c.getSSEHub()
	if hub == nil {
		return nil
	}

	client := sse.NewClient(c.Writer, c.Request, filters...)
	sse.ApplyClientOptions(client, opts...)
	hub.RegisterClient(client)
	return client
}

// BroadcastSSE 广播SSE事件
func (c *Context) BroadcastSSE(event *sse.Event) {
	if hub := c.getSSEHub(); hub != nil {
		hub.Broadcast(event)
	}
}

// 安全相关方法

// CSRFToken 生成CSRF令牌
func (c *Context) CSRFToken() string {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(token)
}

// SetCSRFToken 设置CSRF令牌
func (c *Context) SetCSRFToken() string {
	token := c.CSRFToken()
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("csrf_token", token, 3600, "/", c.RootDomain(), c.IsSSL(), true)
	return token
}

// SetSecureHeaders 设置常用安全头
func (c *Context) SetSecureHeaders() {
	c.Header("X-XSS-Protection", "1; mode=block")
	c.Header("X-Frame-Options", "SAMEORIGIN")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
}

// 其他辅助方法

// Language 获取客户端语言
// 使用 golang.org/x/text/language 标准库解析 Accept-Language 头
func (c *Context) Language() string {
	accept := c.GetHeader("Accept-Language")
	if accept == "" {
		return "zh-CN"
	}

	tags, _, err := language.ParseAcceptLanguage(accept)
	if err != nil || len(tags) == 0 {
		return "zh-CN"
	}

	return tags[0].String()
}

// GetIntSlice 获取整型切片
// 使用 strings.FieldsFunc 自动过滤空值和处理分隔符
func (c *Context) GetIntSlice(key string, sep ...string) []int {
	separator := ","
	if len(sep) > 0 && sep[0] != "" {
		separator = sep[0]
	}

	str := c.Query(key)
	if str == "" {
		str = c.PostForm(key)
	}

	if str == "" {
		return []int{}
	}

	parts := strings.Split(str, separator)
	result := make([]int, 0, len(parts))

	for _, part := range parts {
		// TrimSpace 自动去除首尾空格
		part = strings.TrimSpace(part)
		if part == "" {
			continue // 跳过空值
		}
		if val, err := strconv.Atoi(part); err == nil {
			result = append(result, val)
		}
	}

	return result
}

// 设置组件方法 - 优化版本，支持延迟初始化

// SetCache 设置缓存实例
func (c *Context) SetCache(cache *cache.Cache[string, any]) {
	c.getComponents().cache = cache
}

// SetErrorHandler 设置错误处理器
func (c *Context) SetErrorHandler(handler types.ErrorHandler) {
	c.getComponents().errorHandler = handler
}

// SetJWTAdapter 设置JWT适配器
func (c *Context) SetJWTAdapter(adapter *JWTAdapter) {
	c.getComponents().jwtAdapter = adapter
}

// GetJWTPayload 获取JWT载荷
func (c *Context) GetJWTPayload() JWTPayload {
	if payload, exists := c.Get("jwt_payload"); exists {
		if jwtPayload, ok := payload.(JWTPayload); ok {
			return jwtPayload
		}
	}
	return nil
}

// SetJWTPayload 设置JWT载荷到上下文
func (c *Context) SetJWTPayload(payload JWTPayload) {
	c.Set("jwt_payload", payload)
}

// SetSSEHub 设置SSE中心
func (c *Context) SetSSEHub(hub *sse.Hub) {
	c.getComponents().sseHub = hub
}

// setGlobalCache 设置全局缓存（内部方法）
func (c *Context) setGlobalCache(cache *cache.Cache[string, any]) {
	c.getComponents().cache = cache
}

// GetGlobalCache 获取全局缓存
func (c *Context) GetGlobalCache() *cache.Cache[string, any] {
	return c.getCache()
}

// CreateJWTSession 创建JWT会话
func (c *Context) CreateJWTSession(secretKey string, duration time.Duration, payload types.H) (string, error) {
	adapter := c.getJWTAdapter()
	if adapter == nil {
		return "", fmt.Errorf("JWT适配器未初始化")
	}

	// 转换payload为JWTPayload类型
	jwtPayload := make(JWTPayload)
	for k, v := range payload {
		jwtPayload[k] = v
	}

	// 设置过期时间
	jwtPayload["exp"] = time.Now().Add(duration).Unix()

	// JWT适配器自己管理密钥，不需要使用secretKey参数
	token, err := adapter.GenerateToken(jwtPayload)
	if err != nil {
		return "", err
	}

	// 设置JWT到cookie
	c.SetJWT(token, int(duration.Seconds()))
	return token, nil
}

// RefreshJWTSession 刷新JWT会话
func (c *Context) RefreshJWTSession(secretKey string, duration time.Duration) (string, error) {
	adapter := c.getJWTAdapter()
	if adapter == nil {
		return "", fmt.Errorf("JWT适配器未初始化")
	}

	// 获取当前JWT
	currentToken := c.GetJWT()
	if currentToken == "" {
		return "", fmt.Errorf("未找到JWT令牌")
	}

	// 验证当前令牌
	payload, err := adapter.ValidateToken(currentToken)
	if err != nil {
		return "", fmt.Errorf("当前JWT令牌无效: %v", err)
	}

	// 更新过期时间
	payload["exp"] = time.Now().Add(duration).Unix()

	// JWT适配器自己管理密钥，不需要使用secretKey参数
	// 生成新令牌
	newToken, err := adapter.GenerateToken(payload)
	if err != nil {
		return "", err
	}

	// 设置新的JWT到cookie
	c.SetJWT(newToken, int(duration.Seconds()))
	return newToken, nil
}

// ClearJWT 清除JWT
func (c *Context) ClearJWT() {
	c.SetCookie("token", "", -1, "/", "", false, true)
}

// SessionGetString 从会话中获取字符串值
func (c *Context) SessionGetString(key string) string {
	// 这里简化实现，从JWT payload中获取值
	adapter := c.getJWTAdapter()
	if adapter == nil {
		return ""
	}

	token := c.GetJWT()
	if token == "" {
		return ""
	}

	payload, err := adapter.ValidateToken(token)
	if err != nil {
		return ""
	}

	if val, exists := payload[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// SuccessWithMsg 成功响应带自定义消息
func (c *Context) SuccessWithMsg(msg string, data interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusOK, types.Response{
		Code: types.SuccessCode,
		Msg:  msg,
		Data: data,
		URL:  respUrl,
	})
	c.Abort()
}

// Created 创建成功响应 (201)
func (c *Context) Created(data interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusCreated, types.Response{
		Code: http.StatusCreated,
		Msg:  "created",
		Data: data,
		URL:  respUrl,
	})
	c.Abort()
}

// Accepted 接受处理响应 (202)
func (c *Context) Accepted(msg string, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusAccepted, types.Response{
		Code: http.StatusAccepted,
		Msg:  msg,
		Data: nil,
		URL:  respUrl,
	})
	c.Abort()
}

// NoContent 无内容响应 (204)
func (c *Context) NoContent() {
	c.Status(http.StatusNoContent)
	c.Abort()
}

// ValidationError 验证错误响应 (422)
func (c *Context) ValidationError(errors interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusUnprocessableEntity, types.Response{
		Code: http.StatusUnprocessableEntity,
		Msg:  "validation failed",
		Data: errors,
		URL:  respUrl,
	})
	c.Abort()
}

// Paginated 分页响应
func (c *Context) Paginated(data interface{}, page, pageSize, total int64, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}

	response := H{
		"list": data,
		"pagination": H{
			"page":      page,
			"page_size": pageSize,
			"total":     total,
			"has_more":  (page * pageSize) < total,
		},
	}

	c.JSON(http.StatusOK, types.Response{
		Code: types.SuccessCode,
		Msg:  "success",
		Data: response,
		URL:  respUrl,
	})
	c.Abort()
}

// ServerError 服务器错误响应 (500)
func (c *Context) ServerError(msg ...string) {
	message := "internal server error"
	if len(msg) > 0 {
		message = msg[0]
	}
	c.JSON(http.StatusInternalServerError, types.Response{
		Code: http.StatusInternalServerError,
		Msg:  message,
		Data: nil,
	})
	c.Abort()
}

// GetCache 获取缓存实例
func (c *Context) GetCache() *cache.Cache[string, any] {
	return c.getCache()
}

// Port 获取请求端口
func (c *Context) Port() string {
	parts := strings.Split(c.Request.Host, ":")
	if len(parts) > 1 {
		return parts[1]
	}
	// 根据协议返回默认端口
	if c.IsSSL() {
		return "443"
	}
	return "80"
}

// SetCSP 设置内容安全策略
func (c *Context) SetCSP(policy string) {
	c.Header("Content-Security-Policy", policy)
}

// SetXFrameOptions 设置X-Frame-Options头
func (c *Context) SetXFrameOptions(option string) {
	c.Header("X-Frame-Options", option)
}

// 性能优化相关方法

// Reset 重置Context状态（用于对象池）
func (c *Context) Reset() {
	if c.components != nil {
		// 清理组件状态但不释放到池中（由releaseContext处理）
		c.components.cache = nil
		c.components.errorHandler = nil
		c.components.jwtAdapter = nil
		c.components.sseHub = nil
	}
}

// IsPooled 检查Context是否来自对象池
func (c *Context) IsPooled() bool {
	return c.pooled
}

// Clone 克隆Context（深拷贝组件）
func (c *Context) Clone() *Context {
	clone := &Context{
		Context: c.Context,
		pooled:  false, // 克隆的实例不放回池中
	}

	// 如果原Context有组件，则复制组件
	if c.components != nil {
		clone.components = &contextComponents{
			cache:        c.components.cache,        // 缓存实例可以共享
			errorHandler: c.components.errorHandler, // 错误处理器可以共享
			jwtAdapter:   c.components.jwtAdapter,   // JWT适配器可以共享
			sseHub:       c.components.sseHub,       // SSE中心可以共享
		}
	}

	return clone
}

// WithComponents 设置多个组件（链式调用）
func (c *Context) WithComponents(cache *cache.Cache[string, any],
	errorHandler types.ErrorHandler, jwtAdapter *JWTAdapter, sseHub *sse.Hub,
) *Context {
	if cache != nil {
		c.SetCache(cache)
	}
	if errorHandler != nil {
		c.SetErrorHandler(errorHandler)
	}
	if jwtAdapter != nil {
		c.SetJWTAdapter(jwtAdapter)
	}
	if sseHub != nil {
		c.SetSSEHub(sseHub)
	}
	return c
}

// HasComponents 检查是否已初始化组件
func (c *Context) HasComponents() bool {
	return c.components != nil
}

// ComponentsCount 获取已设置的组件数量（用于调试）
func (c *Context) ComponentsCount() int {
	if c.components == nil {
		return 0
	}

	count := 0
	if c.components.cache != nil {
		count++
	}
	if c.components.errorHandler != nil {
		count++
	}
	if c.components.jwtAdapter != nil {
		count++
	}
	if c.components.sseHub != nil {
		count++
	}
	return count
}

// newContext 创建一个新的Context实例 - 优化版本，支持对象池化
func newContext(c *gin.Context) *Context {
	// 检查是否已经包装过
	if existingCtx, ok := c.Get("_context_instance"); ok {
		if ctx, ok := existingCtx.(*Context); ok {
			return ctx
		}
	}

	// 从对象池获取Context实例
	ctx := contextPool.Get().(*Context)

	// 重置Context状态
	ctx.Context = c
	ctx.components = nil // 延迟初始化
	ctx.pooled = true

	// 存储在gin上下文中以便复用
	c.Set("_context_instance", ctx)

	return ctx
}

// releaseContext 释放Context实例回对象池 - 性能优化
func releaseContext(ctx *Context) {
	if !ctx.pooled {
		return
	}

	// 重置Context状态
	ctx.Context = nil

	// 释放组件到对象池
	if ctx.components != nil {
		// 清理组件状态
		ctx.components.cache = nil
		ctx.components.errorHandler = nil
		ctx.components.jwtAdapter = nil
		ctx.components.sseHub = nil

		// 放回组件池
		componentsPool.Put(ctx.components)
		ctx.components = nil
	}

	// 放回Context池
	contextPool.Put(ctx)
}

// NewContext 创建新的Context实例（公共方法）
func NewContext(c *gin.Context) *Context {
	return newContext(c)
}

// NewContextWithComponents 创建带组件的Context实例
func NewContextWithComponents(c *gin.Context, cache *cache.Cache[string, any],
	errorHandler types.ErrorHandler, jwtAdapter *JWTAdapter, sseHub *sse.Hub,
) *Context {
	ctx := newContext(c)

	// 设置组件
	if cache != nil {
		ctx.SetCache(cache)
	}
	if errorHandler != nil {
		ctx.SetErrorHandler(errorHandler)
	}
	if jwtAdapter != nil {
		ctx.SetJWTAdapter(jwtAdapter)
	}
	if sseHub != nil {
		ctx.SetSSEHub(sseHub)
	}

	return ctx
}

// Next 覆盖gin.Context的Next方法，支持中间件管理器的控制
func (c *Context) Next() {
	c.nextCalled = true
	if c.nextFunc != nil {
		c.nextFunc()
	} else {
		// 如果没有自定义next函数，调用gin的原始Next方法
		c.Context.Next()
	}
}
