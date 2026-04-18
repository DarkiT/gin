// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/darkit/gin/pkg/cache"
	"github.com/darkit/gin/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// ErrMissingParameter 表示请求缺少必需参数。
var ErrMissingParameter = errors.New("缺少必需参数")

const requestIDHeader = "X-Request-ID"

// Context 是增强版请求上下文，封装 gin.Context 并绑定 Engine。
type Context struct {
	*gin.Context
	engine         *Engine
	requestContext context.Context
}

// baseContext 返回当前请求对应的标准库 context.Context。
// 即使增强 Context 在请求结束后被继续持有，也优先使用捕获到的 request context，
// 避免访问已回收的 gin.Context 导致 panic。
func (c *Context) baseContext() context.Context {
	if c == nil {
		return context.Background()
	}
	if c.requestContext != nil {
		return c.requestContext
	}
	if c.Context != nil && c.Context.Request != nil {
		return c.Context.Request.Context()
	}
	return context.Background()
}

// Deadline 实现 context.Context，返回请求上下文的截止时间。
func (c *Context) Deadline() (time.Time, bool) {
	return c.baseContext().Deadline()
}

// Done 实现 context.Context，返回请求上下文的取消信号。
func (c *Context) Done() <-chan struct{} {
	return c.baseContext().Done()
}

// Err 实现 context.Context，返回请求上下文的错误状态。
func (c *Context) Err() error {
	return c.baseContext().Err()
}

// Value 实现 context.Context，读取请求上下文中的键值。
func (c *Context) Value(key any) any {
	return c.baseContext().Value(key)
}

// Copy 返回一个可安全在请求作用域外使用的上下文副本。
func (c *Context) Copy() *Context {
	if c == nil {
		return nil
	}
	if c.Context == nil {
		return &Context{
			engine:         c.engine,
			requestContext: c.baseContext(),
		}
	}
	cp := c.Context.Copy()
	return &Context{
		Context:        cp,
		engine:         c.engine,
		requestContext: c.baseContext(),
	}
}

// Handler 返回当前主处理器。
func (c *Context) Handler() HandlerFunc {
	if c == nil || c.Context == nil {
		return nil
	}
	handler := c.Context.Handler()
	if handler == nil {
		return nil
	}
	return func(ctx *Context) {
		if ctx == nil || ctx.Context == nil {
			return
		}
		handler(ctx.Context)
	}
}

// GetIP 返回客户端真实 IP，优先读取 X-Real-IP/X-Forwarded-For。
func (c *Context) GetIP() string {
	if ip := c.Request.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if ip := c.Request.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return c.ClientIP()
}

// GetUserAgent 返回请求的 User-Agent。
func (c *Context) GetUserAgent() string {
	return c.Request.Header.Get("User-Agent")
}

// IsAjax 判断是否为 AJAX 请求（X-Requested-With）。
func (c *Context) IsAjax() bool {
	return c.Request.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// IsJSON 判断请求 Content-Type 是否包含 application/json。
func (c *Context) IsJSON() bool {
	return strings.Contains(c.Request.Header.Get("Content-Type"), "application/json")
}

// Param 获取路径参数，行为与上游 gin 保持一致。
func (c *Context) Param(key string) string {
	if c == nil || c.Context == nil {
		return ""
	}
	return c.Context.Param(key)
}

// Input 获取路径/查询/表单参数，并支持默认值。
func (c *Context) Input(key string, def ...string) string {
	for i := len(c.Params) - 1; i >= 0; i-- {
		if c.Params[i].Key == key {
			return c.Params[i].Value
		}
	}
	if val := c.Query(key); val != "" {
		return val
	}
	if val := c.PostForm(key); val != "" {
		return val
	}
	if len(def) > 0 {
		return def[0]
	}
	return ""
}

// ParamInt 获取整型参数，支持默认值。
func (c *Context) ParamInt(key string, def ...int) int {
	val := c.Input(key)
	if val == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	intVal, _ := strconv.Atoi(val)
	return intVal
}

// ParamInt64 获取 int64 参数，支持默认值。
func (c *Context) ParamInt64(key string, def ...int64) int64 {
	val := c.Input(key)
	if val == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	intVal, _ := strconv.ParseInt(val, 10, 64)
	return intVal
}

// ParamFloat 获取 float64 参数，支持默认值。
func (c *Context) ParamFloat(key string, def ...float64) float64 {
	val := c.Input(key)
	if val == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0.0
	}
	floatVal, _ := strconv.ParseFloat(val, 64)
	return floatVal
}

// ParamBool 获取布尔参数，支持默认值。
func (c *Context) ParamBool(key string, def ...bool) bool {
	val := c.Input(key)
	if val == "" {
		if len(def) > 0 {
			return def[0]
		}
		return false
	}
	boolVal, _ := strconv.ParseBool(val)
	return boolVal
}

// ============================================================
// 带错误返回的参数转换方法
// ============================================================

// ErrParamNotFound 表示参数不存在。
var ErrParamNotFound = errors.New("参数不存在")

// ErrParamInvalid 表示参数格式无效。
var ErrParamInvalid = errors.New("参数格式无效")

// ParamIntE 获取整型参数，返回错误信息。
// 可区分参数不存在和格式错误两种情况。
func (c *Context) ParamIntE(key string) (int, error) {
	val := c.Input(key)
	if val == "" {
		return 0, ErrParamNotFound
	}
	intVal, err := strconv.Atoi(val)
	if err != nil {
		return 0, ErrParamInvalid
	}
	return intVal, nil
}

// ParamInt64E 获取 int64 参数，返回错误信息。
func (c *Context) ParamInt64E(key string) (int64, error) {
	val := c.Input(key)
	if val == "" {
		return 0, ErrParamNotFound
	}
	intVal, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, ErrParamInvalid
	}
	return intVal, nil
}

// ParamFloatE 获取 float64 参数，返回错误信息。
func (c *Context) ParamFloatE(key string) (float64, error) {
	val := c.Input(key)
	if val == "" {
		return 0, ErrParamNotFound
	}
	floatVal, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0, ErrParamInvalid
	}
	return floatVal, nil
}

// ParamBoolE 获取布尔参数，返回错误信息。
func (c *Context) ParamBoolE(key string) (bool, error) {
	val := c.Input(key)
	if val == "" {
		return false, ErrParamNotFound
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false, ErrParamInvalid
	}
	return boolVal, nil
}

// MustParamInt 获取整型参数，参数不存在或格式错误时 panic。
func (c *Context) MustParamInt(key string) int {
	val, err := c.ParamIntE(key)
	if err != nil {
		panic("context: param '" + key + "' " + err.Error())
	}
	return val
}

// MustParamInt64 获取 int64 参数，参数不存在或格式错误时 panic。
func (c *Context) MustParamInt64(key string) int64 {
	val, err := c.ParamInt64E(key)
	if err != nil {
		panic("context: param '" + key + "' " + err.Error())
	}
	return val
}

// MustParamFloat 获取 float64 参数，参数不存在或格式错误时 panic。
func (c *Context) MustParamFloat(key string) float64 {
	val, err := c.ParamFloatE(key)
	if err != nil {
		panic("context: param '" + key + "' " + err.Error())
	}
	return val
}

// MustParamBool 获取布尔参数，参数不存在或格式错误时 panic。
func (c *Context) MustParamBool(key string) bool {
	val, err := c.ParamBoolE(key)
	if err != nil {
		panic("context: param '" + key + "' " + err.Error())
	}
	return val
}

// RequireParams 检查必需参数是否存在，缺失时返回 ErrMissingParameter。
func (c *Context) RequireParams(keys ...string) error {
	for _, key := range keys {
		if c.Input(key) == "" {
			return ErrMissingParameter
		}
	}
	return nil
}

// BindAndValidate 绑定并校验请求参数。
func (c *Context) BindAndValidate(obj any) error {
	return c.ShouldBind(obj)
}

// BindJSONOrAbort 绑定 JSON 并在失败时返回 422。
func (c *Context) BindJSONOrAbort(obj any) bool {
	if err := c.ShouldBindJSON(obj); err != nil {
		c.ValidationError(ExtractValidationErrors(err))
		c.Abort()
		return false
	}
	return true
}

// BindQueryOrAbort 绑定 Query 并在失败时返回 422。
func (c *Context) BindQueryOrAbort(obj any) bool {
	if err := c.ShouldBindQuery(obj); err != nil {
		c.ValidationError(ExtractValidationErrors(err))
		c.Abort()
		return false
	}
	return true
}

// ExtractValidationErrors 将校验错误转为标准结构。
func ExtractValidationErrors(err error) []ValidationError {
	if err == nil {
		return nil
	}
	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		errs := make([]ValidationError, 0, len(ve))
		for _, fe := range ve {
			errs = append(errs, ValidationError{
				Field:   fe.Field(),
				Tag:     fe.Tag(),
				Param:   fe.Param(),
				Message: formatValidationMessage(fe),
			})
		}
		return errs
	}
	return []ValidationError{{Field: "", Message: err.Error()}}
}

// formatValidationMessage 生成人类可读的验证错误消息。
func formatValidationMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fe.Field() + " 是必填字段"
	case "min":
		return fe.Field() + " 最小值为 " + fe.Param()
	case "max":
		return fe.Field() + " 最大值为 " + fe.Param()
	case "len":
		return fe.Field() + " 长度必须为 " + fe.Param()
	case "email":
		return fe.Field() + " 必须是有效的邮箱地址"
	case "url":
		return fe.Field() + " 必须是有效的 URL"
	case "oneof":
		return fe.Field() + " 必须是以下值之一: " + fe.Param()
	case "gt":
		return fe.Field() + " 必须大于 " + fe.Param()
	case "gte":
		return fe.Field() + " 必须大于或等于 " + fe.Param()
	case "lt":
		return fe.Field() + " 必须小于 " + fe.Param()
	case "lte":
		return fe.Field() + " 必须小于或等于 " + fe.Param()
	default:
		return fe.Field() + " 验证失败: " + fe.Tag()
	}
}

// OK 返回 200 成功响应。
func (c *Context) Success(data any) {
	c.JSON(http.StatusOK, newResponse(http.StatusOK, "success", data, c.getRequestID()))
}

// SuccessWithMessage 返回成功响应，同时包含自定义消息。
func (c *Context) SuccessWithMessage(data interface{}, message string) {
	c.JSON(http.StatusOK, newResponse(http.StatusOK, message, data, c.getRequestID()))
}

// Created 返回 201 创建成功响应。
func (c *Context) Created(data any) {
	c.JSON(http.StatusCreated, newResponse(http.StatusCreated, "created", data, c.getRequestID()))
}

// Accepted 返回 202 已接收响应。
func (c *Context) Accepted(data any) {
	c.JSON(http.StatusAccepted, newResponse(http.StatusAccepted, "accepted", data, c.getRequestID()))
}

// NoContent 返回 204 无内容响应。
func (c *Context) NoContent() {
	c.Status(http.StatusNoContent)
}

// Paginated 返回分页数据响应。
func (c *Context) Paginated(data any, page, perPage int, total int64) {
	pagination := NewPagination(page, perPage, total)
	c.JSON(http.StatusOK, newPaginatedResponse(http.StatusOK, "success", data, pagination, c.getRequestID()))
}

// ParsePagination 解析分页参数。
// 默认 page=1、per_page=20，支持 page、per_page、page_size、limit。
func (c *Context) ParsePagination(defaults ...int) (page, perPage int) {
	defaultPage := 1
	defaultPerPage := 20
	if len(defaults) > 0 {
		defaultPage = normalizeDefault(defaults[0], defaultPage)
	}
	if len(defaults) > 1 {
		defaultPerPage = normalizeDefault(defaults[1], defaultPerPage)
	}
	page = parsePositiveInt(c.Input("page"), defaultPage)
	perPageValue := firstNonEmpty(
		c.Input("per_page"),
		c.Input("page_size"),
		c.Input("limit"),
	)
	perPage = parsePositiveInt(perPageValue, defaultPerPage)
	return page, perPage
}

// PaginationParams 解析分页参数并返回结构体。
func (c *Context) PaginationParams(opts ...PaginationOption) *PaginationParams {
	options := defaultPaginationOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	page := parsePositiveInt(c.Input("page"), options.defaultPage)
	perPageValue := firstNonEmpty(
		c.Input("per_page"),
		c.Input("page_size"),
		c.Input("limit"),
	)
	perPage := parsePositiveInt(perPageValue, options.defaultPerPage)
	perPage = applyMaxPerPage(perPage, options.maxPerPage)
	return &PaginationParams{
		Page:    page,
		PerPage: perPage,
		Offset:  calculateOffset(page, perPage),
	}
}

// BadRequest 返回 400 错误响应。
func (c *Context) BadRequest(message string) {
	c.JSON(http.StatusBadRequest, newErrorResponse(http.StatusBadRequest, message, nil, c.getRequestID()))
}

// Unauthorized 返回 401 错误响应。
func (c *Context) Unauthorized(message string) {
	c.JSON(http.StatusUnauthorized, newErrorResponse(http.StatusUnauthorized, message, nil, c.getRequestID()))
}

// Forbidden 返回 403 错误响应。
func (c *Context) Forbidden(message string) {
	c.JSON(http.StatusForbidden, newErrorResponse(http.StatusForbidden, message, nil, c.getRequestID()))
}

// NotFound 返回 404 错误响应。
func (c *Context) NotFound(message string) {
	c.JSON(http.StatusNotFound, newErrorResponse(http.StatusNotFound, message, nil, c.getRequestID()))
}

// Conflict 返回 409 错误响应。
func (c *Context) Conflict(message string) {
	c.JSON(http.StatusConflict, newErrorResponse(http.StatusConflict, message, nil, c.getRequestID()))
}

// ValidationError 返回 422 校验失败响应。
func (c *Context) ValidationError(errors []ValidationError) {
	c.JSON(http.StatusUnprocessableEntity, newErrorResponse(http.StatusUnprocessableEntity, "validation failed", errors, c.getRequestID()))
}

// InternalError 返回 500 错误响应。
func (c *Context) InternalError(message string) {
	c.JSON(http.StatusInternalServerError, newErrorResponse(http.StatusInternalServerError, message, nil, c.getRequestID()))
}

// Error 追加错误到 gin 的错误列表并返回错误对象。
func (c *Context) Error(err error) *Error {
	if c == nil || c.Context == nil {
		if err == nil {
			return nil
		}
		return &Error{Err: err}
	}
	return c.Context.Error(err)
}

// ErrorResponse 返回指定状态码的统一错误响应。
func (c *Context) ErrorResponse(code int, message string) {
	c.JSON(code, newErrorResponse(code, message, nil, c.getRequestID()))
}

// Logger 返回当前 Engine 的日志器。
func (c *Context) Logger() logger.Logger {
	if c.engine != nil && c.engine.logger != nil {
		return c.engine.logger
	}
	return logger.NewNoop()
}

// Cache 返回当前 Engine 的缓存实现。
func (c *Context) Cache() cache.Cache {
	if c.engine != nil && c.engine.cache != nil {
		return c.engine.cache
	}
	return nil
}

// SetEngine 设置上下文关联的 Engine。
func (c *Context) SetEngine(e *Engine) {
	c.engine = e
	if c.requestContext == nil && c.Context != nil && c.Context.Request != nil {
		c.requestContext = c.Context.Request.Context()
	}
}

// RequestID 获取请求 ID，优先从上下文获取，其次从 Header 获取。
func (c *Context) RequestID() string {
	if id := c.getRequestID(); id != "" {
		return id
	}
	return c.GetHeader(requestIDHeader)
}

// SetRequestID 设置请求 ID 并写入响应 Header。
func (c *Context) SetRequestID(id string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	c.Set("request_id", id)
	c.Header(requestIDHeader, id)
}

func (c *Context) getRequestID() string {
	if id, exists := c.Get("request_id"); exists {
		if str, ok := id.(string); ok {
			return str
		}
	}
	return ""
}

// RequireParamsOrAbort 批量参数校验，缺失时自动返回 400。
func (c *Context) RequireParamsOrAbort(keys ...string) bool {
	if err := c.RequireParams(keys...); err != nil {
		c.BadRequest(err.Error())
		c.Abort()
		return false
	}
	return true
}

// GetQueryInt 获取 Query 参数（整型）。
func (c *Context) GetQueryInt(key string, def ...int) int {
	val := c.Query(key)
	if val == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	intVal, _ := strconv.Atoi(val)
	return intVal
}

// GetQueryBool 获取 Query 参数（布尔型）。
func (c *Context) GetQueryBool(key string, def ...bool) bool {
	val := c.Query(key)
	if val == "" {
		if len(def) > 0 {
			return def[0]
		}
		return false
	}
	return val == "true" || val == "1" || val == "yes"
}

// JSONOrAbort 绑定 JSON 并在失败时自动返回 400。
func (c *Context) JSONOrAbort(obj interface{}) bool {
	if err := c.ShouldBindJSON(obj); err != nil {
		c.BadRequest("请求格式错误: " + err.Error())
		c.Abort()
		return false
	}
	return true
}

// OKIf 条件响应（条件为真则返回 200，否则返回 404）。
func (c *Context) OKIf(condition bool, data interface{}, notFoundMsg ...string) {
	if condition {
		c.Success(data)
		return
	}
	msg := "资源不存在"
	if len(notFoundMsg) > 0 {
		msg = notFoundMsg[0]
	}
	c.NotFound(msg)
}

// RedirectPermanent 永久重定向（301）。
func (c *Context) RedirectPermanent(location string) {
	c.Redirect(http.StatusMovedPermanently, location)
}

// RedirectTemporary 临时重定向（302）。
func (c *Context) RedirectTemporary(location string) {
	c.Redirect(http.StatusFound, location)
}

// SetSecureCookie 设置安全 Cookie（HttpOnly + Secure + SameSite）。
func (c *Context) SetSecureCookie(name, value string, maxAge int) {
	// 手动构建 Set-Cookie 头以支持 SameSite 属性
	cookieStr := name + "=" + value
	cookieStr += "; Path=/"
	if maxAge > 0 {
		cookieStr += "; Max-Age=" + strconv.Itoa(maxAge)
	}
	cookieStr += "; Secure; HttpOnly; SameSite=Strict"
	c.Writer.Header().Add("Set-Cookie", cookieStr)
}

// GetCookieOr 获取 Cookie，不存在时返回默认值。
func (c *Context) GetCookieOr(name string, def string) string {
	cookie, err := c.Cookie(name)
	if err != nil {
		return def
	}
	return cookie
}

// DeleteCookie 删除 Cookie。
func (c *Context) DeleteCookie(name string) {
	c.SetCookie(name, "", -1, "/", "", false, true)
}

// CookieOptions 定义 Cookie 设置选项。
type CookieOptions struct {
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// SetCookieWithOptions 通过选项设置 Cookie。
func (c *Context) SetCookieWithOptions(name, value string, opts CookieOptions) {
	if opts.Path == "" {
		opts.Path = "/"
	}
	if opts.SameSite != http.SameSiteDefaultMode {
		c.SetSameSite(opts.SameSite)
	}
	c.SetCookie(name, value, opts.MaxAge, opts.Path, opts.Domain, opts.Secure, opts.HttpOnly)
}

// IsMethod 判断请求方法。
func (c *Context) IsMethod(method string) bool {
	return c.Request.Method == method
}

// IsGET 是否为 GET 请求。
func (c *Context) IsGET() bool {
	return c.IsMethod("GET")
}

// IsPOST 是否为 POST 请求。
func (c *Context) IsPOST() bool {
	return c.IsMethod("POST")
}

// AcceptsJSON 客户端是否接受 JSON 响应。
func (c *Context) AcceptsJSON() bool {
	accept := c.GetHeader("Accept")
	return strings.Contains(accept, "application/json")
}

// AcceptsHTML 客户端是否接受 HTML 响应。
func (c *Context) AcceptsHTML() bool {
	accept := c.GetHeader("Accept")
	return strings.Contains(accept, "text/html")
}

// Negotiate 内容协商，保持与上游 gin 一致。
func (c *Context) Negotiate(code int, config Negotiate) {
	if c == nil || c.Context == nil {
		return
	}
	c.Context.Negotiate(code, gin.Negotiate(config))
}

// AutoNegotiate 根据 Accept 头自动返回 JSON/HTML。
func (c *Context) AutoNegotiate(data interface{}) {
	if c.AcceptsJSON() {
		c.JSON(http.StatusOK, data)
	} else if c.AcceptsHTML() {
		c.HTML(http.StatusOK, "index.html", data)
	} else {
		c.JSON(http.StatusOK, data)
	}
}

// ============================================================
// P0 - RESTful API 必备方法
// ============================================================

// IsPUT 判断是否 PUT 请求。
func (c *Context) IsPUT() bool {
	return c.Request.Method == http.MethodPut
}

// IsPATCH 判断是否 PATCH 请求。
func (c *Context) IsPATCH() bool {
	return c.Request.Method == http.MethodPatch
}

// IsDELETE 判断是否 DELETE 请求。
func (c *Context) IsDELETE() bool {
	return c.Request.Method == http.MethodDelete
}

// IsOPTIONS 判断是否 OPTIONS 请求（常用于 CORS 预检）。
func (c *Context) IsOPTIONS() bool {
	return c.Request.Method == http.MethodOptions
}

// MethodNotAllowed 返回 405 方法不允许错误。
func (c *Context) MethodNotAllowed(message string) {
	c.JSON(http.StatusMethodNotAllowed, newErrorResponse(http.StatusMethodNotAllowed, message, nil, c.getRequestID()))
}

// TooManyRequests 返回 429 请求过多错误（限流场景）。
func (c *Context) TooManyRequests(message string) {
	c.JSON(http.StatusTooManyRequests, newErrorResponse(http.StatusTooManyRequests, message, nil, c.getRequestID()))
}

// ============================================================
// P1 - 认证与安全方法
// ============================================================

// GetBearerToken 从 Authorization 头获取 Bearer Token（JWT 认证常用）。
func (c *Context) GetBearerToken() string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// GetBasicAuth 从 Authorization 头获取 Basic 认证的用户名和密码。
func (c *Context) GetBasicAuth() (username, password string, ok bool) {
	return c.Request.BasicAuth()
}

// IsSecure 判断是否 HTTPS 请求（检查 TLS 或 X-Forwarded-Proto 头）。
func (c *Context) IsSecure() bool {
	return c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
}

// GetReferer 获取 Referer 请求头（来源追踪/防盗链）。
func (c *Context) GetReferer() string {
	return c.GetHeader("Referer")
}

// GetOrigin 获取 Origin 请求头（用于 CORS 来源验证）。
func (c *Context) GetOrigin() string {
	return c.GetHeader("Origin")
}

// ============================================================
// P2 - 参数处理增强方法
// ============================================================

// ParamSlice 获取切片参数（支持逗号分隔，如 ?ids=1,2,3）。
func (c *Context) ParamSlice(key string, sep ...string) []string {
	separator := ","
	if len(sep) > 0 {
		separator = sep[0]
	}

	value := c.Input(key)
	if value == "" {
		return []string{}
	}

	parts := strings.Split(value, separator)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// ParamIntSlice 获取整型切片参数（支持逗号分隔）。
func (c *Context) ParamIntSlice(key string, sep ...string) []int {
	strs := c.ParamSlice(key, sep...)
	result := make([]int, 0, len(strs))
	for _, s := range strs {
		if n, err := strconv.Atoi(s); err == nil {
			result = append(result, n)
		}
	}
	return result
}

// ParamTime 获取时间参数（layout 参考 time.RFC3339）。
func (c *Context) ParamTime(key, layout string, def ...time.Time) time.Time {
	value := c.Input(key)
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return time.Time{}
	}

	t, err := time.Parse(layout, value)
	if err != nil {
		if len(def) > 0 {
			return def[0]
		}
		return time.Time{}
	}
	return t
}

// ParamDuration 获取时长参数（如 "5s", "10m", "1h"）。
func (c *Context) ParamDuration(key string, def ...time.Duration) time.Duration {
	value := c.Input(key)
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}

	d, err := time.ParseDuration(value)
	if err != nil {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	return d
}

// GetQueryFloat 获取 Query 浮点型参数，不存在则返回默认值。
func (c *Context) GetQueryFloat(key string, def ...float64) float64 {
	value := c.Query(key)
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}

	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	return f
}

// GetQueryStringSlice 获取 Query 中的字符串切片（支持重复参数）。
func (c *Context) GetQueryStringSlice(key string) []string {
	values, ok := c.GetQueryArray(key)
	if !ok {
		return []string{}
	}
	return values
}

// GetHeaderInt 获取 Header 参数（整型）。
func (c *Context) GetHeaderInt(key string, def ...int) int {
	value := c.GetHeader(key)
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	intVal, _ := strconv.Atoi(value)
	return intVal
}

// GetHeaderBool 获取 Header 参数（布尔型）。
func (c *Context) GetHeaderBool(key string, def ...bool) bool {
	value := c.GetHeader(key)
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return false
	}
	return value == "true" || value == "1" || value == "yes"
}

// GetHeaderFloat 获取 Header 浮点型参数。
func (c *Context) GetHeaderFloat(key string, def ...float64) float64 {
	value := c.GetHeader(key)
	if value == "" {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	f, _ := strconv.ParseFloat(value, 64)
	return f
}

// GetHeaderOr 获取 Header，不存在则返回默认值。
func (c *Context) GetHeaderOr(key, def string) string {
	value := c.GetHeader(key)
	if value == "" {
		return def
	}
	return value
}

// ============================================================
// P3 - 响应增强方法
// ============================================================

// ServiceUnavailable 返回 503 服务不可用错误（熔断/维护场景）。
func (c *Context) ServiceUnavailable(message string) {
	c.JSON(http.StatusServiceUnavailable, newErrorResponse(http.StatusServiceUnavailable, message, nil, c.getRequestID()))
}

// GatewayTimeout 返回 504 网关超时错误（上游服务超时）。
func (c *Context) GatewayTimeout(message string) {
	c.JSON(http.StatusGatewayTimeout, newErrorResponse(http.StatusGatewayTimeout, message, nil, c.getRequestID()))
}

// Gone 返回 410 资源已删除错误（资源永久下线）。
func (c *Context) Gone(message string) {
	c.JSON(http.StatusGone, newErrorResponse(http.StatusGone, message, nil, c.getRequestID()))
}

// CreatedWithLocation 返回 201 创建成功响应，并设置 Location 头（REST 规范）。
func (c *Context) CreatedWithLocation(data interface{}, location string) {
	c.Header("Location", location)
	c.JSON(http.StatusCreated, newResponse(http.StatusCreated, "created", data, c.getRequestID()))
}

// ============================================================
// P4 - 请求检测增强方法
// ============================================================

// IsForm 判断是否 Form 表单请求（application/x-www-form-urlencoded）。
func (c *Context) IsForm() bool {
	ct := c.GetHeader("Content-Type")
	return strings.Contains(ct, "application/x-www-form-urlencoded")
}

// IsMultipart 判断是否 Multipart 请求（multipart/form-data，文件上传）。
func (c *Context) IsMultipart() bool {
	ct := c.GetHeader("Content-Type")
	return strings.Contains(ct, "multipart/form-data")
}

// IsWebSocket 判断是否 WebSocket 升级请求。
func (c *Context) IsWebSocket() bool {
	return strings.ToLower(c.GetHeader("Connection")) == "upgrade" &&
		strings.ToLower(c.GetHeader("Upgrade")) == "websocket"
}

// GetContentLength 获取请求体大小（Content-Length 头）。
func (c *Context) GetContentLength() int64 {
	return c.Request.ContentLength
}

// ============================================================
// P5 - 上下文操作增强方法
// ============================================================

// MustGet 获取上下文存储值，不存在则 panic（断言式获取）。
func (c *Context) MustGet(key any) any {
	value, exists := c.Get(key)
	if !exists {
		panic("context: key does not exist")
	}
	return value
}

// GetStringOr 获取上下文字符串值，不存在则返回默认值。
func (c *Context) GetStringOr(key, def string) string {
	if value, exists := c.Get(key); exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return def
}

// GetIntOr 获取上下文整型值，不存在则返回默认值。
func (c *Context) GetIntOr(key string, def int) int {
	if value, exists := c.Get(key); exists {
		if num, ok := value.(int); ok {
			return num
		}
	}
	return def
}

// HasKey 检查上下文中是否存在指定 key。
func (c *Context) HasKey(key string) bool {
	_, exists := c.Get(key)
	return exists
}
