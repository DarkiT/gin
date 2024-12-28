package gin

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

const (
	SuccessCode   = 200 // 成功状态码
	FailCode      = 400 // 失败状态码
	ErrorCode     = 500 // 错误状态码
	ForbiddenCode = 403 // 禁止访问状态码
	NotFound      = 404 // 资源不存在状态码
)

var (
	domainSpecialSuffix = []string{
		// 通用顶级域名 (gTLD)
		"app", "art", "bid", "bio", "biz", "cab", "cam", "cfd", "com", "dev", "dog", "llc",
		"lol", "mba", "moe", "mom", "net", "one", "org", "pro", "red", "rip", "sbs", "tel",
		"top", "vin", "vip", "win", "xxx", "xyz",

		// 国家代码顶级域名 (ccTLD)
		"ac", "ae", "af", "ai", "am", "at", "be", "bz", "ca", "cc", "ch", "cl", "cm", "cn", "co", "cx", "cz", "de",
		"dk", "ec", "es", "eu", "fm", "fr", "gd", "gg", "gl", "gr", "gs", "gy", "hk", "hn", "ht", "hu", "im", "in",
		"io", "it", "je", "jp", "kr", "la", "lc", "li", "lt", "lu", "lv", "me", "mn", "ms", "mu", "mx", "nl", "nu",
		"nz", "pe", "ph", "pl", "pm", "pt", "pw", "qa", "re", "ro", "ru", "sb", "sc", "se", "sg", "sh", "si", "so",
		"sx", "tc", "tf", "tk", "tm", "to", "tv", "tw", "uk", "us", "vc", "vg", "wf", "ws", "yt",

		// 新通用顶级域名 (New gTLDs)
		"asia", "best", "blue", "cash", "club", "cool", "cyou", "express", "futbol", "game", "global", "group",
		"immo", "info", "kiwi", "link", "live", "media", "mobi", "name", "network", "online", "pink", "plus",
		"shop", "site", "space", "studio", "team", "tools", "wang", "wiki", "works",
	}

	mimeType = map[string]string{
		"xml":   "application/xml,text/xml,application/x-xml",
		"json":  "application/json,text/x-json,application/jsonrequest,text/json",
		"js":    "text/javascript,application/javascript,application/x-javascript",
		"css":   "text/css",
		"rss":   "application/rss+xml",
		"yaml":  "application/x-yaml,text/yaml",
		"atom":  "application/atom+xml",
		"pdf":   "application/pdf",
		"text":  "text/plain",
		"image": "image/png,image/jpg,image/jpeg,image/pjpeg,image/gif,image/webp,image/*",
		"csv":   "text/csv",
		"html":  "text/html,application/xhtml+xml,*/*",
	}
)

type Context struct {
	*gin.Context
	hub *SSEHub
}

// 定义统一的响应结构
type response struct {
	Code int         `json:"code"`           // 状态码
	Msg  string      `json:"msg"`            // 提示信息
	Data interface{} `json:"data,omitempty"` // 数据
	Url  string      `json:"url,omitempty"`  // 重定向URL地址
}

// Success 成功响应
func (c *Context) Success(data interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusOK, response{
		Code: SuccessCode,
		Msg:  "success",
		Data: data,
		Url:  respUrl,
	})
	c.Abort()
}

// Fail 失败响应
func (c *Context) Fail(msg string, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusBadRequest, response{
		Code: FailCode,
		Msg:  msg,
		Data: nil,
		Url:  respUrl,
	})
	c.Abort()
}

// Error 错误响应
func (c *Context) Error(msg string, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusInternalServerError, response{
		Code: ErrorCode,
		Msg:  msg,
		Data: nil,
		Url:  respUrl,
	})
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
	c.JSON(http.StatusForbidden, response{
		Code: ForbiddenCode,
		Msg:  msg,
		Data: nil,
		Url:  respUrl,
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
	c.JSON(http.StatusNotFound, response{
		Code: NotFound,
		Msg:  msg,
		Data: nil,
		Url:  respUrl,
	})
	c.Abort()
}

// Response 自定义响应
func (c *Context) Response(httpStatus, code int, msg string, data interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(httpStatus, response{
		Code: code,
		Msg:  msg,
		Data: data,
		Url:  respUrl,
	})
	c.Abort()
}

// SuccessWithMsg 成功响应（自定义消息）
func (c *Context) SuccessWithMsg(msg string, data interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusOK, response{
		Code: SuccessCode,
		Msg:  msg,
		Data: data,
		Url:  respUrl,
	})
	c.Abort()
}

// FailWithData 失败响应（带数据）
func (c *Context) FailWithData(msg string, data interface{}, url ...string) {
	var respUrl string
	if len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusBadRequest, response{
		Code: FailCode,
		Msg:  msg,
		Data: data,
		Url:  respUrl,
	})
	c.Abort()
}

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

// GetToken 从请求头获取Token
func (c *Context) GetToken(name ...string) string {
	key := "Authorization"
	if len(name) > 0 {
		key = name[0]
	}
	token := c.GetHeader(key)
	if token == "" {
		token = c.Param(key)
	}
	if token == "" {
		return ""
	}
	token = strings.TrimPrefix(token, "Bearer ")
	return token
}

// Param 获取当前请求的变量
func (c *Context) Param(param string, defaultValue ...string) string {
	sources := []func(string) string{
		c.Context.Param,
		c.Context.Query,
		c.Context.PostForm,
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

// ParamInt 获取当前请求的变量
func (c *Context) ParamInt(param string, defaultValue ...int) int {
	sources := []func(string) string{
		c.Context.Param,
		c.Context.Query,
		c.Context.PostForm,
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

// Redirect 临时重定向
func (c *Context) Redirect(location string) {
	c.Context.Redirect(http.StatusTemporaryRedirect, location)
}

// RedirectPermanent 永久重定向
func (c *Context) RedirectPermanent(location string) {
	c.Context.Redirect(http.StatusMovedPermanently, location)
}

// AllowCORS 允许跨域请求
func (c *Context) AllowCORS() {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Origin,Content-Type,Accept,Authorization")
}

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
	if c.IsSsl() {
		return "https"
	}
	return "http"
}

// Port 获取当前请求的端口
func (c *Context) Port() string {
	return c.Request.URL.Port()
}

// RemotePort 获取当前请求的REMOTE_PORT
func (c *Context) RemotePort() string {
	return c.Request.RemoteAddr
}

// Protocol 获取当前请求的协议
func (c *Context) Protocol() string {
	return c.Request.Proto
}

// ContentType 获取当前请求的CONTENT_TYPE
func (c *Context) ContentType() string {
	return c.Request.Header.Get("Content-Type")
}

// URL 获取当前请求的完整URL
func (c *Context) URL() string {
	return c.Request.URL.String()
}

// BaseURL 获取当前请求的基本URL（不含QUERY_STRING）
func (c *Context) BaseURL() string {
	return c.Request.URL.Path
}

// Time 获取当前请求的时间
func (c *Context) Time() time.Time {
	return time.Now() // 返回当前时间
}

// Type 获取当前请求的资源类型
func (c *Context) Type() string {
	accept := c.GetHeader("Accept")
	array := strings.Split(accept, ",")
	for k, val := range mimeType {
		if strings.Contains(val, array[0]) {
			return k
		}
	}
	return ""
}

// Domain 获取当前包含协议的域名
func (c *Context) Domain() string {
	return c.Scheme() + "://" + c.Host()
}

// SubDomain 获取当前访问的子域名
func (c *Context) SubDomain() string {
	rootDomain := c.RootDomain()
	if rootDomain == "" {
		return ""
	}
	sub := strings.TrimSuffix(c.Host(), rootDomain)
	return strings.Trim(sub, ".")
}

// PanDomain 获取当前访问的泛域名
func (c *Context) PanDomain() string {
	subDomain := c.SubDomain()
	if subDomain == "" {
		return ""
	}
	return subDomain + "." + c.RootDomain()
}

// RootDomain 获取当前访问的根域名
func (c *Context) RootDomain() string {
	host := c.Host()
	if host == "" {
		return ""
	}

	// 尝试分离主机名和端口号
	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		// 如果没有端口号，直接使用整个主机名
		hostOnly = host
	}

	// 检查是否是IP地址
	parsedIP := net.ParseIP(hostOnly)
	if parsedIP != nil {
		return "" // 如果是IP地址，直接返回空字符串
	}

	items := strings.Split(hostOnly, ".") // 将主机名按点分割
	if len(items) < 2 {
		return hostOnly // 如果没有点，返回主机名
	}

	count := len(items)
	var root string
	if count > 1 {
		// 默认取最后两个部分作为根域名
		root = items[count-2] + "." + items[count-1]
		// 处理特殊后缀情况
		if count > 2 && c.containsSpecialSuffix(items[count-2]) {
			root = items[count-3] + "." + root
		}
	} else {
		// 如果只有一个部分，直接使用该部分
		root = items[0]
	}
	return root
}

// 检查是否包含特殊后缀（改为私有方法）
func (c *Context) containsSpecialSuffix(suffix string) bool {
	for _, specialSuffix := range domainSpecialSuffix {
		if suffix == specialSuffix {
			return true
		}
	}
	return false
}

// Ext 获取当前URL的访问后缀
func (c *Context) Ext() string {
	return filepath.Ext(c.BaseURL())
}

// IsGet 判断是否GET请求
func (c *Context) IsGet() bool {
	return c.Request.Method == MethodGet
}

// IsHead 判断是否Head请求
func (c *Context) IsHead() bool {
	return c.Request.Method == MethodHead
}

// IsPut 判断是否Put请求
func (c *Context) IsPut() bool {
	return c.Request.Method == MethodPut
}

// IsPost 判断是否Post请求
func (c *Context) IsPost() bool {
	return c.Request.Method == MethodPost
}

// IsPatch 判断是否Patch请求
func (c *Context) IsPatch() bool {
	return c.Request.Method == MethodPatch
}

// IsDelete 判断是否Delete请求
func (c *Context) IsDelete() bool {
	return c.Request.Method == MethodDelete
}

// IsConnect 判断是否Connect请求
func (c *Context) IsConnect() bool {
	return c.Request.Method == MethodConnect
}

// IsOptions 判断是否Options请求
func (c *Context) IsOptions() bool {
	return c.Request.Method == MethodOptions
}

// IsTrace 判断是否Trace请求
func (c *Context) IsTrace() bool {
	return c.Request.Method == MethodTrace
}

// IsAjax 判断是否是Ajax请求
func (c *Context) IsAjax() bool {
	return c.GetHeader("X-Requested-With") == "XMLHttpRequest"
}

// IsJson 判断是否是Json请求
func (c *Context) IsJson() bool {
	return c.Type() == "json"
}

// IsPjax 判断是否是Pjax请求
func (c *Context) IsPjax() bool {
	return c.GetHeader("HTTP_X_PJAX") != ""
}

// IsSsl 判断是否是SSL
func (c *Context) IsSsl() bool {
	return c.Request.TLS != nil
}

// UploadConfig 文件上传相关方法
type UploadConfig struct {
	AllowedExts []string // 允许的文件扩展名
	MaxSize     int64    // 最大文件大小（字节）
	SavePath    string   // 保存路径
}

// ValidateFile 验证上传文件
func (c *Context) ValidateFile(file *multipart.FileHeader, config UploadConfig) error {
	if config.MaxSize > 0 && file.Size > config.MaxSize {
		return fmt.Errorf("文件大小超过限制")
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
			return fmt.Errorf("不支持的文件类型")
		}
	}
	return nil
}

// SaveUploadedFile 保存上传文件
func (c *Context) SaveUploadedFile(file *multipart.FileHeader, config UploadConfig) (string, error) {
	if err := c.ValidateFile(file, config); err != nil {
		return "", err
	}

	ext := filepath.Ext(file.Filename)

	hash := md5.Sum([]byte(file.Filename))
	newFileName := fmt.Sprintf("%s%s", hex.EncodeToString(hash[:]), ext)
	savePath := filepath.Join(config.SavePath, newFileName)

	if err := os.MkdirAll(config.SavePath, 0o755); err != nil {
		return "", err
	}

	if err := c.Context.SaveUploadedFile(file, savePath); err != nil {
		return "", err
	}

	return newFileName, nil
}

// Pagination 分页信息结构体
type Pagination struct {
	CurrentPage int   `json:"current_page"`          // 当前页码，使用下划线风格的JSON标签
	PageSize    int   `json:"page_size"`             // 每页数量
	TotalCount  int64 `json:"total_count"`           // 总数据量，使用更准确的命名
	TotalPages  int   `json:"total_pages,omitempty"` // 总页数（可选）
}

// ListResponse 通用列表响应结构体
type ListResponse struct {
	Data       any        `json:"data"`       // 数据列表，使用更通用的名称
	Pagination Pagination `json:"pagination"` // 分页信息，使用更专业的命名
}

// PageResponse 分页响应方法，适配新的结构体
func (c *Context) PageResponse(list any, totalCount int64, currentPage, pageSize int) {
	// 处理pageSize为0的情况
	if pageSize <= 0 {
		pageSize = 10 // 设置一个默认值
	}

	// 计算总页数
	totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))

	// 确保当前页有效
	if currentPage <= 0 {
		currentPage = 1
	}

	c.JSON(http.StatusOK, response{
		Code: SuccessCode,
		Msg:  "success",
		Data: ListResponse{
			Data: list,
			Pagination: Pagination{
				CurrentPage: currentPage,
				PageSize:    pageSize,
				TotalCount:  totalCount,
				TotalPages:  totalPages,
			},
		},
	})
	c.Abort()
}

// BuildUrl 创建一个 urlBuilder 实例
func (c *Context) BuildUrl(path string, params H) *urlBuilder {
	return &urlBuilder{
		scheme: c.Scheme(),
		domain: "",
		path:   path,
		ext:    "",
		params: params,
	}
}

// urlBuilder 结构体用于构建 URL（改为私有）
type urlBuilder struct {
	domain, path, ext, scheme string
	params                    H
}

// Scheme 设置 URL 的访问协议（改为私有方法）
func (ub *urlBuilder) Scheme(scheme string) *urlBuilder {
	ub.scheme = scheme
	return ub
}

// Domain 设置是否使用域名（改为私有方法）
func (ub *urlBuilder) Domain(domain string) *urlBuilder {
	ub.domain = domain
	return ub
}

// Suffix 设置 URL 的后缀（改为私有方法）
func (ub *urlBuilder) Suffix(suffix string) *urlBuilder {
	ub.ext = suffix
	return ub
}

// Builder 生成最终的 URL（改为私有方法）
func (ub *urlBuilder) Builder() string {
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

	query := u.Query()
	for key, value := range ub.params {
		query.Set(key, fmt.Sprintf("%v", value))
	}
	u.RawQuery = query.Encode()

	return u.String()
}

// 增加常用的参数绑定和验证方法

// BindAndValidate 绑定并验证请求数据
func (c *Context) BindAndValidate(obj interface{}) bool {
	if err := c.ShouldBind(obj); err != nil {
		c.Fail(fmt.Sprintf("参数绑定失败: %v", err))
		return false
	}
	return true
}

// BindJSON 绑定JSON请求数据并处理错误
func (c *Context) BindJSON(obj interface{}) bool {
	if err := c.ShouldBindJSON(obj); err != nil {
		c.Fail(fmt.Sprintf("JSON参数绑定失败: %v", err))
		return false
	}
	return true
}

// BindQuery 绑定查询参数并处理错误
func (c *Context) BindQuery(obj interface{}) bool {
	if err := c.ShouldBindQuery(obj); err != nil {
		c.Fail(fmt.Sprintf("查询参数绑定失败: %v", err))
		return false
	}
	return true
}

// BindForm 绑定表单参数并处理错误
func (c *Context) BindForm(obj interface{}) bool {
	if err := c.ShouldBindWith(obj, binding.Form); err != nil {
		c.Fail(fmt.Sprintf("表单参数绑定失败: %v", err))
		return false
	}
	return true
}

// BindHeader 绑定Header参数并处理错误
func (c *Context) BindHeader(obj interface{}) bool {
	if err := c.ShouldBindHeader(obj); err != nil {
		c.Fail(fmt.Sprintf("Header参数绑定失败: %v", err))
		return false
	}
	return true
}

// BindUri 绑定URI参数并处理错误
func (c *Context) BindUri(obj interface{}) bool {
	if err := c.ShouldBindUri(obj); err != nil {
		c.Fail(fmt.Sprintf("URI参数绑定失败: %v", err))
		return false
	}
	return true
}

// 增加JWT相关方法

// JWT常量，保留公开因为它们是API契约的一部分
const (
	JWTHeaderKey = "Authorization"
	JWTQueryKey  = "token"
	JWTCookieKey = "jwt"
	JWTPrefix    = "Bearer "

	// JWT算法
	JWTAlgHS256 = "HS256" // HMAC-SHA256
	JWTAlgHS384 = "HS384" // HMAC-SHA384
	JWTAlgHS512 = "HS512" // HMAC-SHA512

	// JWT标准声明
	JWTClaimIss = "iss" // 签发者
	JWTClaimSub = "sub" // 主题
	JWTClaimAud = "aud" // 受众
	JWTClaimExp = "exp" // 过期时间
	JWTClaimNbf = "nbf" // 生效时间
	JWTClaimIat = "iat" // 签发时间
	JWTClaimJti = "jti" // JWT ID
)

// jwtUtil JWT工具类（改为私有）
type jwtUtil struct {
	SecretKey []byte // 密钥
	Alg       string // 算法
}

// 创建默认的JWT工具（改为私有）
func newJWTUtil(secretKey string) *jwtUtil {
	return &jwtUtil{
		SecretKey: []byte(secretKey),
		Alg:       JWTAlgHS256,
	}
}

// 创建JWT工具并指定算法（改为私有）
func newJWTUtilWithAlg(secretKey string, alg string) *jwtUtil {
	return &jwtUtil{
		SecretKey: []byte(secretKey),
		Alg:       alg,
	}
}

// jwtHeader JWT头部（改为私有）
type jwtHeader struct {
	Alg string `json:"alg"` // 算法
	Typ string `json:"typ"` // 类型
}

// JWTPayload JWT载荷（保留公开因为它是API的一部分）
type JWTPayload map[string]interface{}

// SetIssuer 设置JWT标准声明
func (p JWTPayload) SetIssuer(issuer string) JWTPayload {
	p[JWTClaimIss] = issuer
	return p
}

func (p JWTPayload) SetSubject(subject string) JWTPayload {
	p[JWTClaimSub] = subject
	return p
}

func (p JWTPayload) SetAudience(audience string) JWTPayload {
	p[JWTClaimAud] = audience
	return p
}

func (p JWTPayload) SetExpiresAt(expiresAt time.Time) JWTPayload {
	p[JWTClaimExp] = expiresAt.Unix()
	return p
}

func (p JWTPayload) SetNotBefore(notBefore time.Time) JWTPayload {
	p[JWTClaimNbf] = notBefore.Unix()
	return p
}

func (p JWTPayload) SetIssuedAt(issuedAt time.Time) JWTPayload {
	p[JWTClaimIat] = issuedAt.Unix()
	return p
}

func (p JWTPayload) SetJWTID(jwtID string) JWTPayload {
	p[JWTClaimJti] = jwtID
	return p
}

// 生成随机JWT ID（改为私有）
func generateJWTID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// 如果生成随机数失败，使用时间戳
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// 生成JWT令牌（改为私有方法）
func (j *jwtUtil) generateToken(payload JWTPayload) (string, error) {
	// 创建头部
	header := jwtHeader{
		Alg: j.Alg,
		Typ: "JWT",
	}

	// 设置默认的签发时间和JWT ID (如果未设置)
	if _, ok := payload[JWTClaimIat]; !ok {
		payload.SetIssuedAt(time.Now())
	}

	if _, ok := payload[JWTClaimJti]; !ok {
		payload.SetJWTID(generateJWTID())
	}

	// 序列化头部和载荷
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("序列化JWT头部失败: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化JWT载荷失败: %w", err)
	}

	// Base64URL编码
	headerBase64 := base64URLEncode(headerJSON)
	payloadBase64 := base64URLEncode(payloadJSON)

	// 计算签名
	signatureBase := headerBase64 + "." + payloadBase64
	signature := j.sign(signatureBase)

	// 拼接JWT令牌
	token := signatureBase + "." + base64URLEncode(signature)

	return token, nil
}

// 验证JWT令牌并返回载荷（改为私有方法）
func (j *jwtUtil) validateToken(token string) (JWTPayload, error) {
	// 解析令牌
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("无效的JWT格式")
	}

	headerBase64, payloadBase64, signatureBase64 := parts[0], parts[1], parts[2]

	// 验证签名
	signatureBase := headerBase64 + "." + payloadBase64
	expectedSignature := j.sign(signatureBase)

	signature, err := base64URLDecode(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("无效的签名编码: %w", err)
	}

	if !hmac.Equal(signature, expectedSignature) {
		return nil, fmt.Errorf("签名验证失败")
	}

	// 解析载荷
	payloadJSON, err := base64URLDecode(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("无效的载荷编码: %w", err)
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("解析载荷失败: %w", err)
	}

	// 验证过期时间
	if exp, ok := payload[JWTClaimExp].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("令牌已过期")
		}
	}

	// 验证生效时间
	if nbf, ok := payload[JWTClaimNbf].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return nil, fmt.Errorf("令牌尚未生效")
		}
	}

	return payload, nil
}

// 签名（改为私有方法）
func (j *jwtUtil) sign(data string) []byte {
	var h hash.Hash

	switch j.Alg {
	case JWTAlgHS384:
		h = hmac.New(sha512.New384, j.SecretKey)
	case JWTAlgHS512:
		h = hmac.New(sha512.New, j.SecretKey)
	default: // JWTAlgHS256
		h = hmac.New(sha256.New, j.SecretKey)
	}

	h.Write([]byte(data))
	return h.Sum(nil)
}

// Base64URL编码（改为私有函数）
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// Base64URL解码（改为私有函数）
func base64URLDecode(s string) ([]byte, error) {
	// 添加填充
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}

	return base64.URLEncoding.DecodeString(s)
}

// 添加到Context的JWT方法

// GenerateJWT 生成JWT令牌
func (c *Context) GenerateJWT(secretKey string, payload JWTPayload) (string, error) {
	jwt := newJWTUtil(secretKey)
	return jwt.generateToken(payload)
}

// ValidateJWT 验证JWT令牌
func (c *Context) ValidateJWT(secretKey string, token string) (JWTPayload, error) {
	jwt := newJWTUtil(secretKey)
	return jwt.validateToken(token)
}

// ParseJWTPayload 解析JWT载荷（不验证签名）
func (c *Context) ParseJWTPayload(token string) (JWTPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("无效的JWT格式")
	}

	payloadBase64 := parts[1]

	// 解析载荷
	payloadJSON, err := base64URLDecode(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("无效的载荷编码: %w", err)
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("解析载荷失败: %w", err)
	}

	return payload, nil
}

// RequireJWT 要求JWT令牌有效并返回载荷
func (c *Context) RequireJWT(secretKey string) (JWTPayload, bool) {
	token := c.GetJWT()
	if token == "" {
		c.Unauthorized("缺少认证令牌")
		return nil, false
	}

	payload, err := c.ValidateJWT(secretKey, token)
	if err != nil {
		c.Unauthorized(fmt.Sprintf("无效的认证令牌: %v", err))
		return nil, false
	}

	return payload, true
}

// CreateJWTSession 使用JWT创建用户会话
func (c *Context) CreateJWTSession(secretKey string, userID string, expiration time.Duration, extraClaims ...map[string]interface{}) (string, error) {
	// 创建标准载荷
	now := time.Now()
	payload := JWTPayload{
		JWTClaimSub: userID,
		JWTClaimIat: now.Unix(),
		JWTClaimNbf: now.Unix(),
		JWTClaimExp: now.Add(expiration).Unix(),
		JWTClaimJti: generateJWTID(),
	}

	// 添加额外的声明
	if len(extraClaims) > 0 {
		for k, v := range extraClaims[0] {
			payload[k] = v
		}
	}

	// 生成令牌
	token, err := c.GenerateJWT(secretKey, payload)
	if err != nil {
		return "", err
	}

	// 设置到Cookie
	maxAge := int(expiration.Seconds())
	c.SetJWT(token, maxAge)

	return token, nil
}

// RefreshJWTSession 刷新JWT会话
func (c *Context) RefreshJWTSession(secretKey string, expiration time.Duration) (string, error) {
	token := c.GetJWT()
	if token == "" {
		return "", fmt.Errorf("没有找到JWT令牌")
	}

	// 解析当前载荷（不验证签名）
	payload, err := c.ParseJWTPayload(token)
	if err != nil {
		return "", err
	}

	// 验证旧令牌
	_, err = c.ValidateJWT(secretKey, token)
	if err != nil {
		return "", err
	}

	// 创建新载荷
	now := time.Now()
	newPayload := JWTPayload{}

	// 复制原始载荷，但更新时间相关的声明
	for k, v := range payload {
		newPayload[k] = v
	}

	newPayload[JWTClaimIat] = now.Unix()
	newPayload[JWTClaimExp] = now.Add(expiration).Unix()
	newPayload[JWTClaimJti] = generateJWTID()

	// 生成新令牌
	newToken, err := c.GenerateJWT(secretKey, newPayload)
	if err != nil {
		return "", err
	}

	// 设置到Cookie
	maxAge := int(expiration.Seconds())
	c.SetJWT(newToken, maxAge)

	return newToken, nil
}

// 增加缓存控制方法

// NoCache 设置禁止缓存的Header
func (c *Context) NoCache() {
	c.Header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
	c.Header("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
	c.Header("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	c.Header("Pragma", "no-cache")
}

// Cache 设置缓存的Header
func (c *Context) Cache(seconds int) {
	c.Header("Cache-Control", fmt.Sprintf("max-age=%d, public", seconds))
	c.Header("Expires", time.Now().Add(time.Duration(seconds)*time.Second).UTC().Format(http.TimeFormat))
}

// 增加国际化支持方法

// Language 获取客户端语言
func (c *Context) Language() string {
	lang := c.GetHeader("Accept-Language")
	if lang == "" {
		return "zh-CN" // 默认中文
	}

	// 解析Accept-Language
	langs := strings.Split(lang, ",")
	if len(langs) > 0 {
		parts := strings.Split(langs[0], ";")
		return parts[0]
	}

	return "zh-CN"
}

// 增加安全相关方法

// SetCSP 设置内容安全策略
func (c *Context) SetCSP(policy string) {
	c.Header("Content-Security-Policy", policy)
}

// SetXFrameOptions 设置X-Frame-Options
func (c *Context) SetXFrameOptions(option string) {
	c.Header("X-Frame-Options", option)
}

// SetXSSProtection 设置XSS保护
func (c *Context) SetXSSProtection() {
	c.Header("X-XSS-Protection", "1; mode=block")
}

// SetSecureHeaders 设置常用安全头
func (c *Context) SetSecureHeaders() {
	c.SetXSSProtection()
	c.SetXFrameOptions("SAMEORIGIN")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
}

// 增加常用响应方法

// HTML 返回HTML响应
func (c *Context) HTML(html string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// XML 返回XML响应
func (c *Context) XML(data interface{}) {
	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.Context.XML(http.StatusOK, data)
}

// YAML 返回YAML响应
func (c *Context) YAML(data interface{}) {
	c.Header("Content-Type", "application/x-yaml; charset=utf-8")
	c.Context.YAML(http.StatusOK, data)
}

// ProtoBuf 返回ProtoBuf响应
func (c *Context) ProtoBuf(data interface{}) {
	c.Header("Content-Type", "application/x-protobuf")
	c.Context.ProtoBuf(http.StatusOK, data)
}

// Download 下载文件
func (c *Context) Download(filepath, filename string) {
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.File(filepath)
}

// StreamFile 流式传输文件
func (c *Context) StreamFile(filepath string) {
	http.ServeFile(c.Writer, c.Request, filepath)
}

// 增加会话相关方法

// SessionGet 获取会话数据
func (c *Context) SessionGet(key string) (interface{}, bool) {
	val, exists := c.Get(key)
	return val, exists
}

// SessionSet 设置会话数据
func (c *Context) SessionSet(key string, value interface{}) {
	c.Set(key, value)
}

// SessionGetString 获取字符串类型的会话数据
func (c *Context) SessionGetString(key string) string {
	if val, exists := c.SessionGet(key); exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// SessionGetInt 获取整数类型的会话数据
func (c *Context) SessionGetInt(key string) int {
	if val, exists := c.SessionGet(key); exists {
		if num, ok := val.(int); ok {
			return num
		}
	}
	return 0
}

// SessionGetBool 获取布尔类型的会话数据
func (c *Context) SessionGetBool(key string) bool {
	if val, exists := c.SessionGet(key); exists {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

// 增加常见的错误和状态码响应方法

// Unauthorized 未授权响应
func (c *Context) Unauthorized(msg string) {
	if msg == "" {
		msg = "未授权访问"
	}
	c.JSON(http.StatusUnauthorized, response{
		Code: http.StatusUnauthorized,
		Msg:  msg,
	})
	c.Abort()
}

// MethodNotAllowed 方法不允许响应
func (c *Context) MethodNotAllowed() {
	c.JSON(http.StatusMethodNotAllowed, response{
		Code: http.StatusMethodNotAllowed,
		Msg:  "请求方法不允许",
	})
	c.Abort()
}

// ServiceUnavailable 服务不可用响应
func (c *Context) ServiceUnavailable(msg string) {
	if msg == "" {
		msg = "服务暂时不可用"
	}
	c.JSON(http.StatusServiceUnavailable, response{
		Code: http.StatusServiceUnavailable,
		Msg:  msg,
	})
	c.Abort()
}

// 增加请求信息辅助方法

// RequestInfo 获取请求信息
func (c *Context) RequestInfo() H {
	return H{
		"method":     c.Method(),
		"path":       c.BaseURL(),
		"query":      c.Request.URL.RawQuery,
		"ip":         c.GetIP(),
		"user_agent": c.GetUserAgent(),
		"referer":    c.GetHeader("Referer"),
		"time":       time.Now().Format(time.RFC3339),
	}
}

// Dump 获取请求详细信息（调试用）
func (c *Context) Dump() H {
	headers := make(map[string]string)
	for k, v := range c.Request.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return H{
		"method":     c.Method(),
		"path":       c.Request.URL.Path,
		"query":      c.Request.URL.RawQuery,
		"protocol":   c.Protocol(),
		"host":       c.Host(),
		"ip":         c.GetIP(),
		"user_agent": c.GetUserAgent(),
		"headers":    headers,
		"time":       time.Now().Format(time.RFC3339),
	}
}

// 增加数据验证辅助方法

// Validator 验证器接口
type Validator interface {
	Validate() (bool, string)
}

// Validate 验证数据
func (c *Context) Validate(v Validator) bool {
	if valid, msg := v.Validate(); !valid {
		c.Fail(msg)
		return false
	}
	return true
}

// ValidateWithCode 带状态码的验证数据
func (c *Context) ValidateWithCode(v Validator, code int) bool {
	if valid, msg := v.Validate(); !valid {
		c.JSON(http.StatusBadRequest, response{
			Code: code,
			Msg:  msg,
		})
		c.Abort()
		return false
	}
	return true
}

// 增加实用的数据转换方法

// GetIntSlice 获取整型切片
func (c *Context) GetIntSlice(key string, sep ...string) []int {
	separator := ","
	if len(sep) > 0 {
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
		if val, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			result = append(result, val)
		}
	}

	return result
}

// GetStringSlice 获取字符串切片
func (c *Context) GetStringSlice(key string, sep ...string) []string {
	separator := ","
	if len(sep) > 0 {
		separator = sep[0]
	}

	str := c.Query(key)
	if str == "" {
		str = c.PostForm(key)
	}

	if str == "" {
		return []string{}
	}

	parts := strings.Split(str, separator)
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// Paginate 分页参数处理
func (c *Context) Paginate(defaultPageSize ...int) (page, pageSize int) {
	// 默认值
	page = 1
	pageSize = 10

	if len(defaultPageSize) > 0 && defaultPageSize[0] > 0 {
		pageSize = defaultPageSize[0]
	}

	// 获取请求中的参数
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

	// 限制最大页面大小
	if pageSize > 100 {
		pageSize = 100
	}

	return page, pageSize
}

// GetJWT 获取JWT令牌
func (c *Context) GetJWT() string {
	// 从Header获取
	token := c.GetHeader(JWTHeaderKey)
	if token != "" {
		return strings.TrimPrefix(token, JWTPrefix)
	}

	// 从Query获取
	token = c.Query(JWTQueryKey)
	if token != "" {
		return token
	}

	// 从Cookie获取
	token, _ = c.Cookie(JWTCookieKey)
	return token
}

// SetJWT 设置JWT令牌到Cookie
func (c *Context) SetJWT(token string, maxAge int) {
	c.SetCookie(JWTCookieKey, token, maxAge, "/", c.RootDomain(), c.IsSsl(), true)
}

// ClearJWT 清除JWT令牌
func (c *Context) ClearJWT() {
	c.SetCookie(JWTCookieKey, "", -1, "/", c.RootDomain(), c.IsSsl(), true)
}
