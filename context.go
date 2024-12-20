package gin

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
	if url != nil && len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusOK, response{
		Code: SuccessCode,
		Msg:  "success",
		Data: data,
		Url:  respUrl,
	})
}

// Fail 失败响应
func (c *Context) Fail(msg string, url ...string) {
	var respUrl string
	if url != nil && len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusBadRequest, response{
		Code: FailCode,
		Msg:  msg,
		Data: nil,
		Url:  respUrl,
	})
}

// Error 错误响应
func (c *Context) Error(msg string, url ...string) {
	var respUrl string
	if url != nil && len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusInternalServerError, response{
		Code: ErrorCode,
		Msg:  msg,
		Data: nil,
		Url:  respUrl,
	})
}

// Forbidden 禁止访问响应
func (c *Context) Forbidden(msg string, url ...string) {
	var respUrl string
	if url != nil && len(url) > 0 {
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
}

// NotFound 资源不存在响应
func (c *Context) NotFound(msg string, url ...string) {
	var respUrl string
	if url != nil && len(url) > 0 {
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
}

// Response 自定义响应
func (c *Context) Response(httpStatus, code int, msg string, data interface{}, url ...string) {
	var respUrl string
	if url != nil && len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(httpStatus, response{
		Code: code,
		Msg:  msg,
		Data: data,
		Url:  respUrl,
	})
}

// SuccessWithMsg 成功响应（自定义消息）
func (c *Context) SuccessWithMsg(msg string, data interface{}, url ...string) {
	var respUrl string
	if url != nil && len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusOK, response{
		Code: SuccessCode,
		Msg:  msg,
		Data: data,
		Url:  respUrl,
	})
}

// FailWithData 失败响应（带数据）
func (c *Context) FailWithData(msg string, data interface{}, url ...string) {
	var respUrl string
	if url != nil && len(url) > 0 {
		respUrl = url[0]
	}
	c.JSON(http.StatusBadRequest, response{
		Code: FailCode,
		Msg:  msg,
		Data: data,
		Url:  respUrl,
	})
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
	if strings.HasPrefix(token, "Bearer ") {
		token = token[7:]
	}
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
	items := strings.Split(c.Host(), ".") // 将主机名按点分割
	if len(items) < 2 {
		return c.Host() // 如果没有点，返回主机名
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

// 检查是否包含特殊后缀
func (d *Context) containsSpecialSuffix(suffix string) bool {
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

// BaseFile 获取当前执行的文件
func (c *Context) BaseFile() string {
	return c.Request.URL.Path
}

// Root 获取URL访问根地址
func (c *Context) Root() string {
	// 这里可以根据具体的逻辑来实现
	return "" // 需要实现具体逻辑
}

// RootUrl 获取URL访问根目录
func (c *Context) RootUrl() string {
	// 这里可以根据具体的逻辑来实现
	return "" // 需要实现具体逻辑
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
	if c.Request.TLS != nil {
		return true
	}
	return false
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

	if err := os.MkdirAll(config.SavePath, 0755); err != nil {
		return "", err
	}

	if err := c.Context.SaveUploadedFile(file, savePath); err != nil {
		return "", err
	}

	return newFileName, nil
}

// pageInfo 新增分页相关结构体
type pageInfo struct {
	Page     int   `json:"page"`     // 当前页码
	PageSize int   `json:"pageSize"` // 每页数量
	Total    int64 `json:"total"`    // 总数据量
}

type rageResponse struct {
	List     interface{} `json:"list"`     // 数据列表
	PageInfo pageInfo    `json:"pageInfo"` // 分页信息
}

// PageResponse 分页响应
func (c *Context) PageResponse(list interface{}, total int64, page, pageSize int) {
	c.JSON(http.StatusOK, response{
		Code: SuccessCode,
		Msg:  "success",
		Data: rageResponse{
			List: list,
			PageInfo: pageInfo{
				Page:     page,
				PageSize: pageSize,
				Total:    total,
			},
		},
	})
}

// BuildUrl 创建一个 UrlBuilder 实例
func (c *Context) BuildUrl(path string, params H) *urlBuilder {
	return &urlBuilder{
		scheme: c.Scheme(),
		domain: "",
		path:   path,
		ext:    "",
		params: params,
	}
}

// urlBuilder 结构体用于构建 URL
type urlBuilder struct {
	domain, path, ext, scheme string
	params                    H
}

// Scheme 设置 URL 的访问协议
func (ub *urlBuilder) Scheme(scheme string) *urlBuilder {
	ub.scheme = scheme
	return ub
}

// Domain 设置是否使用域名
func (ub *urlBuilder) Domain(domain string) *urlBuilder {
	ub.domain = domain
	return ub
}

// Suffix 设置 URL 的后缀
func (ub *urlBuilder) Suffix(suffix string) *urlBuilder {
	ub.ext = suffix
	return ub
}

// Builder 生成最终的 URL
func (ub *urlBuilder) Builder() string {
	u := &url.URL{}

	if ub.domain != "" {
		if ub.scheme == "" {
			u.Scheme = "http"
		} else {
			u.Scheme = ub.scheme
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
