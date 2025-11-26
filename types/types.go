// Package types 定义框架中通用的类型和接口，解决循环导入问题
package types

import (
	"context"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// H 是map[string]interface{}的简化版本，用于快速构建响应数据
type H map[string]interface{}

// HandlerFunc 定义处理函数类型（前向声明，实际类型在主包中定义）
// 这里只是为了避免循环导入，实际使用时会被主包的类型覆盖
type HandlerFunc interface{}

// ContextKey 用于上下文键的类型
type ContextKey string

// ResponseWriter 定义响应写入器接口
type ResponseWriter interface {
	http.ResponseWriter
	JSON(code int, obj interface{})
	Abort()
}

// RequestContext 定义请求上下文接口
type RequestContext interface {
	context.Context

	// 基础方法
	Method() string
	Host() string
	URL() string
	GetHeader(key string) string
	GetIP() string

	// 参数获取
	Param(key string, defaultValue ...string) string
	ParamInt(key string, defaultValue ...int) int
	Query(key string) string
	PostForm(key string) string

	// 响应方法
	Success(data interface{}, url ...string)
	Fail(msg string, url ...string)
	Error(msg string, url ...string)
	JSON(code int, obj interface{})

	// 缓存方法
	CacheSet(key string, value interface{}, duration ...time.Duration)
	CacheGet(key string) (interface{}, bool)
	CacheDelete(key string)

	// JWT方法
	SetJWT(token string, maxAge int)
	GetJWT() string

	// 文件上传
	FormFile(name string) (*multipart.FileHeader, error)
}

// ErrorHandler 错误处理器接口
type ErrorHandler interface {
	HandleError(ctx RequestContext, err error)
}

// CacheStorage 缓存存储接口
type CacheStorage interface {
	Set(key string, value interface{}, duration ...time.Duration)
	Get(key string) (interface{}, bool)
	Delete(key string)
	Has(key string) bool
	Keys() []string
	Clear()
}

// JWTManager JWT管理器接口
type JWTManager interface {
	GenerateToken(payload map[string]interface{}) (string, error)
	ValidateToken(token string) (map[string]interface{}, error)
	ParsePayload(token string) (map[string]interface{}, error)
	RevokeToken(jti string, expirationTime time.Time) error
	IsTokenRevoked(jti string) bool
}

// ResourcePool 资源池接口
type ResourcePool[T any] interface {
	Get() (T, error)
	Put(resource T)
	Close()
	Len() int
	Stats() (active, idle int)
}

// FileStreamer 文件流处理器接口
type FileStreamer interface {
	Process(filePath string, processor func(chunk []byte, offset int64) error) error
	ProcessReader(reader http.Request, processor func(chunk []byte, offset int64) error) error
}

// SSEHub SSE中心接口
type SSEHub interface {
	RegisterClient(client SSEClient)
	UnregisterClient(client SSEClient)
	Broadcast(event *SSEEvent)
	GetClients() []string
	Close()
}

// SSEClient SSE客户端接口
type SSEClient interface {
	GetID() string
	Send(event *SSEEvent) error
	Close()
}

// SSEEvent SSE事件结构
type SSEEvent struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
	ID    string      `json:"id"`
	Retry int         `json:"retry"`
}

// UploadConfig 文件上传配置
type UploadConfig struct {
	AllowedExts []string // 允许的文件扩展名
	MaxSize     int64    // 最大文件大小（字节）
	SavePath    string   // 保存路径
}

// Pagination 分页信息结构体
type Pagination struct {
	CurrentPage int   `json:"current_page"`
	PageSize    int   `json:"page_size"`
	TotalCount  int64 `json:"total_count"`
	TotalPages  int   `json:"total_pages,omitempty"`
}

// ListResponse 通用列表响应结构体
type ListResponse struct {
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

// Response 统一响应结构
type Response struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data,omitempty"`
	URL  string      `json:"url,omitempty"`
}

// AuthInfo 表示认证用户的基础信息
type AuthInfo struct {
	UserID   string   `json:"user_id,omitempty"`
	Username string   `json:"username,omitempty"`
	Email    string   `json:"email,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Extra    H        `json:"extra,omitempty"`
}

// Claims 将 AuthInfo 转换为 JWT 载荷
func (a AuthInfo) Claims() H {
	claims := H{}
	if a.UserID != "" {
		claims["user_id"] = a.UserID
	}
	if a.Username != "" {
		claims["username"] = a.Username
	}
	if a.Email != "" {
		claims["email"] = a.Email
	}
	if len(a.Roles) > 0 {
		claims["roles"] = a.Roles
	}
	for k, v := range a.Extra {
		claims[k] = v
	}
	return claims
}

// HasRole 判断是否包含指定角色（不区分大小写）
func (a AuthInfo) HasRole(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return false
	}
	for _, r := range a.Roles {
		if strings.ToLower(r) == role {
			return true
		}
	}
	return false
}

// HasAnyRole 判断是否包含任意一个角色
func (a AuthInfo) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if a.HasRole(role) {
			return true
		}
	}
	return false
}

// Validator 验证器接口
type Validator interface {
	Validate() (bool, string)
}

// 常量定义
const (
	SuccessCode   = 200 // 成功状态码
	FailCode      = 400 // 失败状态码
	ErrorCode     = 500 // 错误状态码
	ForbiddenCode = 403 // 禁止访问状态码
	NotFoundCode  = 404 // 资源不存在状态码
)

// JWT常量
const (
	JWTHeaderKey = "Authorization"
	JWTQueryKey  = "token"
	JWTCookieKey = "token"
	JWTPrefix    = "Bearer "
)

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
