package middleware

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/darkit/gin"
)

// IdempotentOption 幂等性配置选项
type IdempotentOption func(*idempotentOptions)

// HandlerFunc 兼容原生 gin 中间件类型
type HandlerFunc = gin.HandlerFunc

// Context 兼容原生 gin 上下文类型
type Context = gin.Context

type idempotentOptions struct {
	ttl           time.Duration
	store         IdempotentStore
	keyFunc       func(*gin.Context) string
	skipFunc      func(*gin.Context) bool
	namespaceFunc func(*gin.Context) string
}

const idempotentHeaderKey = "Idempotency-Key"

// Idempotent 幂等性中间件（默认配置）
func Idempotent(opts ...IdempotentOption) gin.HandlerFunc {
	options := &idempotentOptions{
		ttl:           5 * time.Minute,
		store:         NewMemoryIdempotentStore(),
		keyFunc:       defaultIdempotentKeyFunc,
		skipFunc:      defaultIdempotentSkipFunc,
		namespaceFunc: defaultIdempotentNamespaceFunc,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.store == nil {
		options.store = NewMemoryIdempotentStore()
	}

	if options.keyFunc == nil {
		options.keyFunc = defaultIdempotentKeyFunc
	}

	if options.skipFunc == nil {
		options.skipFunc = defaultIdempotentSkipFunc
	}

	if options.namespaceFunc == nil {
		options.namespaceFunc = defaultIdempotentNamespaceFunc
	}

	return func(c *gin.Context) {
		if options.skipFunc(c) {
			c.Next()
			return
		}

		key := buildIdempotentKey(c, options)
		if key == "" {
			c.Next()
			return
		}

		if statusCode, body, exists := options.store.Get(key); exists {
			c.Status(statusCode)
			if len(body) > 0 {
				_, _ = c.Writer.Write(body)
			}
			c.Abort()
			return
		}

		// 原子占位防并发重复执行：同一 key 的并发请求，只有首个能占位成功并继续执行；
		// 其余请求说明已有 in-flight 请求在处理，返回 409 Conflict 避免重复扣款/创建。
		if !options.store.Reserve(key, options.ttl) {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"error": "idempotent request already in progress",
			})
			return
		}

		// committed 标记响应是否已成功写入缓存；defer 兜底：handler panic / abort / 写缓存失败时，
		// 删除 pending 占位让后续请求可重试，避免占位残留到 TTL 期间同 key 被全部 409 锁死。
		committed := false
		defer func() {
			if !committed {
				_ = options.store.Delete(key)
			}
		}()

		writer := &idempotentResponseWriter{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
			statusCode:     http.StatusOK,
		}
		c.Writer = writer

		c.Next()

		if c.IsAborted() {
			return
		}

		statusCode := writer.statusCode
		if statusCode == 0 {
			statusCode = c.Writer.Status()
		}

		if err := options.store.Set(key, statusCode, writer.body.Bytes(), options.ttl); err != nil {
			return
		}
		committed = true
	}
}

// IdempotentWithTTL 带自定义 TTL 的幂等性中间件
func IdempotentWithTTL(ttl time.Duration) gin.HandlerFunc {
	return Idempotent(WithIdempotentTTL(ttl))
}

// WithIdempotentTTL 设置缓存 TTL
func WithIdempotentTTL(ttl time.Duration) IdempotentOption {
	return func(opts *idempotentOptions) {
		if ttl > 0 {
			opts.ttl = ttl
		}
	}
}

// WithIdempotentStore 设置自定义存储
func WithIdempotentStore(store IdempotentStore) IdempotentOption {
	return func(opts *idempotentOptions) {
		opts.store = store
	}
}

// WithIdempotentKeyFunc 设置 Key 获取函数
func WithIdempotentKeyFunc(fn func(*gin.Context) string) IdempotentOption {
	return func(opts *idempotentOptions) {
		opts.keyFunc = fn
	}
}

// WithIdempotentSkipFunc 设置跳过函数
func WithIdempotentSkipFunc(fn func(*gin.Context) bool) IdempotentOption {
	return func(opts *idempotentOptions) {
		opts.skipFunc = fn
	}
}

// WithIdempotentNamespaceFunc 设置幂等键命名空间函数。
// 返回值会追加到 method/path/key 之后，适合按租户、主体或业务域隔离重放边界。
func WithIdempotentNamespaceFunc(fn func(*gin.Context) string) IdempotentOption {
	return func(opts *idempotentOptions) {
		opts.namespaceFunc = fn
	}
}

func defaultIdempotentKeyFunc(c *gin.Context) string {
	return c.GetHeader(idempotentHeaderKey)
}

func defaultIdempotentSkipFunc(c *gin.Context) bool {
	return false
}

// defaultIdempotentNamespaceFunc 默认把鉴权主体（user_id）纳入幂等键命名空间，避免：
//  1. 横向越权——知道他人 Idempotency-Key 即命中他人缓存响应（信息泄漏）；
//  2. 跨主体共享——不同用户用相同 key 时互相干扰。
//
// 无鉴权主体时返回空串，行为与旧版一致（向后兼容）。
func defaultIdempotentNamespaceFunc(c *gin.Context) string {
	return c.GetString("user_id")
}

func buildIdempotentKey(c *gin.Context, options *idempotentOptions) string {
	if c == nil || c.Request == nil || options == nil || options.keyFunc == nil {
		return ""
	}
	requestKey := strings.TrimSpace(options.keyFunc(c))
	if requestKey == "" {
		return ""
	}
	namespace := ""
	if options.namespaceFunc != nil {
		namespace = strings.TrimSpace(options.namespaceFunc(c))
	}
	path := ""
	if c.Request.URL != nil {
		path = c.Request.URL.Path
	}
	if path == "" {
		path = c.FullPath()
	}
	if path == "" {
		path = "/"
	}

	h := sha256.New()
	h.Write([]byte(c.Request.Method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(requestKey))
	h.Write([]byte{0})
	h.Write([]byte(namespace))
	return fmt.Sprintf("idempotent:%x", h.Sum(nil))
}

// idempotentResponseWriter 包装 gin.ResponseWriter，捕获响应数据
type idempotentResponseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (w *idempotentResponseWriter) Write(data []byte) (int, error) {
	_, _ = w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

func (w *idempotentResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
