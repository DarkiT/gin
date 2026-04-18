package middleware

import (
	"bytes"
	"net/http"
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
	ttl      time.Duration
	store    IdempotentStore
	keyFunc  func(*gin.Context) string
	skipFunc func(*gin.Context) bool
}

const idempotentHeaderKey = "Idempotency-Key"

// Idempotent 幂等性中间件（默认配置）
func Idempotent(opts ...IdempotentOption) gin.HandlerFunc {
	options := &idempotentOptions{
		ttl:      5 * time.Minute,
		store:    NewMemoryIdempotentStore(),
		keyFunc:  defaultIdempotentKeyFunc,
		skipFunc: defaultIdempotentSkipFunc,
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

	return func(c *gin.Context) {
		if options.skipFunc(c) {
			c.Next()
			return
		}

		key := options.keyFunc(c)
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

func defaultIdempotentKeyFunc(c *gin.Context) string {
	return c.GetHeader(idempotentHeaderKey)
}

func defaultIdempotentSkipFunc(c *gin.Context) bool {
	return false
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
