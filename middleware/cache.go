package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"net/http"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/pkg/cache"
)

// cachedResponse 缓存的响应结构
type cachedResponse struct {
	Status  int         // HTTP 状态码
	Headers http.Header // 响应头
	Body    []byte      // 响应体
}

// cacheOptions 缓存选项配置
type cacheOptions struct {
	store        cache.Cache               // 缓存存储
	keyFunc      func(*gin.Context) string // 缓存键生成函数
	cacheControl string                    // Cache-Control 头
	varyHeaders  []string                  // Vary 头
}

// CacheOption 缓存选项函数类型
type CacheOption func(*cacheOptions)

// WithCacheStore 设置缓存存储（用于分布式缓存，如 Redis）
func WithCacheStore(store cache.Cache) CacheOption {
	return func(o *cacheOptions) {
		o.store = store
	}
}

// WithCacheKey 设置自定义缓存键生成函数
func WithCacheKey(keyFunc func(*gin.Context) string) CacheOption {
	return func(o *cacheOptions) {
		o.keyFunc = keyFunc
	}
}

// WithCacheControl 设置 Cache-Control 响应头
func WithCacheControl(control string) CacheOption {
	return func(o *cacheOptions) {
		o.cacheControl = control
	}
}

// WithCacheVary 设置 Vary 响应头
func WithCacheVary(headers ...string) CacheOption {
	return func(o *cacheOptions) {
		o.varyHeaders = headers
	}
}

// responseWriter 自定义响应写入器，用于拦截响应内容
type responseWriter struct {
	gin.ResponseWriter
	status int
	body   *bytes.Buffer
}

// newResponseWriter 创建新的响应写入器
func newResponseWriter(w gin.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

// Write 写入响应体
func (w *responseWriter) Write(data []byte) (int, error) {
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

// WriteString 写入字符串响应体
func (w *responseWriter) WriteString(s string) (int, error) {
	w.body.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}

// WriteHeader 写入响应状态码
func (w *responseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Status 获取响应状态码
func (w *responseWriter) Status() int {
	return w.status
}

// defaultCacheKey 默认缓存键生成函数
// 格式: method:path:querystring
func defaultCacheKey(c *gin.Context) string {
	h := sha256.New()
	h.Write([]byte(c.Request.Method))
	h.Write([]byte(":"))
	h.Write([]byte(c.Request.URL.Path))
	h.Write([]byte(":"))
	h.Write([]byte(c.Request.URL.RawQuery))
	return fmt.Sprintf("cache:%x", h.Sum(nil))
}

// Cache 响应缓存中间件
// 缓存 HTTP 响应指定时间
func Cache(duration time.Duration, opts ...CacheOption) gin.HandlerFunc {
	// 默认选项
	options := &cacheOptions{
		store:   cache.NewMemoryCache(),
		keyFunc: defaultCacheKey,
	}

	// 应用自定义选项
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		// 只缓存 GET 和 HEAD 请求
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Next()
			return
		}

		// 生成缓存键
		key := options.keyFunc(c)

		// 尝试从缓存获取
		ctx := context.Background()
		cached, err := options.store.Get(ctx, key)
		if err == nil {
			// 缓存命中，反序列化并返回
			var resp cachedResponse
			if err := gob.NewDecoder(bytes.NewReader(cached)).Decode(&resp); err == nil {
				// 设置响应头
				for k, v := range resp.Headers {
					for _, val := range v {
						c.Header(k, val)
					}
				}

				// 设置 Cache-Control
				if options.cacheControl != "" {
					c.Header("Cache-Control", options.cacheControl)
				}

				// 设置 Vary
				if len(options.varyHeaders) > 0 {
					for _, h := range options.varyHeaders {
						c.Writer.Header().Add("Vary", h)
					}
				}

				// 设置缓存状态
				c.Header("X-Cache", "HIT")

				// 返回缓存的响应
				c.Data(resp.Status, c.GetHeader("Content-Type"), resp.Body)
				c.Abort()
				return
			}
		}

		// 缓存未命中，创建自定义响应写入器
		writer := newResponseWriter(c.Writer)
		c.Writer = writer

		// 设置缓存状态
		c.Header("X-Cache", "MISS")

		// 继续处理请求
		c.Next()

		// 只缓存成功的响应（2xx）
		if writer.Status() >= 200 && writer.Status() < 300 {
			// 复制响应头
			headers := make(http.Header)
			for k, v := range c.Writer.Header() {
				headers[k] = v
			}

			// 创建缓存响应
			resp := cachedResponse{
				Status:  writer.Status(),
				Headers: headers,
				Body:    writer.body.Bytes(),
			}

			// 序列化响应
			var buf bytes.Buffer
			if err := gob.NewEncoder(&buf).Encode(&resp); err == nil {
				// 保存到缓存
				_ = options.store.Set(ctx, key, buf.Bytes(), duration)
			}
		}
	}
}

// CacheIf 条件缓存中间件
// 根据条件决定是否缓存响应
func CacheIf(condition func(*gin.Context) bool, duration time.Duration, opts ...CacheOption) gin.HandlerFunc {
	cacheHandler := Cache(duration, opts...)

	return func(c *gin.Context) {
		// 检查条件
		if !condition(c) {
			c.Next()
			return
		}

		// 条件满足，使用缓存
		cacheHandler(c)
	}
}
