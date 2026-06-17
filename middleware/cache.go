package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"net/http"
	"strings"
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
	skipFunc     func(*gin.Context) bool   // 跳过缓存判断
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

// WithCacheVary 设置 Vary 响应头，并将请求侧对应 Header 值纳入缓存键。
func WithCacheVary(headers ...string) CacheOption {
	return func(o *cacheOptions) {
		o.varyHeaders = normalizeCacheVaryHeaders(headers)
	}
}

// WithCacheSkip 设置跳过缓存的判断函数。
func WithCacheSkip(skip func(*gin.Context) bool) CacheOption {
	return func(o *cacheOptions) {
		o.skipFunc = skip
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

// defaultCacheKey 默认缓存键生成函数。
// 格式: method:path:querystring；WithCacheVary 会在此基础上追加请求 Header 维度。
func defaultCacheKey(c *gin.Context) string {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return ""
	}
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
		store:   cache.NewMemory(cache.WithCleanupInterval(0)),
		keyFunc: defaultCacheKey,
	}

	// 应用自定义选项
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	if options.store == nil {
		options.store = cache.NewMemory(cache.WithCleanupInterval(0))
	}
	if options.keyFunc == nil {
		options.keyFunc = defaultCacheKey
	}

	return func(c *gin.Context) {
		if c == nil || c.Request == nil {
			return
		}
		// 只缓存 GET 和 HEAD 请求
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Next()
			return
		}
		if shouldSkipCache(c, options) {
			c.Next()
			return
		}

		// 生成缓存键
		key := buildCacheKey(c, options)
		if key == "" {
			c.Next()
			return
		}

		// 尝试从缓存获取
		ctx := cacheRequestContext(c)
		cached, err := options.store.Get(ctx, key)
		if err == nil {
			// 缓存命中，反序列化并返回
			var resp cachedResponse
			if err := gob.NewDecoder(bytes.NewReader(cached)).Decode(&resp); err == nil {
				// 设置响应头
				copyCachedHeaders(c.Writer.Header(), resp.Headers)

				// 设置 Cache-Control
				if options.cacheControl != "" {
					c.Header("Cache-Control", options.cacheControl)
				}

				// 设置 Vary
				writeVaryHeaders(c, options.varyHeaders)

				// 设置缓存状态
				c.Header("X-Cache", "HIT")

				// 返回缓存的响应
				c.Data(resp.Status, resp.Headers.Get("Content-Type"), resp.Body)
				c.Abort()
				return
			}
		}

		// 缓存未命中，创建自定义响应写入器
		writer := newResponseWriter(c.Writer)
		c.Writer = writer

		// 设置缓存状态与 Vary 响应头
		c.Header("X-Cache", "MISS")
		writeVaryHeaders(c, options.varyHeaders)

		// 继续处理请求
		c.Next()

		// 只缓存明确可安全复用的成功响应
		if responseCacheable(writer) {
			// 复制响应头
			headers := cloneHeader(c.Writer.Header())

			// 创建缓存响应
			resp := cachedResponse{
				Status:  writer.Status(),
				Headers: headers,
				Body:    append([]byte(nil), writer.body.Bytes()...),
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

func shouldSkipCache(c *gin.Context, options *cacheOptions) bool {
	if options != nil && options.skipFunc != nil && options.skipFunc(c) {
		return true
	}
	if c.GetHeader("Authorization") != "" || c.GetHeader("Cookie") != "" {
		return true
	}
	if cacheControlHasDirective(c.GetHeader("Cache-Control"), "no-cache", "no-store") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(c.GetHeader("Pragma")), "no-cache")
}

func buildCacheKey(c *gin.Context, options *cacheOptions) string {
	if options == nil || options.keyFunc == nil {
		return ""
	}
	base := options.keyFunc(c)
	if base == "" || len(options.varyHeaders) == 0 {
		return base
	}

	h := sha256.New()
	h.Write([]byte(base))
	for _, header := range options.varyHeaders {
		h.Write([]byte{0})
		h.Write([]byte(http.CanonicalHeaderKey(header)))
		for _, value := range c.Request.Header.Values(header) {
			h.Write([]byte{0})
			h.Write([]byte(value))
		}
	}
	return fmt.Sprintf("%s:vary:%x", base, h.Sum(nil))
}

func normalizeCacheVaryHeaders(headers []string) []string {
	seen := make(map[string]struct{}, len(headers))
	result := make([]string, 0, len(headers))
	for _, header := range headers {
		header = http.CanonicalHeaderKey(strings.TrimSpace(header))
		if header == "" {
			continue
		}
		lower := strings.ToLower(header)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		result = append(result, header)
	}
	return result
}

func responseCacheable(writer *responseWriter) bool {
	if writer == nil {
		return false
	}
	status := writer.Status()
	if status < 200 || status >= 300 {
		return false
	}
	headers := writer.Header()
	if len(headers.Values("Set-Cookie")) > 0 {
		return false
	}
	return !cacheControlHasDirective(headers.Get("Cache-Control"), "private", "no-cache", "no-store")
}

func cacheControlHasDirective(header string, directives ...string) bool {
	if header == "" {
		return false
	}
	wanted := make(map[string]struct{}, len(directives))
	for _, directive := range directives {
		wanted[strings.ToLower(strings.TrimSpace(directive))] = struct{}{}
	}
	for part := range strings.SplitSeq(header, ",") {
		directive := strings.ToLower(strings.TrimSpace(part))
		if idx := strings.IndexByte(directive, '='); idx >= 0 {
			directive = strings.TrimSpace(directive[:idx])
		}
		if _, ok := wanted[directive]; ok {
			return true
		}
	}
	return false
}

func writeVaryHeaders(c *gin.Context, headers []string) {
	if len(headers) == 0 {
		return
	}
	for _, h := range headers {
		addHeaderValueOnce(c.Writer.Header(), "Vary", h)
	}
}

func addHeaderValueOnce(header http.Header, key string, value string) {
	for _, existing := range header.Values(key) {
		if strings.EqualFold(existing, value) {
			return
		}
	}
	header.Add(key, value)
}

func copyCachedHeaders(dst, src http.Header) {
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func cloneHeader(src http.Header) http.Header {
	clone := make(http.Header, len(src))
	for key, values := range src {
		clone[key] = append([]string(nil), values...)
	}
	return clone
}

func cacheRequestContext(c *gin.Context) context.Context {
	if c != nil && c.Request != nil && c.Request.Context() != nil {
		return c.Request.Context()
	}
	return context.Background()
}
