package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkit/gin"
)

// NonceStore Nonce存储接口（防重放）
type NonceStore interface {
	// Exists 检查 nonce 是否已存在
	Exists(nonce string) bool

	// Set 设置 nonce，并指定过期时间
	Set(nonce string, expiry time.Duration) error
}

// MemoryNonceStore 内存存储实现（用于开发/测试）
type MemoryNonceStore struct {
	mu    sync.RWMutex
	store map[string]time.Time
	done  chan struct{}
	wg    sync.WaitGroup
}

// NewMemoryNonceStore 创建内存 Nonce 存储并启动清理任务
func NewMemoryNonceStore() *MemoryNonceStore {
	store := &MemoryNonceStore{
		store: make(map[string]time.Time),
		done:  make(chan struct{}),
	}

	// 启动清理 goroutine，每分钟清理一次过期条目
	store.wg.Add(1)
	go store.cleanupExpired()

	return store
}

// Exists 检查 nonce 是否存在且未过期
func (s *MemoryNonceStore) Exists(nonce string) bool {
	s.mu.RLock()
	expiry, exists := s.store[nonce]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	// 检查是否过期
	if time.Now().After(expiry) {
		return false
	}

	return true
}

// Set 存储 nonce 及其过期时间
func (s *MemoryNonceStore) Set(nonce string, expiry time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.store[nonce] = time.Now().Add(expiry)
	return nil
}

// cleanupExpired 定期清理过期的 nonce
func (s *MemoryNonceStore) cleanupExpired() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for nonce, expiry := range s.store {
				if now.After(expiry) {
					delete(s.store, nonce)
				}
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}

// Close 停止清理 goroutine
func (s *MemoryNonceStore) Close() error {
	close(s.done)
	s.wg.Wait()
	return nil
}

// SignatureOption 签名验证配置选项
type SignatureOption func(*signatureOptions)

const DefaultMaxBodySize int64 = 10 * 1024 * 1024

// signatureOptions 签名验证配置
type signatureOptions struct {
	secret      string     // 签名密钥
	expiry      int64      // 时间戳过期时间（秒）
	nonceStore  NonceStore // Nonce 存储
	algorithm   string     // 签名算法
	headers     []string   // 参与签名的额外 header
	maxBodySize int64      // 请求体大小限制
}

// WithSignatureSecret 设置签名密钥
func WithSignatureSecret(secret string) SignatureOption {
	return func(opts *signatureOptions) {
		opts.secret = secret
	}
}

// WithSignatureExpiry 设置时间戳过期时间（秒）
func WithSignatureExpiry(expiry int64) SignatureOption {
	return func(opts *signatureOptions) {
		if expiry > 0 {
			opts.expiry = expiry
		}
	}
}

// WithSignatureNonceStore 设置自定义 Nonce 存储
func WithSignatureNonceStore(store NonceStore) SignatureOption {
	return func(opts *signatureOptions) {
		opts.nonceStore = store
	}
}

// WithSignatureAlgorithm 设置签名算法（HMAC-SHA256, HMAC-SHA1）
func WithSignatureAlgorithm(algo string) SignatureOption {
	return func(opts *signatureOptions) {
		algo = strings.ToUpper(strings.TrimSpace(algo))
		if algo == "HMAC-SHA256" || algo == "HMAC-SHA1" {
			opts.algorithm = algo
		}
	}
}

// WithSignatureHeaders 设置参与签名的额外 header
func WithSignatureHeaders(headers ...string) SignatureOption {
	return func(opts *signatureOptions) {
		opts.headers = headers
	}
}

// WithSignatureMaxBodySize 设置请求体大小限制
func WithSignatureMaxBodySize(maxBodySize int64) SignatureOption {
	return func(opts *signatureOptions) {
		if maxBodySize > 0 {
			opts.maxBodySize = maxBodySize
		}
	}
}

// SignatureVerify 签名验证中间件
func SignatureVerify(opts ...SignatureOption) gin.HandlerFunc {
	// 初始化默认配置
	options := &signatureOptions{
		secret:      "",
		expiry:      300, // 默认 5 分钟
		nonceStore:  NewMemoryNonceStore(),
		algorithm:   "HMAC-SHA256",
		headers:     []string{},
		maxBodySize: DefaultMaxBodySize,
	}

	// 应用配置选项
	for _, opt := range opts {
		opt(options)
	}

	// 验证必要配置
	if options.secret == "" {
		panic("gin/middleware: signature secret is required")
	}

	return func(c *gin.Context) {
		// 1. 获取必要的请求头
		timestamp := c.GetHeader("X-Timestamp")
		nonce := c.GetHeader("X-Nonce")
		signature := c.GetHeader("X-Signature")

		// 2. 验证必要的请求头是否存在
		if timestamp == "" || nonce == "" || signature == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing required headers: X-Timestamp, X-Nonce, X-Signature",
			})
			return
		}

		// 3. 验证时间戳格式
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid timestamp format",
			})
			return
		}

		// 4. 验证时间戳是否过期
		now := time.Now().Unix()
		if now-ts > options.expiry || ts > now+options.expiry {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "timestamp expired or invalid",
			})
			return
		}

		// 5. 检查 nonce 是否已使用（防重放攻击）
		if options.nonceStore.Exists(nonce) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "nonce already used (replay attack detected)",
			})
			return
		}

		// 6. 读取请求体
		limitedReader := &io.LimitedReader{R: c.Request.Body, N: options.maxBodySize + 1}
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to read request body",
			})
			return
		}
		if int64(len(body)) > options.maxBodySize {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large",
			})
			return
		}

		// 7. 恢复请求体（以便后续处理）
		c.Request.Body = io.NopCloser(strings.NewReader(string(body)))

		// 8. 构建签名字符串
		signString := buildSignString(c, timestamp, nonce, string(body), options.headers)

		// 9. 计算期望的签名
		expectedSignature := computeSignature(signString, options.secret, options.algorithm)

		// 10. 验证签名
		if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid signature",
			})
			return
		}

		// 11. 存储 nonce（防止重放攻击）
		if err := options.nonceStore.Set(nonce, time.Duration(options.expiry)*time.Second); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to store nonce",
			})
			return
		}

		// 12. 验证通过，继续处理
		c.Next()
	}
}

// buildSignString 构建签名字符串
// 格式：timestamp + nonce + method + path + body + headers
func buildSignString(c *gin.Context, timestamp, nonce, body string, headers []string) string {
	var builder strings.Builder

	// 基本字段
	builder.WriteString(timestamp)
	builder.WriteString(nonce)
	builder.WriteString(c.Request.Method)
	builder.WriteString(c.Request.URL.Path)
	builder.WriteString(body)

	// 额外的 header
	sortedHeaders := make([]string, len(headers))
	copy(sortedHeaders, headers)
	sort.Strings(sortedHeaders)
	for _, header := range sortedHeaders {
		value := c.GetHeader(header)
		builder.WriteString(value)
	}

	return builder.String()
}

// computeSignature 计算签名
func computeSignature(data, secret, algorithm string) string {
	var h []byte

	switch algorithm {
	case "HMAC-SHA256":
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(data))
		h = mac.Sum(nil)
	case "HMAC-SHA1":
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(data))
		h = mac.Sum(nil)
	default:
		// 默认使用 HMAC-SHA256
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(data))
		h = mac.Sum(nil)
	}

	return hex.EncodeToString(h)
}

// GenerateSignature 生成签名（辅助函数，用于客户端生成签名）
func GenerateSignature(method, path, body, timestamp, nonce, secret string, algorithm string, headers map[string]string) string {
	var builder strings.Builder

	// 基本字段
	builder.WriteString(timestamp)
	builder.WriteString(nonce)
	builder.WriteString(method)
	builder.WriteString(path)
	builder.WriteString(body)

	// 额外的 header（按键排序）
	if headers != nil {
		sortedKeys := make([]string, 0, len(headers))
		for key := range headers {
			sortedKeys = append(sortedKeys, key)
		}
		sort.Strings(sortedKeys)
		for _, key := range sortedKeys {
			builder.WriteString(headers[key])
		}
	}

	signString := builder.String()

	if algorithm == "" {
		algorithm = "HMAC-SHA256"
	}

	return computeSignature(signString, secret, algorithm)
}

// GenerateNonce 生成随机 nonce（辅助函数）
func GenerateNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// MustGenerateNonce 生成随机 nonce，失败时 panic。
func MustGenerateNonce() string {
	nonce, err := GenerateNonce()
	if err != nil {
		panic(err)
	}
	return nonce
}
