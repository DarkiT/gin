package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkit/gin"
	"golang.org/x/time/rate"
)

// RateLimitOption 限流配置选项
type RateLimitOption func(*rateLimitOptions)

type rateLimitOptions struct {
	store    RateLimitStore
	onLimit  func(*gin.Context)
	burst    int
	fallback float64
}

// RateLimitByUser 按用户限流（默认从 context 获取 user_id）
func RateLimitByUser(limit string, opts ...RateLimitOption) gin.HandlerFunc {
	return rateLimitByKey(defaultUserKeyFunc, limit, opts...)
}

// RateLimitByKey 按自定义 Key 限流
func RateLimitByKey(keyFunc func(*gin.Context) string, limit string, opts ...RateLimitOption) gin.HandlerFunc {
	if keyFunc == nil {
		keyFunc = defaultUserKeyFunc
	}
	return rateLimitByKey(keyFunc, limit, opts...)
}

// RateLimitTier 分级限流
func RateLimitTier(tiers map[string]float64, tierFunc func(*gin.Context) string, opts ...RateLimitOption) gin.HandlerFunc {
	options := newRateLimitOptions(opts...)
	compiled := compileTierRates(tiers, options.fallback)

	if tierFunc == nil {
		tierFunc = defaultTierFunc
	}

	return func(c *gin.Context) {
		tier := strings.TrimSpace(tierFunc(c))
		ratePerSecond := compiled[tier]
		if ratePerSecond == 0 {
			ratePerSecond = compiled[""]
		}
		identity := rateLimitIdentity(c, defaultUserKeyFunc)
		if identity == "" {
			identity = c.ClientIP()
		}
		key := "tier:" + tier + ":" + identity
		if !options.allow(key, ratePerSecond) {
			handleRateLimitBlocked(c, options)
			return
		}
		c.Next()
	}
}

// WithRateLimitStore 设置自定义存储
func WithRateLimitStore(store RateLimitStore) RateLimitOption {
	return func(opts *rateLimitOptions) {
		opts.store = store
	}
}

// WithRateLimitOnLimit 设置限流回调
func WithRateLimitOnLimit(fn func(*gin.Context)) RateLimitOption {
	return func(opts *rateLimitOptions) {
		opts.onLimit = fn
	}
}

// WithRateLimitBurst 设置突发容量
func WithRateLimitBurst(burst int) RateLimitOption {
	return func(opts *rateLimitOptions) {
		if burst > 0 {
			opts.burst = burst
		}
	}
}

func rateLimitByKey(keyFunc func(*gin.Context) string, limit string, opts ...RateLimitOption) gin.HandlerFunc {
	options := newRateLimitOptions(opts...)
	ratePerSecond, burst, err := parseRateLimit(limit, options.burst)
	if err != nil {
		panic(err)
	}

	return func(c *gin.Context) {
		key := rateLimitIdentity(c, keyFunc)
		if key == "" {
			// 鉴权主体未建立（keyFunc 返回空）时，回退到 IP 维度限流；
			// 禁止静默放行——否则未鉴权请求将完全绕过限流（限流旁路）。
			key = c.ClientIP()
		}
		key = "key:" + key
		if !options.allowWithBurst(key, ratePerSecond, burst) {
			handleRateLimitBlocked(c, options)
			return
		}
		c.Next()
	}
}

func newRateLimitOptions(opts ...RateLimitOption) *rateLimitOptions {
	options := &rateLimitOptions{
		burst:    1,
		fallback: 1,
	}
	for _, opt := range opts {
		opt(options)
	}
	if options.store == nil {
		options.store = newMemoryRateLimitStore()
	}
	if options.fallback <= 0 {
		options.fallback = 1
	}
	return options
}

func (o *rateLimitOptions) allow(key string, ratePerSecond float64) bool {
	return o.allowWithBurst(key, ratePerSecond, o.burst)
}

func (o *rateLimitOptions) allowWithBurst(key string, ratePerSecond float64, burst int) bool {
	if burst <= 0 {
		burst = o.burst
	}
	if ratePerSecond <= 0 {
		ratePerSecond = o.fallback
	}
	return o.store.Allow(key, ratePerSecond, burst)
}

func handleRateLimitBlocked(c *gin.Context, options *rateLimitOptions) {
	if options.onLimit != nil {
		options.onLimit(c)
		if c.IsAborted() {
			return
		}
	}
	c.AbortWithStatus(http.StatusTooManyRequests)
}

// defaultUserKeyFunc 仅信任鉴权中间件写入 context 的 user_id。
//
// 禁止回退读取客户端可控的 X-User-ID 头：该头完全由请求方伪造，一旦信任，攻击者只需
// 每个请求换一个 X-User-ID 即可每个"用户"各拿一份限流配额，彻底击穿按用户限流。
// 鉴权主体未建立时返回空串，由调用方回退到 IP 维度。
func defaultUserKeyFunc(c *gin.Context) string {
	return c.GetString("user_id")
}

func defaultTierFunc(c *gin.Context) string {
	return c.GetString("user_tier")
}

func rateLimitIdentity(c *gin.Context, keyFunc func(*gin.Context) string) string {
	if keyFunc == nil {
		return ""
	}
	key := strings.TrimSpace(keyFunc(c))
	if key != "" {
		return key
	}
	return ""
}

func compileTierRates(tiers map[string]float64, fallback float64) map[string]float64 {
	compiled := make(map[string]float64, len(tiers)+1)
	for tier, value := range tiers {
		compiled[strings.TrimSpace(tier)] = normalizeRate(value, fallback)
	}
	compiled[""] = normalizeRate(fallback, fallback)
	return compiled
}

func normalizeRate(value float64, fallback float64) float64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func parseRateLimit(limit string, defaultBurst int) (float64, int, error) {
	limit = strings.TrimSpace(limit)
	if limit == "" {
		return 0, 0, fmt.Errorf("gin/middleware: rate limit cannot be empty")
	}

	parts := strings.Split(limit, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("gin/middleware: invalid rate limit format")
	}

	count, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	if err != nil || count <= 0 {
		return 0, 0, fmt.Errorf("gin/middleware: invalid rate limit count")
	}

	window, err := parseRateWindow(parts[1])
	if err != nil {
		return 0, 0, err
	}

	ratePerSecond := count / window.Seconds()
	burst := defaultBurst
	if burst <= 0 {
		burst = max(int(count), 1)
	}

	return ratePerSecond, burst, nil
}

func parseRateWindow(window string) (time.Duration, error) {
	window = strings.TrimSpace(window)
	if window == "" {
		return 0, fmt.Errorf("gin/middleware: invalid rate limit window")
	}

	// 如果只有一个字符（单位），默认为 1
	if len(window) == 1 {
		switch window[0] {
		case 'S', 's':
			return time.Second, nil
		case 'M', 'm':
			return time.Minute, nil
		case 'H', 'h':
			return time.Hour, nil
		default:
			return 0, fmt.Errorf("gin/middleware: invalid rate limit window")
		}
	}

	unit := window[len(window)-1]
	value := strings.TrimSpace(window[:len(window)-1])
	count, err := strconv.ParseFloat(value, 64)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("gin/middleware: invalid rate limit window")
	}

	switch unit {
	case 'S', 's':
		return time.Duration(count * float64(time.Second)), nil
	case 'M', 'm':
		return time.Duration(count * float64(time.Minute)), nil
	case 'H', 'h':
		return time.Duration(count * float64(time.Hour)), nil
	case 'D', 'd':
		return time.Duration(count * float64(24*time.Hour)), nil
	default:
		return 0, fmt.Errorf("gin/middleware: unsupported rate limit window")
	}
}

type rateLimiterBucket struct {
	mu      sync.Mutex
	limiter *rate.Limiter
	rate    rate.Limit
	burst   int
}

func newRateLimiterBucket(ratePerSecond float64, burst int) *rateLimiterBucket {
	return &rateLimiterBucket{
		limiter: rate.NewLimiter(rate.Limit(ratePerSecond), burst),
		rate:    rate.Limit(ratePerSecond),
		burst:   burst,
	}
}

func (b *rateLimiterBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.limiter.Allow()
}

func (b *rateLimiterBucket) Update(ratePerSecond float64, burst int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	newRate := rate.Limit(ratePerSecond)
	if newRate != b.rate {
		b.limiter.SetLimit(newRate)
		b.rate = newRate
	}
	if burst > 0 && burst != b.burst {
		b.limiter.SetBurst(burst)
		b.burst = burst
	}
}
