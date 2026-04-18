package middleware

import (
	"strconv"
	"time"

	"github.com/darkit/gin"
)

const (
	errCapacityExceeded = "Server capacity exceeded."
	errTimedOut         = "Timed out while waiting for a pending request to complete."
	errContextCanceled  = "Context was canceled."
)

var defaultBacklogTimeout = time.Second * 60

// ThrottleOpts 节流选项配置
type ThrottleOpts struct {
	// RetryAfterFn 计算 Retry-After 响应头的函数
	// ctxDone 表示是否因为 context 取消而返回
	RetryAfterFn func(ctxDone bool) time.Duration

	// Limit 并发处理的请求数上限
	Limit int

	// BacklogLimit 等待队列的最大长度
	// 超过此限制的请求将立即被拒绝
	BacklogLimit int

	// BacklogTimeout 等待队列中请求的最大等待时间
	BacklogTimeout time.Duration

	// StatusCode 限流时返回的 HTTP 状态码，默认 429
	StatusCode int
}

// Throttle 并发请求限流中间件
//
// 限制同时处理的请求数量，超出限制的请求将被拒绝或进入等待队列。
// 注意: 这不是基于用户的速率限制器，而是对所有请求的全局并发数限制。
//
// 使用场景:
//   - 保护后端服务不被过载
//   - 控制数据库连接数
//   - 限制 CPU/内存密集型操作的并发数
//
// 使用示例:
//
//	// 限制同时处理 100 个请求
//	router.Use(middleware.Throttle(100))
//
//	// 限制 100 个并发，50 个积压队列，30秒超时
//	router.Use(middleware.ThrottleBacklog(100, 50, 30*time.Second))
func Throttle(limit int) gin.HandlerFunc {
	return ThrottleWithOpts(ThrottleOpts{
		Limit:          limit,
		BacklogTimeout: defaultBacklogTimeout,
	})
}

// ThrottleBacklog 带积压队列的并发限流中间件
//
// 参数:
//   - limit: 同时处理的请求数上限
//   - backlogLimit: 等待队列的最大长度
//   - backlogTimeout: 等待队列中的最大等待时间
//
// 工作流程:
//  1. 请求到达时先尝试获取处理令牌
//  2. 如果无法立即获取，进入等待队列
//  3. 等待队列满或超时则返回 429 错误
//
// 使用示例:
//
//	// 同时处理 100 个请求，最多 50 个请求排队等待，超时 30 秒
//	router.Use(middleware.ThrottleBacklog(100, 50, 30*time.Second))
func ThrottleBacklog(limit, backlogLimit int, backlogTimeout time.Duration) gin.HandlerFunc {
	return ThrottleWithOpts(ThrottleOpts{
		Limit:          limit,
		BacklogLimit:   backlogLimit,
		BacklogTimeout: backlogTimeout,
	})
}

// ThrottleWithOpts 自定义选项的并发限流中间件
//
// 使用示例:
//
//	router.Use(middleware.ThrottleWithOpts(middleware.ThrottleOpts{
//	    Limit:          100,
//	    BacklogLimit:   50,
//	    BacklogTimeout: 30 * time.Second,
//	    StatusCode:     503,
//	    RetryAfterFn: func(ctxDone bool) time.Duration {
//	        if ctxDone {
//	            return 0
//	        }
//	        return 60 * time.Second
//	    },
//	}))
func ThrottleWithOpts(opts ThrottleOpts) gin.HandlerFunc {
	if opts.Limit < 1 {
		panic("gin/middleware: Throttle expects limit > 0")
	}

	if opts.BacklogLimit < 0 {
		panic("gin/middleware: Throttle expects backlogLimit to be positive")
	}

	statusCode := opts.StatusCode
	if statusCode == 0 {
		statusCode = 429 // StatusTooManyRequests
	}

	t := throttler{
		tokens:         make(chan token, opts.Limit),
		backlogTokens:  make(chan token, opts.Limit+opts.BacklogLimit),
		backlogTimeout: opts.BacklogTimeout,
		statusCode:     statusCode,
		retryAfterFn:   opts.RetryAfterFn,
	}

	// 填充令牌
	for i := 0; i < opts.Limit+opts.BacklogLimit; i++ {
		if i < opts.Limit {
			t.tokens <- token{}
		}
		t.backlogTokens <- token{}
	}

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		select {

		// Context 已取消
		case <-ctx.Done():
			t.setRetryAfterHeaderIfNeeded(c, true)
			c.String(t.statusCode, errContextCanceled)
			c.Abort()
			return

		// 获取积压令牌（进入等待队列）
		case btok := <-t.backlogTokens:
			defer func() {
				t.backlogTokens <- btok
			}()

			// 先尝试立即获取处理令牌
			select {
			case tok := <-t.tokens:
				defer func() {
					t.tokens <- tok
				}()
				c.Next()
				return
			default:
				// 没有立即可用的令牌，需要等待
			}

			// 等待处理令牌，有超时限制
			timer := time.NewTimer(t.backlogTimeout)
			defer timer.Stop()

			select {
			case <-timer.C:
				// 超时
				t.setRetryAfterHeaderIfNeeded(c, false)
				c.String(t.statusCode, errTimedOut)
				c.Abort()
				return

			case <-ctx.Done():
				// Context 取消
				t.setRetryAfterHeaderIfNeeded(c, true)
				c.String(t.statusCode, errContextCanceled)
				c.Abort()
				return

			case tok := <-t.tokens:
				// 成功获取处理令牌
				defer func() {
					t.tokens <- tok
				}()
				c.Next()
			}
			return

		// 连积压令牌都拿不到（服务器容量超限）
		default:
			t.setRetryAfterHeaderIfNeeded(c, false)
			c.String(t.statusCode, errCapacityExceeded)
			c.Abort()
			return
		}
	}
}

// token 表示正在处理的请求
type token struct{}

// throttler 限流器内部状态
type throttler struct {
	tokens         chan token                       // 处理令牌通道
	backlogTokens  chan token                       // 积压令牌通道
	retryAfterFn   func(ctxDone bool) time.Duration // Retry-After 计算函数
	backlogTimeout time.Duration                    // 积压超时时间
	statusCode     int                              // 限流时的状态码
}

// setRetryAfterHeaderIfNeeded 设置 Retry-After 响应头
func (t throttler) setRetryAfterHeaderIfNeeded(c *gin.Context, ctxDone bool) {
	if t.retryAfterFn == nil {
		return
	}
	retryAfter := t.retryAfterFn(ctxDone)
	c.Header("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
}
