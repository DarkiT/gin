// Package circuitbreaker 提供简单的熔断器实现。
package circuitbreaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCircuitOpen 熔断器打开错误
var ErrCircuitOpen = errors.New("circuit breaker is open")

// State 熔断器状态
type State int

const (
	StateClosed   State = iota // 关闭（正常）
	StateOpen                  // 打开（熔断）
	StateHalfOpen              // 半开（测试恢复）
)

// String 返回状态名称
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// BreakerStats 熔断器统计信息。
type BreakerStats struct {
	State            State         // 当前状态
	Requests         int64         // 总请求数
	TotalSuccesses   int64         // 总成功数
	TotalFailures    int64         // 总失败数
	ConsecutiveFails int64         // 连续失败数
	LastFailTime     time.Time     // 最后失败时间
	Timeout          time.Duration // 熔断超时时间
}

// StateChangeCallback 状态变更回调函数类型。
type StateChangeCallback func(from, to State)

// CircuitBreaker 熔断器
type CircuitBreaker struct {
	mu               sync.RWMutex
	state            State
	failureCount     int
	successCount     int
	failureThreshold int           // 失败阈值
	successThreshold int           // 成功恢复阈值
	timeout          time.Duration // 熔断超时
	lastFailTime     time.Time

	// 统计信息（使用原子操作）
	totalRequests  int64
	totalSuccesses int64
	totalFailures  int64

	// 状态变更回调
	onStateChange StateChangeCallback
}

// New 创建熔断器
func New(failureThreshold, successThreshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            StateClosed,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		timeout:          timeout,
	}
}

// Call 执行受保护的调用
func (cb *CircuitBreaker) Call(fn func() error) error {
	if !cb.Allow() {
		return ErrCircuitOpen
	}

	err := fn()
	cb.Record(err == nil)
	return err
}

// Allow 是否允许请求通过
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// 统计请求数
	atomic.AddInt64(&cb.totalRequests, 1)

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// 检查是否超时，可以进入半开状态
		if time.Since(cb.lastFailTime) > cb.timeout {
			oldState := cb.state
			cb.state = StateHalfOpen
			cb.successCount = 0
			cb.notifyStateChange(oldState, StateHalfOpen)
			return true
		}
		return false
	case StateHalfOpen:
		return true
	}
	return false
}

// Record 记录调用结果
func (cb *CircuitBreaker) Record(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if success {
		atomic.AddInt64(&cb.totalSuccesses, 1)
		cb.failureCount = 0
		cb.successCount++

		if cb.state == StateHalfOpen && cb.successCount >= cb.successThreshold {
			oldState := cb.state
			cb.state = StateClosed
			cb.successCount = 0
			cb.notifyStateChange(oldState, StateClosed)
		}
	} else {
		atomic.AddInt64(&cb.totalFailures, 1)
		cb.successCount = 0
		cb.failureCount++
		cb.lastFailTime = time.Now()

		if cb.failureCount >= cb.failureThreshold {
			oldState := cb.state
			cb.state = StateOpen
			cb.notifyStateChange(oldState, StateOpen)
		}
	}
}

// GetState 获取当前状态
func (cb *CircuitBreaker) GetState() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset 重置熔断器到初始状态
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failureCount = 0
	cb.successCount = 0
}

// Stats 返回熔断器统计信息。
func (cb *CircuitBreaker) Stats() BreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return BreakerStats{
		State:            cb.state,
		Requests:         atomic.LoadInt64(&cb.totalRequests),
		TotalSuccesses:   atomic.LoadInt64(&cb.totalSuccesses),
		TotalFailures:    atomic.LoadInt64(&cb.totalFailures),
		ConsecutiveFails: int64(cb.failureCount),
		LastFailTime:     cb.lastFailTime,
		Timeout:          cb.timeout,
	}
}

// ResetStats 重置统计计数器（不影响熔断器状态）。
func (cb *CircuitBreaker) ResetStats() {
	atomic.StoreInt64(&cb.totalRequests, 0)
	atomic.StoreInt64(&cb.totalSuccesses, 0)
	atomic.StoreInt64(&cb.totalFailures, 0)
}

// OnStateChange 注册状态变更回调函数。
// 回调函数在状态变更时同步调用，应避免阻塞操作。
func (cb *CircuitBreaker) OnStateChange(fn StateChangeCallback) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = fn
}

// notifyStateChange 触发状态变更回调（内部方法，调用时已持有锁）。
func (cb *CircuitBreaker) notifyStateChange(from, to State) {
	if cb.onStateChange != nil && from != to {
		cb.onStateChange(from, to)
	}
}
