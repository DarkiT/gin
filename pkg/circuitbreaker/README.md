# pkg/circuitbreaker

`pkg/circuitbreaker` 提供简单的熔断器实现，用于保护分布式系统在故障时不会级联崩溃。

## 模块用途

- 防止级联故障，保护下游服务
- 提供三态熔断机制：关闭、打开、半开
- 支持状态变更回调，便于监控和告警
- 提供统计信息，便于观察系统健康状态

## 核心概念

### 熔断器状态

| 状态 | 说明 |
|------|------|
| `StateClosed` | 关闭（正常），请求通过 |
| `StateOpen` | 打开（熔断），请求被拒绝 |
| `StateHalfOpen` | 半开（测试恢复），允许部分请求通过 |

### 状态转换

```
关闭 → (失败次数达到阈值) → 打开
打开 → (超时后) → 半开
半开 → (成功次数达到阈值) → 关闭
半开 → (再次失败) → 打开
```

## 关键类型与函数

### CircuitBreaker

```go
cb := circuitbreaker.New(
    failureThreshold,  // 失败阈值，达到后打开熔断器
    successThreshold,  // 成功阈值，达到后关闭熔断器
    timeout,           // 熔断超时时间
)
```

### 方法

| 方法 | 说明 |
|------|------|
| `Call(fn func() error) error` | 执行受保护的调用 |
| `Allow() bool` | 检查是否允许请求通过 |
| `Record(success bool)` | 记录调用结果 |
| `GetState() State` | 获取当前状态 |
| `Reset()` | 重置熔断器到初始状态 |
| `Stats() BreakerStats` | 获取统计信息 |
| `ResetStats()` | 重置统计计数器 |
| `OnStateChange(fn StateChangeCallback)` | 注册状态变更回调 |

### BreakerStats

```go
type BreakerStats struct {
    State            State         // 当前状态
    Requests         int64         // 总请求数
    TotalSuccesses   int64         // 总成功数
    TotalFailures    int64         // 总失败数
    ConsecutiveFails int64         // 连续失败数
    LastFailTime     time.Time     // 最后失败时间
    Timeout          time.Duration // 熔断超时时间
}
```

## 配置说明

### 参数配置

- `failureThreshold`：连续失败次数阈值，达到后打开熔断器（默认：5）
- `successThreshold`：半开状态下连续成功次数阈值，达到后关闭熔断器（默认：3）
- `timeout`：熔断超时时间，超时后进入半开状态（默认：60s）

### 状态变更回调

```go
cb.OnStateChange(func(from, to circuitbreaker.State) {
    log.Printf("Circuit breaker state changed: %s -> %s", from, to)
})
```

## 使用示例

### 基本用法

```go
package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/darkit/gin/pkg/circuitbreaker"
)

func main() {
	cb := circuitbreaker.New(3, 2, 5*time.Second)

	for i := 0; i < 10; i++ {
		err := cb.Call(func() error {
			// 模拟请求
			if i%3 == 0 {
				return errors.New("request failed")
			}
			return nil
		})

		stats := cb.Stats()
		fmt.Printf("Attempt %d: err=%v, state=%s, requests=%d, successes=%d, failures=%d\n",
			i, err, stats.State, stats.Requests, stats.TotalSuccesses, stats.TotalFailures)

		time.Sleep(time.Millisecond * 100)
	}
}
```

### 与 HTTP 客户端集成

```go
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/darkit/gin/pkg/circuitbreaker"
)

func main() {
	cb := circuitbreaker.New(5, 3, 30*time.Second)

	httpClient := &http.Client{Timeout: 5 * time.Second}

	request := func() error {
		resp, err := httpClient.Get("https://api.example.com/health")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("server error: %d", resp.StatusCode)
		}
		return nil
	}

	// 使用熔断器包装
	err := cb.Call(request)
	if err != nil {
		if errors.Is(err, circuitbreaker.ErrCircuitOpen) {
			fmt.Println("Circuit is open, request rejected")
		} else {
			fmt.Println("Request failed:", err)
		}
	}
}
```

### 监控告警示例

```go
cb := circuitbreaker.New(5, 3, 30*time.Second)

cb.OnStateChange(func(from, to circuitbreaker.State) {
    if to == circuitbreaker.StateOpen {
        // 发送告警通知
        sendAlert("Circuit breaker opened!")
    }
    if to == circuitbreaker.StateClosed {
        // 发送恢复通知
        sendNotification("Circuit breaker closed!")
    }
})

// 定期检查状态
go func() {
    ticker := time.NewTicker(10 * time.Second)
    for range ticker.C {
        stats := cb.Stats()
        fmt.Printf("State: %s, Requests: %d, Successes: %d, Failures: %d\n",
            stats.State, stats.Requests, stats.TotalSuccesses, stats.TotalFailures)
    }
}()
```

## 与 Engine 的集成

框架的 `middleware.CircuitBreaker()` 中间件内部使用此包：

```go
r.Use(middleware.CircuitBreaker())
```

## 错误

| 错误 | 说明 |
|------|------|
| `ErrCircuitOpen` | 熔断器打开，请求被拒绝 |
