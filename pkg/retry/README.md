# pkg/retry

`pkg/retry` 提供简单的重试机制，支持多种重试策略。

## 模块用途

- 自动重试失败的操作用
- 支持多种退避策略
- 可配置的最大重试次数
- 提供重试回调便于监控

## 重试策略

| 策略 | 说明 |
|------|------|
| `StrategyFixed` | 固定延迟，每次重试间隔相同 |
| `StrategyLinear` | 线性递增延迟，每次重试延迟增加 |
| `StrategyExponential` | 指数退避延迟，每次重试延迟翻倍 |

## 关键类型与函数

### Config

```go
type Config struct {
    MaxAttempts  int             // 最大重试次数
    InitialDelay time.Duration   // 初始延迟
    MaxDelay     time.Duration   // 最大延迟
    Strategy     Strategy        // 重试策略
    OnRetry      func(attempt int, err error) // 重试回调
}
```

### Do

```go
err := retry.Do(fn func() error, config Config) error
```

## 配置说明

### 参数说明

- `MaxAttempts`：最大重试次数，包括第一次尝试
- `InitialDelay`：第一次重试前的延迟时间
- `MaxDelay`：最大延迟上限，避免延迟过长
- `Strategy`：重试策略
- `OnRetry`：每次重试前调用的回调函数

### 延迟计算

| 策略 | 第 N 次重试延迟 |
|------|----------------|
| `StrategyFixed` | InitialDelay |
| `StrategyLinear` | N × InitialDelay |
| `StrategyExponential` | 2^(N-1) × InitialDelay |

## 使用示例

### 固定延迟重试

```go
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/darkit/gin/pkg/retry"
)

func main() {
	err := retry.Do(
		func() error {
			resp, err := http.Get("https://api.example.com/health")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status: %d", resp.StatusCode)
			}
			return nil
		},
		retry.Config{
			MaxAttempts:  3,
			InitialDelay: 100 * time.Millisecond,
			MaxDelay:     time.Second,
			Strategy:     retry.StrategyFixed,
		},
	)

	if err != nil {
		fmt.Println("All retries failed:", err)
	} else {
		fmt.Println("Request succeeded")
	}
}
```

### 指数退避重试

```go
err := retry.Do(
    fn,
    retry.Config{
        MaxAttempts:  5,
        InitialDelay: 100 * time.Millisecond,
        MaxDelay:     30 * time.Second,
        Strategy:     retry.StrategyExponential,
    },
)
```

### 带监控回调

```go
err := retry.Do(
    fn,
    retry.Config{
        MaxAttempts:  3,
        InitialDelay: 200 * time.Millisecond,
        Strategy:     retry.StrategyExponential,
        OnRetry: func(attempt int, err error) {
            fmt.Printf("Retry %d: %v\n", attempt, err)
            metrics.Inc("retry_attempt")
        },
    },
)
```

### 与数据库操作结合

```go
func fetchUser(userID string) (*User, error) {
    var user *User
    err := retry.Do(
        func() error {
            return db.Where("id = ?", userID).First(&user).Error
        },
        retry.Config{
            MaxAttempts:  3,
            InitialDelay: 50 * time.Millisecond,
            Strategy:     retry.StrategyLinear,
        },
    )
    return user, err
}
```

### 与 HTTP 客户端结合

```go
func callAPIWithRetry(url string) ([]byte, error) {
    var result []byte
    err := retry.Do(
        func() error {
            resp, err := httpClient.Get(url)
            if err != nil {
                return err
            }
            defer resp.Body.Close()

            if resp.StatusCode >= 500 {
                return fmt.Errorf("server error: %d", resp.StatusCode)
            }

            if resp.StatusCode == 429 { // Too Many Requests
                return ErrRateLimited
            }

            result, err = io.ReadAll(resp.Body)
            return err
        },
        retry.Config{
            MaxAttempts:  5,
            InitialDelay: time.Second,
            MaxDelay:     60 * time.Second,
            Strategy:     retry.StrategyExponential,
        },
    )
    return result, err
}
```

## 最佳实践

1. **最大重试次数**：
   - 网络相关操作：3-5 次
   - 数据库操作：2-3 次
   - 外部 API：根据服务 SLA 调整

2. **初始延迟**：
   - 快速失败场景：100ms-500ms
   - 需要等待服务恢复：1s-5s

3. **最大延迟**：
   - 不要设置过长，建议不超过 60s
   - 考虑用户等待时间

4. **策略选择**：
   - `StrategyFixed`：适用于偶发性失败
   - `StrategyLinear`：适用于负载均衡场景
   - `StrategyExponential`：适用于服务暂时不可用场景

5. **幂等性**：
   - 确保重试操作是幂等的
   - 避免非幂等操作在重试时产生副作用

## 注意事项

1. **非幂等操作**：重试可能产生副作用，如重复下单
2. **超时控制**：重试机制不替代调用方的超时设置
3. **最大延迟**：务必设置 MaxDelay 避免无限等待
4. **错误类型**：区分可重试和不可重试的错误
