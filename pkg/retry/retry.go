// Package retry 提供简单的重试机制。
package retry

import (
	"fmt"
	"time"
)

// Strategy 重试策略
type Strategy int

const (
	StrategyFixed       Strategy = iota // 固定延迟
	StrategyLinear                      // 线性递增
	StrategyExponential                 // 指数退避
)

// Config 重试配置
type Config struct {
	MaxAttempts  int                          // 最大重试次数
	InitialDelay time.Duration                // 初始延迟
	MaxDelay     time.Duration                // 最大延迟
	Strategy     Strategy                     // 重试策略
	OnRetry      func(attempt int, err error) // 重试回调
}

// Do 执行带重试的函数
func Do(fn func() error, config Config) error {
	var err error
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}

		if attempt < config.MaxAttempts {
			delay := calculateDelay(attempt, config)
			if config.OnRetry != nil {
				config.OnRetry(attempt, err)
			}
			time.Sleep(delay)
		}
	}
	return fmt.Errorf("重试 %d 次后仍失败: %w", config.MaxAttempts, err)
}

// calculateDelay 计算延迟时间
func calculateDelay(attempt int, config Config) time.Duration {
	var delay time.Duration
	switch config.Strategy {
	case StrategyFixed:
		delay = config.InitialDelay
	case StrategyLinear:
		delay = time.Duration(attempt) * config.InitialDelay
	case StrategyExponential:
		delay = config.InitialDelay * time.Duration(1<<uint(attempt-1))
	}

	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}
	return delay
}
