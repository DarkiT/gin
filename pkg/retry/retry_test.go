package retry

import (
	"errors"
	"testing"
	"time"
)

// TestDo_Success 测试成功执行
func TestDo_Success(t *testing.T) {
	called := 0
	err := Do(func() error {
		called++
		return nil
	}, Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		Strategy:     StrategyFixed,
	})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if called != 1 {
		t.Errorf("expected 1 call, got %d", called)
	}
}

// TestDo_SuccessAfterRetry 测试重试后成功
func TestDo_SuccessAfterRetry(t *testing.T) {
	called := 0
	err := Do(func() error {
		called++
		if called < 2 {
			return errors.New("temporary error")
		}
		return nil
	}, Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		Strategy:     StrategyFixed,
	})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if called != 2 {
		t.Errorf("expected 2 calls, got %d", called)
	}
}

// TestDo_MaxAttemptsExceeded 测试超过最大重试次数
func TestDo_MaxAttemptsExceeded(t *testing.T) {
	called := 0
	testErr := errors.New("test error")

	err := Do(func() error {
		called++
		return testErr
	}, Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		Strategy:     StrategyFixed,
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if called != 3 {
		t.Errorf("expected 3 calls, got %d", called)
	}
}

// TestDo_OnRetryCallback 测试重试回调
func TestDo_OnRetryCallback(t *testing.T) {
	retries := 0
	testErr := errors.New("test error")

	err := Do(func() error {
		return testErr
	}, Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		Strategy:     StrategyFixed,
		OnRetry: func(attempt int, err error) {
			retries++
			if err != testErr {
				t.Errorf("expected error %v, got %v", testErr, err)
			}
		},
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	// OnRetry is called MaxAttempts-1 times (not called on the last attempt)
	if retries != 2 {
		t.Errorf("expected 2 retries, got %d", retries)
	}
}

// TestCalculateDelay_FixedStrategy 测试固定延迟策略
func TestCalculateDelay_FixedStrategy(t *testing.T) {
	config := Config{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Strategy:     StrategyFixed,
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 100 * time.Millisecond},
		{3, 100 * time.Millisecond},
	}

	for _, tt := range tests {
		delay := calculateDelay(tt.attempt, config)
		if delay != tt.expected {
			t.Errorf("attempt %d: expected %v, got %v", tt.attempt, tt.expected, delay)
		}
	}
}

// TestCalculateDelay_LinearStrategy 测试线性递增策略
func TestCalculateDelay_LinearStrategy(t *testing.T) {
	config := Config{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Strategy:     StrategyLinear,
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 300 * time.Millisecond},
	}

	for _, tt := range tests {
		delay := calculateDelay(tt.attempt, config)
		if delay != tt.expected {
			t.Errorf("attempt %d: expected %v, got %v", tt.attempt, tt.expected, delay)
		}
	}
}

// TestCalculateDelay_ExponentialStrategy 测试指数退避策略
func TestCalculateDelay_ExponentialStrategy(t *testing.T) {
	config := Config{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Strategy:     StrategyExponential,
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
	}

	for _, tt := range tests {
		delay := calculateDelay(tt.attempt, config)
		if delay != tt.expected {
			t.Errorf("attempt %d: expected %v, got %v", tt.attempt, tt.expected, delay)
		}
	}
}

// TestCalculateDelay_MaxDelay 测试最大延迟限制
func TestCalculateDelay_MaxDelay(t *testing.T) {
	config := Config{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     500 * time.Millisecond,
		Strategy:     StrategyExponential,
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 500 * time.Millisecond}, // capped at MaxDelay
		{5, 500 * time.Millisecond}, // capped at MaxDelay
	}

	for _, tt := range tests {
		delay := calculateDelay(tt.attempt, config)
		if delay != tt.expected {
			t.Errorf("attempt %d: expected %v, got %v", tt.attempt, tt.expected, delay)
		}
	}
}

// TestDo_RetryCount 测试重试次数准确性
func TestDo_RetryCount(t *testing.T) {
	called := 0

	err := Do(func() error {
		called++
		return errors.New("test error")
	}, Config{
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Second,
		Strategy:     StrategyFixed,
	})

	if err == nil {
		t.Error("expected error, got nil")
	}

	if called != 5 {
		t.Errorf("expected 5 calls, got %d", called)
	}
}
