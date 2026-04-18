package circuitbreaker

import (
	"errors"
	"testing"
	"time"
)

// TestNew 测试创建熔断器
func TestNew(t *testing.T) {
	cb := New(3, 2, time.Second)
	if cb == nil {
		t.Fatal("New returned nil")
	}
	if cb.GetState() != StateClosed {
		t.Errorf("expected state %v, got %v", StateClosed, cb.GetState())
	}
}

// TestCircuitBreaker_Call_Success 测试成功调用
func TestCircuitBreaker_Call_Success(t *testing.T) {
	cb := New(3, 2, time.Second)

	err := cb.Call(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if cb.GetState() != StateClosed {
		t.Errorf("expected state %v, got %v", StateClosed, cb.GetState())
	}
}

// TestCircuitBreaker_Call_Failure 测试失败调用
func TestCircuitBreaker_Call_Failure(t *testing.T) {
	cb := New(3, 2, time.Second)
	testErr := errors.New("test error")

	// 第一次失败
	err := cb.Call(func() error {
		return testErr
	})

	if err != testErr {
		t.Errorf("expected error %v, got %v", testErr, err)
	}
	if cb.GetState() != StateClosed {
		t.Errorf("expected state %v after 1 failure, got %v", StateClosed, cb.GetState())
	}
}

// TestCircuitBreaker_OpenCircuit 测试熔断器打开
func TestCircuitBreaker_OpenCircuit(t *testing.T) {
	cb := New(3, 2, time.Second)
	testErr := errors.New("test error")

	// 连续失败 3 次
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return testErr
		})
		if err != testErr {
			t.Fatalf("expected error %v, got %v", testErr, err)
		}
	}

	if cb.GetState() != StateOpen {
		t.Errorf("expected state %v, got %v", StateOpen, cb.GetState())
	}

	// 熔断器打开后，请求应该被拒绝
	err := cb.Call(func() error {
		return nil
	})

	if err != ErrCircuitOpen {
		t.Errorf("expected error %v, got %v", ErrCircuitOpen, err)
	}
}

// TestCircuitBreaker_HalfOpen 测试半开状态
func TestCircuitBreaker_HalfOpen(t *testing.T) {
	cb := New(3, 2, 100*time.Millisecond)
	testErr := errors.New("test error")

	// 触发熔断
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return testErr
		})
		if err != testErr {
			t.Fatalf("expected error %v, got %v", testErr, err)
		}
	}

	if cb.GetState() != StateOpen {
		t.Errorf("expected state %v, got %v", StateOpen, cb.GetState())
	}

	// 等待超时
	time.Sleep(150 * time.Millisecond)

	// 第一个请求应该被允许（进入半开状态）
	if !cb.Allow() {
		t.Error("expected request to be allowed after timeout")
	}

	if cb.GetState() != StateHalfOpen {
		t.Errorf("expected state %v, got %v", StateHalfOpen, cb.GetState())
	}
}

// TestCircuitBreaker_Recovery 测试恢复
func TestCircuitBreaker_Recovery(t *testing.T) {
	cb := New(3, 2, 100*time.Millisecond)
	testErr := errors.New("test error")

	// 触发熔断
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return testErr
		})
		if err != testErr {
			t.Fatalf("expected error %v, got %v", testErr, err)
		}
	}

	// 等待超时进入半开状态
	time.Sleep(150 * time.Millisecond)

	// 连续成功 2 次
	for i := 0; i < 2; i++ {
		err := cb.Call(func() error {
			return nil
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}

	// 应该恢复到关闭状态
	if cb.GetState() != StateClosed {
		t.Errorf("expected state %v, got %v", StateClosed, cb.GetState())
	}
}

// TestCircuitBreaker_HalfOpenToOpen 测试半开状态失败回到打开状态
func TestCircuitBreaker_HalfOpenToOpen(t *testing.T) {
	cb := New(3, 2, 100*time.Millisecond)
	testErr := errors.New("test error")

	// 触发熔断
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return testErr
		})
		if err != testErr {
			t.Fatalf("expected error %v, got %v", testErr, err)
		}
	}

	// 等待超时进入半开状态
	time.Sleep(150 * time.Millisecond)

	// 第一个请求失败
	err := cb.Call(func() error {
		return testErr
	})
	if err != testErr {
		t.Fatalf("expected error %v, got %v", testErr, err)
	}

	// 应该回到打开状态
	if cb.GetState() != StateOpen {
		t.Errorf("expected state %v, got %v", StateOpen, cb.GetState())
	}
}

// TestCircuitBreaker_Reset 测试重置
func TestCircuitBreaker_Reset(t *testing.T) {
	cb := New(3, 2, time.Second)
	testErr := errors.New("test error")

	// 触发熔断
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return testErr
		})
		if err != testErr {
			t.Fatalf("expected error %v, got %v", testErr, err)
		}
	}

	if cb.GetState() != StateOpen {
		t.Errorf("expected state %v, got %v", StateOpen, cb.GetState())
	}

	// 重置
	cb.Reset()

	if cb.GetState() != StateClosed {
		t.Errorf("expected state %v after reset, got %v", StateClosed, cb.GetState())
	}
}

// TestState_String 测试状态字符串
func TestState_String(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("State.String() = %v, want %v", got, tt.expected)
		}
	}
}

// TestCircuitBreaker_Concurrent 测试并发
func TestCircuitBreaker_Concurrent(t *testing.T) {
	cb := New(10, 2, time.Second)

	const goroutines = 100
	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			if err := cb.Call(func() error {
				time.Sleep(time.Millisecond)
				return nil
			}); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			done <- true
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	if cb.GetState() != StateClosed {
		t.Errorf("expected state %v, got %v", StateClosed, cb.GetState())
	}
}
