package concurrency

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGroup_Do_SingleExecution 测试单次执行
func TestGroup_Do_SingleExecution(t *testing.T) {
	var g Group
	var calls int32

	fn := func() (any, error) {
		atomic.AddInt32(&calls, 1)
		return "result", nil
	}

	result, err := g.Do("key1", fn)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "result" {
		t.Errorf("expected result, got %v", result)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

// TestGroup_Do_Concurrent 测试并发调用
func TestGroup_Do_Concurrent(t *testing.T) {
	var g Group
	var calls int32

	fn := func() (any, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(50 * time.Millisecond)
		return "result", nil
	}

	const goroutines = 10
	results := make(chan any, goroutines)
	errors := make(chan error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			result, err := g.Do("key1", fn)
			results <- result
			errors <- err
		}()
	}

	wg.Wait()
	close(results)
	close(errors)

	// 验证只调用了一次
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}

	// 验证所有 goroutine 都得到了相同的结果
	for result := range results {
		if result != "result" {
			t.Errorf("expected result, got %v", result)
		}
	}

	for err := range errors {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

// TestGroup_Do_DifferentKeys 测试不同键
func TestGroup_Do_DifferentKeys(t *testing.T) {
	var g Group
	var calls int32

	fn := func() (any, error) {
		atomic.AddInt32(&calls, 1)
		return "result", nil
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if _, err := g.Do("key1", fn); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := g.Do("key2", fn); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := g.Do("key3", fn); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	wg.Wait()

	// 不同键应该分别执行
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

// TestGroup_Do_Error 测试错误处理
func TestGroup_Do_Error(t *testing.T) {
	var g Group
	var calls int32
	testErr := errors.New("test error")

	fn := func() (any, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(20 * time.Millisecond) // 确保并发
		return nil, testErr
	}

	const goroutines = 5
	errors := make(chan error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			_, err := g.Do("key1", fn)
			errors <- err
		}()
	}

	wg.Wait()
	close(errors)

	// 验证只调用了一次
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}

	// 验证所有 goroutine 都得到了相同的错误
	for err := range errors {
		if err != testErr {
			t.Errorf("expected test error, got %v", err)
		}
	}
}

// TestGroup_Do_Sequential 测试顺序调用（不会缓存）
func TestGroup_Do_Sequential(t *testing.T) {
	var g Group
	var calls int32

	fn := func() (any, error) {
		count := atomic.AddInt32(&calls, 1)
		return count, nil
	}

	// 第一次调用
	result1, err := g.Do("key1", fn)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result1 != int32(1) {
		t.Errorf("expected 1, got %v", result1)
	}

	// 第二次调用（应该再次执行，因为不缓存结果）
	result2, err := g.Do("key1", fn)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result2 != int32(2) {
		t.Errorf("expected 2, got %v", result2)
	}

	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

// TestGroup_Do_MixedKeysAndConcurrency 测试混合键和并发
func TestGroup_Do_MixedKeysAndConcurrency(t *testing.T) {
	var g Group
	var mu sync.Mutex
	callCounts := make(map[string]int)

	fn := func(key string) func() (any, error) {
		return func() (any, error) {
			mu.Lock()
			callCounts[key]++
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			return key, nil
		}
	}

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// 10 个 goroutine 访问 key1，10 个访问 key2，10 个访问 key3
	for i := range goroutines {
		key := ""
		if i < 10 {
			key = "key1"
		} else if i < 20 {
			key = "key2"
		} else {
			key = "key3"
		}

		go func(k string) {
			defer wg.Done()
			if _, err := g.Do(k, fn(k)); err != nil {
				t.Errorf("unexpected error for %s: %v", k, err)
			}
		}(key)
	}

	wg.Wait()

	// 每个键应该只被调用一次
	for key, count := range callCounts {
		if count != 1 {
			t.Errorf("key %s: expected 1 call, got %d", key, count)
		}
	}
}
