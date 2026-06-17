package concurrency

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewPool 测试创建协程池
func TestNewPool(t *testing.T) {
	pool := NewPool(5)
	if pool == nil {
		t.Fatal("NewPool returned nil")
	}
	pool.Shutdown()
}

// TestWorkerPool_Submit 测试提交任务
func TestWorkerPool_Submit(t *testing.T) {
	pool := NewPool(3)
	defer pool.Shutdown()

	var counter int32
	var wg sync.WaitGroup

	const tasks = 10
	wg.Add(tasks)

	for range tasks {
		pool.Submit(func() {
			atomic.AddInt32(&counter, 1)
			wg.Done()
		})
	}

	wg.Wait()

	if counter != tasks {
		t.Errorf("expected %d tasks executed, got %d", tasks, counter)
	}
}

// TestWorkerPool_Shutdown 测试关闭
func TestWorkerPool_Shutdown(t *testing.T) {
	pool := NewPool(3)

	var counter int32
	var wg sync.WaitGroup
	wg.Add(5)

	for range 5 {
		pool.Submit(func() {
			atomic.AddInt32(&counter, 1)
			wg.Done()
		})
	}

	wg.Wait()
	pool.Shutdown()

	// 关闭后提交应该被忽略
	pool.Submit(func() {
		atomic.AddInt32(&counter, 1)
	})

	time.Sleep(50 * time.Millisecond)

	if counter != 5 {
		t.Errorf("expected 5 tasks, got %d", counter)
	}
}

// TestWorkerPool_Concurrent 测试并发提交
func TestWorkerPool_Concurrent(t *testing.T) {
	pool := NewPool(10)
	defer pool.Shutdown()

	const goroutines = 20
	const tasksPerGoroutine = 50

	var counter int32
	var wg sync.WaitGroup
	wg.Add(goroutines * tasksPerGoroutine)

	for range goroutines {
		go func() {
			for range tasksPerGoroutine {
				pool.Submit(func() {
					atomic.AddInt32(&counter, 1)
					wg.Done()
				})
			}
		}()
	}

	wg.Wait()

	expected := int32(goroutines * tasksPerGoroutine)
	if counter != expected {
		t.Errorf("expected %d tasks, got %d", expected, counter)
	}
}

// TestWorkerPool_ShutdownWait 测试 Shutdown 等待所有任务完成
func TestWorkerPool_ShutdownWait(t *testing.T) {
	pool := NewPool(2)

	var completed int32
	var wg sync.WaitGroup
	wg.Add(3)

	for range 3 {
		pool.Submit(func() {
			time.Sleep(50 * time.Millisecond)
			atomic.AddInt32(&completed, 1)
			wg.Done()
		})
	}

	wg.Wait()
	pool.Shutdown()

	if completed != 3 {
		t.Errorf("expected 3 completed tasks, got %d", completed)
	}
}
