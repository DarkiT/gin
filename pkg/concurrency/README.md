# pkg/concurrency

`pkg/concurrency` 提供并发控制工具，包括协程池和 singleflight 组。

## 目录

- [WorkerPool](#workerpool) - 协程池
- [Group](#group---singleflight) - Singleflight 组

---

## WorkerPool

### 模块用途

- 控制并发执行的 goroutine 数量
- 防止 goroutine 泄漏
- 提供任务队列管理
- 支持多种溢出策略

### 关键类型与函数

#### WorkerPool

```go
pool := concurrency.NewPool(workers int, opts ...PoolOption)
```

#### 配置选项

| 选项 | 说明 |
|------|------|
| `WithQueueSize(size int)` | 设置任务队列大小 |
| `WithOverflowPolicy(policy OverflowPolicy)` | 设置溢出策略 |
| `WithOnTaskDropped(fn func())` | 设置任务丢弃回调 |

#### 溢出策略

| 策略 | 说明 |
|------|------|
| `PolicyBlock` | 阻塞等待直到队列有空间（默认） |
| `PolicyDrop` | 丢弃任务，不执行 |
| `PolicyCallerRuns` | 由调用者线程执行任务 |

#### 方法

| 方法 | 说明 |
|------|------|
| `Submit(fn func()) bool` | 提交任务 |
| `TrySubmit(fn func()) bool` | 尝试提交任务，队列满时立即返回 false |
| `Stats() PoolStats` | 获取统计信息 |
| `Shutdown()` | 关闭池（立即停止） |
| `ShutdownGraceful()` | 优雅关闭池（等待已提交任务完成） |

#### PoolStats

```go
type PoolStats struct {
    Workers   int   // 工作协程数
    QueueSize int   // 队列容量
    Queued    int   // 当前队列中的任务数
    Submitted int64 // 已提交任务数
    Completed int64 // 已完成任务数
    Dropped   int64 // 已丢弃任务数
}
```

### 使用示例

#### 基本用法

```go
package main

import (
	"fmt"
	"time"

	"github.com/darkit/gin/pkg/concurrency"
)

func main() {
	pool := concurrency.NewPool(5, concurrency.WithQueueSize(10))
	defer pool.Shutdown()

	for i := 0; i < 20; i++ {
		taskID := i
		ok := pool.Submit(func() {
			fmt.Printf("Task %d started\n", taskID)
			time.Sleep(100 * time.Millisecond)
			fmt.Printf("Task %d completed\n", taskID)
		})
		if !ok {
			fmt.Printf("Task %d rejected\n", taskID)
		}
	}

	// 等待所有任务完成
	pool.ShutdownGraceful()
	fmt.Println("All tasks completed")
}
```

#### 带溢出的优雅关闭

```go
pool := concurrency.NewPool(
    10,
    concurrency.WithQueueSize(100),
    concurrency.WithOverflowPolicy(concurrency.PolicyCallerRuns),
    concurrency.WithOnTaskDropped(func() {
        metrics.Inc("task_dropped")
    }),
)

// 优雅关闭：等待已提交任务完成
pool.ShutdownGraceful()
```

---

## Group - Singleflight

### 模块用途

- 防止缓存击穿
- 合并相同 key 的并发请求
- 确保同一 key 的请求只执行一次

### 关键类型与函数

#### Group

```go
var g concurrency.Group
```

#### 方法

| 方法 | 说明 |
|------|------|
| `Do(key string, fn func() (interface{}, error)) (interface{}, error)` | 执行函数，同一 key 只执行一次 |

### 使用示例

#### 基本用法

```go
package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/darkit/gin/pkg/concurrency"
)

func main() {
	var g concurrency.Group

	// 模拟多个并发请求相同资源
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			start := time.Now()
			val, err := g.Do("user:1001", func() (interface{}, error) {
				// 模拟数据库查询
				time.Sleep(100 * time.Millisecond)
				return map[string]string{"id": "1001", "name": "Alice"}, nil
			})
			fmt.Printf("Goroutine %d: val=%v, err=%v, duration=%v\n",
				id, val, err, time.Since(start))
		}(i)
	}

	wg.Wait()
}
```

#### 防止缓存击穿

```go
var g concurrency.Group

func GetUser(userID string) (*User, error) {
	return g.Do("user:"+userID, func() (interface{}, error) {
		// 只有第一个请求会执行数据库查询
		// 其他请求等待第一个请求完成后获得相同结果
		return db.Users.Find(userID)
	}).(*User, nil)
}
```

---

## 最佳实践

1. **WorkerPool 大小选择**：
   - CPU 密集型任务：设置为 `runtime.NumCPU()`
   - IO 密集型任务：可以设置为 `runtime.NumCPU() * 2` 或更高

2. **队列大小设置**：
   - 队列大小通常设置为 worker 数的 2-4 倍
   - 考虑内存使用和最大并发数

3. **Singleflight 场景**：
   - 适用于数据库查询、API 调用等昂贵操作
   - 不适用于需要个性化处理的场景

4. **优雅关闭**：
   - 使用 `ShutdownGraceful()` 确保任务完成
   - 注意设置合理的超时避免永久阻塞

## 与 Engine 的集成

协程池可用于：

- 后台任务处理
- 批量操作
- 并发爬虫
- 定时任务执行
