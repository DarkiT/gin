// Package concurrency 提供并发控制工具。
package concurrency

import (
	"context"
	"sync"
	"sync/atomic"
)

// OverflowPolicy 定义任务队列溢出时的处理策略。
type OverflowPolicy int

const (
	// PolicyBlock 阻塞等待直到队列有空间（默认）。
	PolicyBlock OverflowPolicy = iota
	// PolicyDrop 丢弃任务，不执行。
	PolicyDrop
	// PolicyCallerRuns 由调用者线程执行任务。
	PolicyCallerRuns
)

// PoolOption 定义协程池配置选项。
type PoolOption func(*poolOptions)

type poolOptions struct {
	queueSize      int
	overflowPolicy OverflowPolicy
	onTaskDropped  func()
}

func defaultPoolOptions(workers int) *poolOptions {
	return &poolOptions{
		queueSize:      workers * 2,
		overflowPolicy: PolicyBlock,
	}
}

// WithQueueSize 设置任务队列大小。
func WithQueueSize(size int) PoolOption {
	return func(o *poolOptions) {
		if size > 0 {
			o.queueSize = size
		}
	}
}

// WithOverflowPolicy 设置队列溢出策略。
func WithOverflowPolicy(policy OverflowPolicy) PoolOption {
	return func(o *poolOptions) {
		o.overflowPolicy = policy
	}
}

// WithOnTaskDropped 设置任务被丢弃时的回调（仅 PolicyDrop 策略有效）。
func WithOnTaskDropped(fn func()) PoolOption {
	return func(o *poolOptions) {
		o.onTaskDropped = fn
	}
}

// WorkerPool 协程池
type WorkerPool struct {
	workers        int
	tasks          chan func()
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	overflowPolicy OverflowPolicy
	onTaskDropped  func()

	// 统计信息
	submitted int64
	completed int64
	dropped   int64
}

// PoolStats 协程池统计信息。
type PoolStats struct {
	Workers   int   // 工作协程数
	QueueSize int   // 队列容量
	Queued    int   // 当前队列中的任务数
	Submitted int64 // 已提交任务数
	Completed int64 // 已完成任务数
	Dropped   int64 // 已丢弃任务数
}

// NewPool 创建协程池
func NewPool(workers int, opts ...PoolOption) *WorkerPool {
	options := defaultPoolOptions(workers)
	for _, opt := range opts {
		opt(options)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := &WorkerPool{
		workers:        workers,
		tasks:          make(chan func(), options.queueSize),
		ctx:            ctx,
		cancel:         cancel,
		overflowPolicy: options.overflowPolicy,
		onTaskDropped:  options.onTaskDropped,
	}

	for i := 0; i < workers; i++ {
		pool.wg.Add(1)
		go pool.worker()
	}

	return pool
}

func (p *WorkerPool) worker() {
	defer p.wg.Done()
	for {
		select {
		case task, ok := <-p.tasks:
			if !ok {
				return
			}
			if task != nil {
				task()
				atomic.AddInt64(&p.completed, 1)
			}
		case <-p.ctx.Done():
			return
		}
	}
}

// Submit 提交任务
func (p *WorkerPool) Submit(fn func()) bool {
	if fn == nil {
		return false
	}

	atomic.AddInt64(&p.submitted, 1)

	switch p.overflowPolicy {
	case PolicyBlock:
		select {
		case p.tasks <- fn:
			return true
		case <-p.ctx.Done():
			return false
		}

	case PolicyDrop:
		select {
		case p.tasks <- fn:
			return true
		default:
			atomic.AddInt64(&p.dropped, 1)
			if p.onTaskDropped != nil {
				p.onTaskDropped()
			}
			return false
		}

	case PolicyCallerRuns:
		select {
		case p.tasks <- fn:
			return true
		default:
			// 由调用者执行
			fn()
			atomic.AddInt64(&p.completed, 1)
			return true
		}
	}

	return false
}

// TrySubmit 尝试提交任务，队列满时立即返回 false（不阻塞）。
func (p *WorkerPool) TrySubmit(fn func()) bool {
	if fn == nil {
		return false
	}

	select {
	case p.tasks <- fn:
		atomic.AddInt64(&p.submitted, 1)
		return true
	default:
		return false
	}
}

// Stats 返回协程池统计信息。
func (p *WorkerPool) Stats() PoolStats {
	return PoolStats{
		Workers:   p.workers,
		QueueSize: cap(p.tasks),
		Queued:    len(p.tasks),
		Submitted: atomic.LoadInt64(&p.submitted),
		Completed: atomic.LoadInt64(&p.completed),
		Dropped:   atomic.LoadInt64(&p.dropped),
	}
}

// Shutdown 关闭池
func (p *WorkerPool) Shutdown() {
	p.cancel()
	p.wg.Wait()
}

// ShutdownGraceful 优雅关闭池，等待所有已提交任务完成。
func (p *WorkerPool) ShutdownGraceful() {
	close(p.tasks)
	p.wg.Wait()
}
