// @Author daixk 2025-10-28 22:00:20
package pool

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 默认配置常量。
const (
	DefaultMinSize       = 100              // 最小协程数
	DefaultMaxSize       = 2000             // 最大协程数
	DefaultScaleUpRate   = 0.8              // 扩容阈值
	DefaultScaleDownRate = 0.3              // 缩容阈值
	DefaultCheckInterval = time.Minute      // 自动扩缩容检查间隔
	DefaultExpiry        = 10 * time.Second // 空闲 worker 过期时间
)

// RenewPoolConfig 定义续期任务协程池配置。
type RenewPoolConfig struct {
	MinSize             int           // 最小协程数
	MaxSize             int           // 最大协程数
	ScaleUpRate         float64       // 扩容阈值
	ScaleDownRate       float64       // 缩容阈值
	CheckInterval       time.Duration // 自动扩缩容检查间隔
	Expiry              time.Duration // 空闲 worker 过期时间
	PrintStatusInterval time.Duration // 定时打印池状态的间隔（0 表示关闭）
	PreAlloc            bool          // 为兼容旧配置保留，轻量实现中无实际效果
	NonBlocking         bool          // 是否启用非阻塞提交
}

// DefaultRenewPoolConfig 返回默认续期池配置。
func DefaultRenewPoolConfig() *RenewPoolConfig {
	return &RenewPoolConfig{
		MinSize:       DefaultMinSize,
		MaxSize:       DefaultMaxSize,
		ScaleUpRate:   DefaultScaleUpRate,
		ScaleDownRate: DefaultScaleDownRate,
		CheckInterval: DefaultCheckInterval,
		Expiry:        DefaultExpiry,
		PreAlloc:      false,
		NonBlocking:   true,
	}
}

// RenewPoolManager 管理 Token 续期任务的轻量协程池。
type RenewPoolManager struct {
	config *RenewPoolConfig // 池配置对象

	mu       sync.RWMutex // 保护 started 等状态
	stopOnce sync.Once    // 确保 Stop 只执行一次
	stopCh   chan struct{}
	taskCh   chan func()
	wg       sync.WaitGroup
	started  bool

	running  int32 // 当前执行中的任务数
	capacity int32 // 当前目标容量
	workers  int32 // 当前已启动的 worker 数
	idle     int32 // 当前空闲的 worker 数
}

// NewRenewPoolManagerWithConfig 使用配置创建续期池管理器。
func NewRenewPoolManagerWithConfig(cfg *RenewPoolConfig) (*RenewPoolManager, error) {
	cfg = normalizeConfig(cfg)

	mgr := &RenewPoolManager{
		config:   cfg,
		stopCh:   make(chan struct{}),
		taskCh:   make(chan func()),
		started:  true,
		capacity: int32(cfg.MinSize),
	}

	mgr.spawnWorkers(cfg.MinSize, true)

	mgr.wg.Add(1)
	go mgr.autoScale()

	if cfg.PrintStatusInterval > 0 {
		mgr.wg.Add(1)
		go mgr.printStatusLoop()
	}

	return mgr, nil
}

// Submit 提交一个续期任务。
func (m *RenewPoolManager) Submit(task func()) error {
	if task == nil {
		return fmt.Errorf("renew task is nil")
	}
	if !m.isStarted() {
		return fmt.Errorf("RenewPool not started")
	}

	if m.config.NonBlocking {
		if atomic.LoadInt32(&m.idle) <= 0 {
			return fmt.Errorf("RenewPool is full")
		}
		select {
		case <-m.stopCh:
			return fmt.Errorf("RenewPool not started")
		case m.taskCh <- task:
			return nil
		default:
			return fmt.Errorf("RenewPool is full")
		}
	}

	select {
	case <-m.stopCh:
		return fmt.Errorf("RenewPool not started")
	case m.taskCh <- task:
		return nil
	}
}

// Stop 停止续期池并尽量等待运行中的任务结束。
func (m *RenewPoolManager) Stop() {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		m.started = false
		close(m.stopCh)
		m.mu.Unlock()

		done := make(chan struct{})
		go func() {
			m.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
}

// Stats 返回当前池状态。
func (m *RenewPoolManager) Stats() (running, capacity int, usage float64) {
	running = int(atomic.LoadInt32(&m.running))
	capacity = int(atomic.LoadInt32(&m.capacity))
	if capacity > 0 {
		usage = float64(running) / float64(capacity)
	}
	return
}

// PrintStatus 打印当前协程池状态。
func (m *RenewPoolManager) PrintStatus() {
	r, c, u := m.Stats()
	fmt.Printf("RenewPool Running: %d, Capacity: %d, Usage: %.1f%%\n", r, c, u*100)
}

// RenewPoolBuilder 用于流式构建 RenewPoolManager。
type RenewPoolBuilder struct {
	cfg *RenewPoolConfig // 构造器配置对象
}

// NewRenewPoolBuilder 创建续期池构造器。
func NewRenewPoolBuilder() *RenewPoolBuilder {
	return &RenewPoolBuilder{cfg: DefaultRenewPoolConfig()}
}

// MinSize 设置最小协程数。
func (b *RenewPoolBuilder) MinSize(size int) *RenewPoolBuilder {
	b.cfg.MinSize = size
	return b
}

// MaxSize 设置最大协程数。
func (b *RenewPoolBuilder) MaxSize(size int) *RenewPoolBuilder {
	b.cfg.MaxSize = size
	return b
}

// ScaleUpRate 设置扩容阈值。
func (b *RenewPoolBuilder) ScaleUpRate(up float64) *RenewPoolBuilder {
	b.cfg.ScaleUpRate = up
	return b
}

// ScaleDownRate 设置缩容阈值。
func (b *RenewPoolBuilder) ScaleDownRate(down float64) *RenewPoolBuilder {
	b.cfg.ScaleDownRate = down
	return b
}

// CheckInterval 设置自动扩缩容检查间隔。
func (b *RenewPoolBuilder) CheckInterval(interval time.Duration) *RenewPoolBuilder {
	b.cfg.CheckInterval = interval
	return b
}

// Expiry 设置空闲 worker 过期时间。
func (b *RenewPoolBuilder) Expiry(expiry time.Duration) *RenewPoolBuilder {
	b.cfg.Expiry = expiry
	return b
}

// PrintStatusInterval 设置定时打印池状态的间隔。
func (b *RenewPoolBuilder) PrintStatusInterval(interval time.Duration) *RenewPoolBuilder {
	b.cfg.PrintStatusInterval = interval
	return b
}

// PreAlloc 设置预分配标志。
func (b *RenewPoolBuilder) PreAlloc(prealloc bool) *RenewPoolBuilder {
	b.cfg.PreAlloc = prealloc
	return b
}

// NonBlocking 设置是否启用非阻塞提交。
func (b *RenewPoolBuilder) NonBlocking(nonblocking bool) *RenewPoolBuilder {
	b.cfg.NonBlocking = nonblocking
	return b
}

// Config 返回当前续期池配置。
func (b *RenewPoolBuilder) Config() *RenewPoolConfig {
	return b.cfg
}

// Build 构建 RenewPoolManager 实例。
func (b *RenewPoolBuilder) Build() (*RenewPoolManager, error) {
	return NewRenewPoolManagerWithConfig(b.cfg)
}

// normalizeConfig 兜底修正无效配置，避免运行期 panic。
func normalizeConfig(cfg *RenewPoolConfig) *RenewPoolConfig {
	if cfg == nil {
		return DefaultRenewPoolConfig()
	}

	if cfg.MinSize <= 0 {
		cfg.MinSize = DefaultMinSize
	}
	if cfg.MaxSize < cfg.MinSize {
		cfg.MaxSize = cfg.MinSize
	}
	if cfg.ScaleUpRate <= 0 || cfg.ScaleUpRate > 1 {
		cfg.ScaleUpRate = DefaultScaleUpRate
	}
	if cfg.ScaleDownRate < 0 || cfg.ScaleDownRate > 1 {
		cfg.ScaleDownRate = DefaultScaleDownRate
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = DefaultCheckInterval
	}
	if cfg.Expiry <= 0 {
		cfg.Expiry = DefaultExpiry
	}

	return cfg
}

// isStarted 返回协程池是否仍在运行。
func (m *RenewPoolManager) isStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}

// spawnWorkers 启动指定数量的 worker。
func (m *RenewPoolManager) spawnWorkers(count int, waitReady bool) {
	var ready chan struct{}
	if waitReady {
		ready = make(chan struct{}, count)
	}

	for i := 0; i < count; i++ {
		atomic.AddInt32(&m.workers, 1)
		m.wg.Add(1)
		go m.worker(ready)
	}

	if ready == nil {
		return
	}

	for i := 0; i < count; i++ {
		<-ready
	}
}

// worker 执行续期任务，并在缩容后按空闲超时自行退出。
func (m *RenewPoolManager) worker(ready chan<- struct{}) {
	defer m.wg.Done()
	defer atomic.AddInt32(&m.workers, -1)

	timer := time.NewTimer(m.config.Expiry)
	defer timer.Stop()

	for {
		resetTimer(timer, m.config.Expiry)
		atomic.AddInt32(&m.idle, 1)
		if ready != nil {
			ready <- struct{}{}
			ready = nil
		}

		select {
		case task := <-m.taskCh:
			atomic.AddInt32(&m.idle, -1)
			if task == nil {
				continue
			}

			atomic.AddInt32(&m.running, 1)
			task()
			atomic.AddInt32(&m.running, -1)

		case <-timer.C:
			atomic.AddInt32(&m.idle, -1)
			if m.shouldRetireWorker() {
				return
			}

		case <-m.stopCh:
			atomic.AddInt32(&m.idle, -1)
			return
		}
	}
}

// shouldRetireWorker 判断当前 worker 是否应在空闲时退出。
func (m *RenewPoolManager) shouldRetireWorker() bool {
	workers := int(atomic.LoadInt32(&m.workers))
	capacity := int(atomic.LoadInt32(&m.capacity))
	return workers > capacity && workers > m.config.MinSize
}

// autoScale 定时根据使用率调整目标容量。
func (m *RenewPoolManager) autoScale() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.adjustCapacity()
		case <-m.stopCh:
			return
		}
	}
}

// adjustCapacity 根据运行中的任务数动态扩缩容。
func (m *RenewPoolManager) adjustCapacity() {
	currentCap := int(atomic.LoadInt32(&m.capacity))
	if currentCap <= 0 {
		return
	}

	running := int(atomic.LoadInt32(&m.running))
	usage := float64(running) / float64(currentCap)
	newCap := currentCap

	switch {
	case usage > m.config.ScaleUpRate && currentCap < m.config.MaxSize:
		newCap = int(float64(currentCap) * 1.5)
		if newCap <= currentCap {
			newCap = currentCap + 1
		}
		if newCap > m.config.MaxSize {
			newCap = m.config.MaxSize
		}

	case usage < m.config.ScaleDownRate && currentCap > m.config.MinSize:
		newCap = int(float64(currentCap) * 0.7)
		if newCap >= currentCap {
			newCap = currentCap - 1
		}
		if newCap < m.config.MinSize {
			newCap = m.config.MinSize
		}
	}

	if newCap == currentCap {
		return
	}

	atomic.StoreInt32(&m.capacity, int32(newCap))
	if newCap > currentCap {
		m.spawnWorkers(newCap-currentCap, false)
	}
}

// printStatusLoop 按配置周期打印池状态。
func (m *RenewPoolManager) printStatusLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.PrintStatusInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.PrintStatus()
		case <-m.stopCh:
			return
		}
	}
}

// resetTimer 安全复用 timer，避免重复触发。
func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}
