package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// State 表示生命周期管理器的运行状态。
type State int

const (
	// StateInit 表示尚未启动。
	StateInit State = iota
	// StateStarting 表示正在启动。
	StateStarting
	// StateRunning 表示已进入运行状态。
	StateRunning
	// StateShuttingDown 表示正在关闭。
	StateShuttingDown
	// StateStopped 表示已完全停止。
	StateStopped
)

// Hook 定义生命周期回调函数。
type Hook func(ctx context.Context) error

// Manager 管理 HTTP 服务的生命周期。
type Manager struct {
	mu              sync.RWMutex
	state           State
	server          *http.Server
	shutdownTimeout time.Duration
	onStart         []Hook
	onShutdown      []Hook
	onStopped       []Hook
	done            chan struct{}
	shutdownOnce    sync.Once
}

// NewManager 创建一个默认配置的生命周期管理器。
func NewManager() *Manager {
	return &Manager{
		state:           StateInit,
		shutdownTimeout: 30 * time.Second,
		done:            make(chan struct{}),
	}
}

// SetShutdownTimeout 设置优雅关闭超时时间。
func (m *Manager) SetShutdownTimeout(d time.Duration) {
	m.mu.Lock()
	m.shutdownTimeout = d
	m.mu.Unlock()
}

// OnStart 注册启动前回调。
func (m *Manager) OnStart(hooks ...Hook) {
	m.mu.Lock()
	m.onStart = append(m.onStart, hooks...)
	m.mu.Unlock()
}

// OnShutdown 注册关闭流程回调。
func (m *Manager) OnShutdown(hooks ...Hook) {
	m.mu.Lock()
	m.onShutdown = append(m.onShutdown, hooks...)
	m.mu.Unlock()
}

// OnStopped 注册停止完成后的回调。
func (m *Manager) OnStopped(hooks ...Hook) {
	m.mu.Lock()
	m.onStopped = append(m.onStopped, hooks...)
	m.mu.Unlock()
}

// Run 启动服务并阻塞等待退出信号。
func (m *Manager) Run(server *http.Server, handler http.Handler) error {
	if server == nil {
		return errors.New("lifecycle: server is nil")
	}
	m.mu.Lock()
	if m.state != StateInit {
		m.mu.Unlock()
		return errors.New("lifecycle: invalid state")
	}
	m.state = StateStarting
	m.server = server
	if handler != nil {
		m.server.Handler = handler
	}
	startHooks := append([]Hook(nil), m.onStart...)
	m.mu.Unlock()

	for _, hook := range startHooks {
		if err := hook(context.Background()); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		err := m.server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			stop()
		}
	}()

	m.mu.Lock()
	m.state = StateRunning
	m.mu.Unlock()

	select {
	case <-ctx.Done():
		return m.Shutdown(context.Background())
	case <-m.done:
		return nil
	case err := <-errCh:
		return err
	}
}

// Shutdown 执行优雅关闭并触发回调。
func (m *Manager) Shutdown(ctx context.Context) error {
	var shutdownErr error
	m.shutdownOnce.Do(func() {
		m.mu.Lock()
		if m.state == StateStopped {
			m.mu.Unlock()
			return
		}
		m.state = StateShuttingDown
		server := m.server
		timeout := m.shutdownTimeout
		shutdownHooks := append([]Hook(nil), m.onShutdown...)
		stoppedHooks := append([]Hook(nil), m.onStopped...)
		m.mu.Unlock()

		shutdownCtx := ctx
		cancel := func() {}
		if timeout > 0 {
			shutdownCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		defer cancel()

		for _, hook := range shutdownHooks {
			if err := hook(shutdownCtx); err != nil && shutdownErr == nil {
				shutdownErr = err
			}
		}

		if server != nil {
			if err := server.Shutdown(shutdownCtx); err != nil && shutdownErr == nil {
				shutdownErr = err
			}
		}

		for _, hook := range stoppedHooks {
			if err := hook(shutdownCtx); err != nil && shutdownErr == nil {
				shutdownErr = err
			}
		}

		m.mu.Lock()
		m.state = StateStopped
		m.mu.Unlock()
		close(m.done)
	})
	return shutdownErr
}

// State 返回当前生命周期状态。
func (m *Manager) State() State {
	m.mu.RLock()
	state := m.state
	m.mu.RUnlock()
	return state
}

// Wait 阻塞直到生命周期结束。
func (m *Manager) Wait() {
	<-m.done
}
