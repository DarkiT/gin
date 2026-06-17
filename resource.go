package gin

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type managedResource struct {
	name  string
	start func(context.Context, *Engine) error
	stop  func(context.Context, *Engine) error
}

type resourceCoordinator struct {
	mu        sync.Mutex
	managed   []managedResource
	started   []managedResource
	startErr  error
	startedOK bool
	stopped   bool
	stopOnce  sync.Once
	// ready 是 startedOK 的无锁快照：启动成功后置位，使 start() 热路径可跳过加锁。
	ready atomic.Bool
}

func newResourceCoordinator() *resourceCoordinator {
	return &resourceCoordinator{}
}

func (rc *resourceCoordinator) register(res managedResource) {
	if res.name == "" {
		panic("gin: managed resource name is required")
	}
	rc.mu.Lock()
	rc.managed = append(rc.managed, res)
	rc.mu.Unlock()
}

func (rc *resourceCoordinator) start(ctx context.Context, e *Engine) error {
	// 快路径：已启动成功时无锁直接返回，避免每个请求争用 mu（高 QPS 热路径）。
	if rc.ready.Load() {
		return nil
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.startedOK {
		return nil
	}
	if rc.startErr != nil {
		return rc.startErr
	}
	if rc.stopped {
		return errors.New("gin: managed resources are stopped")
	}
	resources := append([]managedResource(nil), rc.managed...)

	started := make([]managedResource, 0, len(resources))
	for _, res := range resources {
		if res.start != nil {
			if err := res.start(ctx, e); err != nil {
				rollbackErr := stopManagedSlice(ctx, e, started)
				combined := err
				if rollbackErr != nil {
					combined = errors.Join(err, rollbackErr)
				}
				wrapped := fmt.Errorf("gin: start managed resource %q: %w", res.name, combined)
				rc.startErr = wrapped
				return wrapped
			}
		}
		started = append(started, res)
	}

	rc.started = started
	rc.startedOK = true
	rc.ready.Store(true)
	return nil
}

func (rc *resourceCoordinator) stop(ctx context.Context, e *Engine) error {
	var stopErr error
	rc.stopOnce.Do(func() {
		rc.mu.Lock()
		started := append([]managedResource(nil), rc.started...)
		rc.started = nil
		rc.stopped = true
		rc.ready.Store(false)
		rc.mu.Unlock()
		stopErr = stopManagedSlice(ctx, e, started)
	})
	return stopErr
}

func stopManagedSlice(ctx context.Context, e *Engine, started []managedResource) error {
	var errs []error
	for i := len(started) - 1; i >= 0; i-- {
		res := started[i]
		if res.stop == nil {
			continue
		}
		if err := res.stop(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("gin: stop managed resource %q: %w", res.name, err))
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) ensureRuntimeReady(ctx context.Context) error {
	if e == nil || e.resources == nil {
		return nil
	}
	startCtx, cancel := e.resourceStartupContext(ctx)
	defer cancel()
	return e.resources.start(startCtx, e)
}

func (e *Engine) stopManagedResources(ctx context.Context) error {
	if e == nil || e.resources == nil {
		return nil
	}
	stopCtx, cancel := e.resourceShutdownContext(ctx)
	defer cancel()
	return e.resources.stop(stopCtx, e)
}

func (e *Engine) resourceStartupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return withOptionalTimeout(parent, e.startupTimeout)
}

func (e *Engine) resourceShutdownContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := time.Duration(0)
	if e != nil && e.lifecycle != nil {
		timeout = e.lifecycle.ShutdownTimeout()
	}
	return withOptionalTimeout(parent, timeout)
}

func withOptionalTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, timeout)
}
