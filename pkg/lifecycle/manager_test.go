package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestManagerStateTransition(t *testing.T) {
	mgr := NewManager()
	server := &http.Server{Addr: "127.0.0.1:0"}

	hookOrder := make([]string, 0, 3)
	mgr.OnStart(func(ctx context.Context) error {
		hookOrder = append(hookOrder, "start")
		return nil
	})
	mgr.OnShutdown(func(ctx context.Context) error {
		hookOrder = append(hookOrder, "shutdown")
		return nil
	})
	mgr.OnStopped(func(ctx context.Context) error {
		hookOrder = append(hookOrder, "stopped")
		return nil
	})

	runErr := make(chan error, 1)
	go func() {
		runErr <- mgr.Run(server, nil)
	}()

	waitState(t, mgr, StateRunning)
	if mgr.State() != StateRunning {
		t.Fatalf("expected StateRunning")
	}

	sendSignal()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit")
	}

	mgr.Wait()
	if mgr.State() != StateStopped {
		t.Fatalf("expected StateStopped")
	}
	if len(hookOrder) != 3 {
		t.Fatalf("expected 3 hooks, got %d", len(hookOrder))
	}
	if hookOrder[0] != "start" || hookOrder[1] != "shutdown" || hookOrder[2] != "stopped" {
		t.Fatalf("hook order mismatch: %v", hookOrder)
	}
}

func TestManagerHookError(t *testing.T) {
	mgr := NewManager()
	server := &http.Server{Addr: "127.0.0.1:0"}
	mgr.server = server
	mgr.state = StateStarting

	mgr.OnShutdown(func(ctx context.Context) error {
		return errors.New("shutdown error")
	})

	err := mgr.Shutdown(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if mgr.State() != StateStopped {
		t.Fatalf("expected StateStopped")
	}
}

func TestManagerShutdownTimeout(t *testing.T) {
	mgr := NewManager()
	server := &http.Server{Addr: "127.0.0.1:0"}
	mgr.server = server

	mgr.SetShutdownTimeout(30 * time.Millisecond)
	mgr.OnShutdown(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	err := mgr.Shutdown(context.Background())
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestManagerSignalHandling(t *testing.T) {
	mgr := NewManager()
	server := &http.Server{Addr: "127.0.0.1:0"}

	var started int32
	mgr.OnStart(func(ctx context.Context) error {
		atomic.StoreInt32(&started, 1)
		return nil
	})

	runErr := make(chan error, 1)
	go func() {
		runErr <- mgr.Run(server, nil)
	}()

	waitState(t, mgr, StateRunning)
	if atomic.LoadInt32(&started) != 1 {
		t.Fatalf("start hook not called")
	}

	sendSignal()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit")
	}
}

func TestManagerConcurrentWait(t *testing.T) {
	mgr := NewManager()
	server := &http.Server{Addr: "127.0.0.1:0"}

	runErr := make(chan error, 1)
	go func() {
		runErr <- mgr.Run(server, nil)
	}()
	waitState(t, mgr, StateRunning)

	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			mgr.Wait()
		})
	}

	sendSignal()
	wg.Wait()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit")
	}
}

func TestManagerExternalShutdownUnblocksRun(t *testing.T) {
	mgr := NewManager()
	server := &http.Server{Addr: "127.0.0.1:0"}

	runErr := make(chan error, 1)
	go func() {
		runErr <- mgr.Run(server, nil)
	}()

	waitState(t, mgr, StateRunning)

	if err := mgr.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error after external shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit after external shutdown")
	}

	mgr.Wait()
	if mgr.State() != StateStopped {
		t.Fatalf("expected StateStopped")
	}
}

func waitState(t *testing.T, mgr *Manager, state State) {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mgr.State() == state {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state not reached: %v", state)
}

func sendSignal() {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		panic(err)
	}
	_ = p.Signal(syscall.SIGTERM)
}
