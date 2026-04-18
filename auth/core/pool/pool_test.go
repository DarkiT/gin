package pool

import (
	"testing"
	"time"
)

// TestRenewPoolManagerNonBlocking 验证非阻塞模式下池满会立即返回错误。
func TestRenewPoolManagerNonBlocking(t *testing.T) {
	mgr, err := NewRenewPoolManagerWithConfig(&RenewPoolConfig{
		MinSize:       1,
		MaxSize:       1,
		CheckInterval: time.Second,
		Expiry:        50 * time.Millisecond,
		NonBlocking:   true,
	})
	if err != nil {
		t.Fatalf("NewRenewPoolManagerWithConfig() error = %v", err)
	}
	defer mgr.Stop()

	started := make(chan struct{})
	release := make(chan struct{})

	if err := mgr.Submit(func() {
		close(started)
		<-release
	}); err != nil {
		t.Fatalf("Submit() first task error = %v", err)
	}

	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("first task did not start in time")
	}

	if err := mgr.Submit(func() {}); err == nil {
		t.Fatal("Submit() expected pool full error, got nil")
	}

	close(release)
}

// TestRenewPoolManagerAutoScale 验证高负载下会按配置自动扩容。
func TestRenewPoolManagerAutoScale(t *testing.T) {
	mgr, err := NewRenewPoolManagerWithConfig(&RenewPoolConfig{
		MinSize:       1,
		MaxSize:       2,
		ScaleUpRate:   0.5,
		ScaleDownRate: 0.1,
		CheckInterval: 20 * time.Millisecond,
		Expiry:        30 * time.Millisecond,
		NonBlocking:   false,
	})
	if err != nil {
		t.Fatalf("NewRenewPoolManagerWithConfig() error = %v", err)
	}
	defer mgr.Stop()

	started := make(chan struct{})
	release := make(chan struct{})

	go func() {
		_ = mgr.Submit(func() {
			close(started)
			<-release
		})
	}()

	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("task did not start in time")
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, capacity, _ := mgr.Stats()
		if capacity == 2 {
			close(release)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(release)
	t.Fatal("pool did not scale up to expected capacity")
}
