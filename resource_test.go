package gin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResourceCoordinatorStartAndStopOrder(t *testing.T) {
	e := New()
	var events []string

	e.resources.register(managedResource{
		name: "first",
		start: func(context.Context, *Engine) error {
			events = append(events, "start:first")
			return nil
		},
		stop: func(context.Context, *Engine) error {
			events = append(events, "stop:first")
			return nil
		},
	})
	e.resources.register(managedResource{
		name: "second",
		start: func(context.Context, *Engine) error {
			events = append(events, "start:second")
			return nil
		},
		stop: func(context.Context, *Engine) error {
			events = append(events, "stop:second")
			return nil
		},
	})

	if err := e.ensureRuntimeReady(context.Background()); err != nil {
		t.Fatalf("ensureRuntimeReady: %v", err)
	}
	if err := e.ensureRuntimeReady(context.Background()); err != nil {
		t.Fatalf("ensureRuntimeReady second call: %v", err)
	}
	if err := e.stopManagedResources(context.Background()); err != nil {
		t.Fatalf("stopManagedResources: %v", err)
	}
	if err := e.stopManagedResources(context.Background()); err != nil {
		t.Fatalf("stopManagedResources second call: %v", err)
	}

	want := []string{"start:first", "start:second", "stop:second", "stop:first"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events mismatch\ngot : %#v\nwant: %#v", events, want)
	}
}

func TestResourceCoordinatorStopOnlyResourceStops(t *testing.T) {
	e := New()
	var stopped bool

	e.resources.register(managedResource{
		name: "stop-only",
		stop: func(context.Context, *Engine) error {
			stopped = true
			return nil
		},
	})

	if err := e.ensureRuntimeReady(context.Background()); err != nil {
		t.Fatalf("ensureRuntimeReady: %v", err)
	}
	if err := e.stopManagedResources(context.Background()); err != nil {
		t.Fatalf("stopManagedResources: %v", err)
	}
	if !stopped {
		t.Fatalf("expected stop-only resource to be stopped")
	}
}

func TestResourceCoordinatorRollbackOnStartFailure(t *testing.T) {
	e := New()
	var events []string
	fail := errors.New("boom")

	e.resources.register(managedResource{
		name: "first",
		start: func(context.Context, *Engine) error {
			events = append(events, "start:first")
			return nil
		},
		stop: func(context.Context, *Engine) error {
			events = append(events, "stop:first")
			return nil
		},
	})
	e.resources.register(managedResource{
		name: "second",
		start: func(context.Context, *Engine) error {
			events = append(events, "start:second")
			return fail
		},
	})

	err := e.ensureRuntimeReady(context.Background())
	if !errors.Is(err, fail) {
		t.Fatalf("expected wrapped fail error, got %v", err)
	}

	want := []string{"start:first", "start:second", "stop:first"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events mismatch\ngot : %#v\nwant: %#v", events, want)
	}
}

func TestResourceCoordinatorConcurrentStartRunsOnce(t *testing.T) {
	e := New()
	var starts atomic.Int32
	gate := make(chan struct{})

	e.resources.register(managedResource{
		name: "slow",
		start: func(context.Context, *Engine) error {
			starts.Add(1)
			<-gate
			return nil
		},
	})

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			errs <- e.ensureRuntimeReady(context.Background())
		}()
	}

	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ensureRuntimeReady: %v", err)
		}
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("resource started %d times, want 1", got)
	}
}

func TestServeHTTPReturns500WhenManagedStartupFails(t *testing.T) {
	e := New()
	e.resources.register(managedResource{
		name: "broken",
		start: func(context.Context, *Engine) error {
			return errors.New("broken resource")
		},
	})
	e.GET("/ok", func(c *Context) {
		c.Success(H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

func TestWithStartupTimeoutSetsEngineField(t *testing.T) {
	e := New()
	WithStartupTimeout(2 * time.Second)(e)
	if e.startupTimeout != 2*time.Second {
		t.Fatalf("startup timeout not set")
	}
}
